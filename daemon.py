#!/usr/bin/python3
# A simple daemon for managing Isolate sandboxes
# (c) 2023 Martin Mares <mj@ucw.cz>

import asyncio
import json
import os
import socket
import struct
import subprocess
from typing import Optional, List, Tuple


# Protocol: in both direction, we send JSON objects separated by an empty line.
# Request pipelining is not supported: wait for a reply before sending the next request.
#
# Currently, only a single request type is defined:
#
# In:   {"op": "init"}
#
# Out:  {"box-id": number, "path": "/path/to/box/directory"}
#
# This allocates a new box ID and initialized the box for use by the user
# who connected to the daemon. When the connection is closed, the box is cleaned up.
#
# The box always has cgroup mode enabled.
#
# Errors are reported as {"error": "Error message"}


MAX_BOXES = 100

free_boxes: List[int] = []
last_allocated_box: int = -1


def allocate_box() -> Optional[int]:
    global last_allocated_box

    if free_boxes:
        return free_boxes.pop()
    elif last_allocated_box < MAX_BOXES - 1:
        last_allocated_box += 1
        return last_allocated_box
    else:
        return None


def free_box(id: int) -> None:
    free_boxes.append(id)


def get_peer_credentials(stream) -> Tuple[int, int]:
    sock = stream.transport.get_extra_info('socket')
    assert sock is not None

    # We hope that this structure has the same format on all Linux systems.
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)

    return uid, gid


class ProtocolError(RuntimeError):
    pass


class Connection:

    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    uid: int
    gid: int
    box_id: Optional[int]

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader = reader
        self.writer = writer
        self.uid, self.gid = get_peer_credentials(writer)
        self.box_id = None
        print(f'New connection (uid={self.uid}, gid={self.gid})')

    async def read_request(self):
        try:
            raw_req = await self.reader.readuntil(b'\n\n')
            req = json.loads(raw_req.decode('utf-8'))
            if type(req) is not dict:
                raise ProtocolError('Request is not a dictionary')
            return req
        except asyncio.IncompleteReadError as e:
            if len(e.partial) == 0:
                print('Connection closed')
                return None
            else:
                raise ProtocolError('Incomplete message')
        except asyncio.LimitOverrunError:
            raise ProtocolError('Message too long')
        except json.JSONDecodeError as e:
            raise ProtocolError(f'Cannot parse message ({e})')
        except UnicodeDecodeError as e:
            raise ProtocolError(f'Cannot decode message ({e})')

    def send_reply(self, reply) -> None:
        self.writer.write(json.dumps(reply, indent=4, sort_keys=True).encode('utf-8'))
        self.writer.write(b'\n\n')

    def send_error(self, msg: str) -> None:
        print('Connection error:', msg)
        err = {'error': msg}
        self.send_reply(err)

    async def op_init(self, req) -> None:
        if self.box_id is not None:
            raise ProtocolError('Box already initialized')

        self.box_id = allocate_box()
        if self.box_id is None:
            raise ProtocolError('All boxes are busy')

        proc = await asyncio.create_subprocess_exec(
            '/usr/local/bin/isolate',
            '--init',
            '--cg',
            '--wait',
            '--box-id', str(self.box_id),
            '--as-uid', str(self.uid),
            '--as-gid', str(self.gid),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=None,
        )

        stdout, _ = await proc.communicate()
        box_path = stdout.decode().rstrip()

        if proc.returncode != 0:
            raise ProtocolError('Box initialization failed')

        reply = {'box-id': self.box_id, 'path': box_path}
        self.send_reply(reply)

        print(f'Initialized box {self.box_id}')

    async def clean_box(self) -> None:
        if self.box_id is None:
            return

        print(f'Cleaning up box {self.box_id}')

        proc = await asyncio.create_subprocess_exec(
            '/usr/local/bin/isolate',
            '--cleanup',
            '--cg',
            '--wait',
            '--box-id', str(self.box_id),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=None,
        )

        _, _ = await proc.communicate()

        if proc.returncode == 0:
            free_box(self.box_id)
        else:
            print('Box cleanup failed')


async def connect_callback(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    conn = Connection(reader, writer)

    try:
        while True:
            req = await conn.read_request()
            if req is None:
                break

            op = req.get('op', "")
            if op == 'init':
                await conn.op_init(req)
            else:
                raise ProtocolError('Invalid operation')

    except Exception as e:
        conn.send_error(str(e))

    try:
        writer.close()
        await writer.wait_closed()
    except Exception as e:
        print(f'Error when closing connection: {e}')

    await conn.clean_box()


async def main() -> None:
    socket_path = 'socket'
    server = await asyncio.start_unix_server(connect_callback, path=socket_path, limit=8192)
    os.chmod(socket_path, 0o777)
    await server.serve_forever()


asyncio.run(main())

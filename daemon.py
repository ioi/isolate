#!/usr/bin/python3

import asyncio
import json
import socket
import struct
import subprocess


def get_peer_credentials(stream):
    sock = stream.transport.get_extra_info('socket')
    assert sock is not None

    # We hope that this structure has the same format on all Linux systems.
    creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
    pid, uid, gid = struct.unpack('3i', creds)

    return uid, gid


class ProtocolError(RuntimeError):
    pass


class Connection:

    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer
        self.uid, self.gid = get_peer_credentials(writer)
        self.box_id = None
        print(f'New connection (uid={self.uid}, gid={self.gid})')

    async def read_request(self):
        try:
            raw_req = await self.reader.readuntil(b'\n\n')
            req = json.loads(raw_req.decode('utf-8'))
            print(req)
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
            raise ProtocolError(f'Cannot parse message: {e}')
        except UnicodeDecodeError as e:
            raise ProtocolError(f'Cannot decode message: {e}')

    def send_reply(self, reply):
        self.writer.write(json.dumps(reply, indent=4, sort_keys=True).encode('utf-8'))
        self.writer.write(b'\n\n')

    def send_error(self, msg):
        print('Connection error:', msg)
        err = {'error': msg}
        self.send_reply(err)

    async def op_init(self, req):
        if self.box_id is not None:
            raise ProtocolError('Box already initialized')

        self.box_id = 0
        proc = await asyncio.create_subprocess_exec(
            # FIXME: quota options
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


async def connect_callback(reader, writer):
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


async def main():
    server = await asyncio.start_unix_server(connect_callback, path='socket', limit=8192)
    await server.serve_forever()


asyncio.run(main())

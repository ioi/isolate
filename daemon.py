#!/usr/bin/python3

import asyncio
import json
import subprocess


class ProtocolError(RuntimeError):
    pass


def send_reply(writer, reply):
    writer.write(json.dumps(reply, indent=4, sort_keys=True).encode('utf-8'))
    writer.write(b'\n\n')


async def connect_callback(reader, writer):
    try:
        print('New connection')
        # FIXME: Get uid and gid

        # FIXME: Better error handling
        raw_req = await reader.readuntil(b'\n\n')
        req = json.loads(raw_req.decode('utf-8'))
        print(req)
        if type(req) is not dict:
            raise ProtocolError('Request is not a dictionary')

        box_id = 0
        proc = await asyncio.create_subprocess_exec(
            '/usr/local/bin/isolate', '--init', '--box-id', str(box_id), '--cg', '--wait',
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=None,
        )

        stdout, _ = await proc.communicate()
        box_path = stdout.decode().rstrip()

        if proc.returncode != 0:
            raise ProtocolError('Box initialization failed')

        reply = {'box-id': box_id, 'path': box_path}
        send_reply(writer, reply)

        FIXME

    except Exception as e:
        print('Connection error:', e)
        err = {'error': str(e)}
        send_reply(writer, err)

    writer.close()
    await writer.wait_closed()


async def main():
    server = await asyncio.start_unix_server(connect_callback, path='socket', limit=8192)
    await server.serve_forever()


asyncio.run(main())

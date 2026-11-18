"""Owned subprocess fixture for the opt-in native SQLite application profile.

Receive ephemeral Guard configuration over stdin, never through CLI or a file.
No account, mutation API, model or public listener is created.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import json
import sys

from reverse_artex_guard import Guard
from reverse_artex_guard.http_server import serve_application_read
from reverse_artex_guard.sqlite_application import SQLiteApplicationResolver


def main():
    raw = sys.stdin.buffer.readline(65537)
    if len(raw) > 65536 or not raw.endswith(b'\n'):
        raise ValueError('bounded fixture configuration required')
    config = json.loads(raw)
    resolver = SQLiteApplicationResolver(config.pop('database'))
    private = base64.b64decode(config.pop('private_key'), validate=True)
    session = base64.b64decode(config.pop('session_key'), validate=True)
    config['identity_key'] = b''
    guards = {prefix: Guard(**config, route_id=route, template=f'/{prefix}/objects/{{id}}', private_key=private, session_key=session)
              for route, prefix in (('modern', 'api'), ('legacy', 'legacy'))}
    class App(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass
        def do_GET(self):
            for prefix, guard in guards.items():
                if self.path.startswith('/' + prefix + '/objects/'):
                    return serve_application_read(self, guard, resolver)
            self.send_response(404); self.send_header('Content-Length', '0'); self.end_headers()
        do_HEAD = do_GET
    server = ThreadingHTTPServer(('127.0.0.1', 0), App)
    server.daemon_threads = True
    print('http://127.0.0.1:' + str(server.server_port), flush=True)
    try: server.serve_forever(poll_interval=.05)
    finally: server.server_close()


if __name__ == '__main__':
    main()

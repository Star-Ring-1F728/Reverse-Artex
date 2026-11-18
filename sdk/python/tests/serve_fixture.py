"""Owned, loopback-only SDK wire fixture; ephemeral configuration on stdin."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import base64
import json
import sys
from reverse_artex_guard import Guard, ObjectSnapshot
from reverse_artex_guard.http_server import serve_object_read

config = json.loads(sys.stdin.readline())
for field in ("private_key", "identity_key", "session_key"):
    config[field] = base64.b64decode(config[field])
guard = Guard(**config)


def resolver(object_id):
    return ObjectSnapshot(object_id, "beta" if object_id == "other-tenant" else "alpha",
                          "alice" if object_id == "self" else "bob",
                          ("alice",) if object_id == "shared" else (), "acl1", "v1",
                          {"secret": "WIRE_PRIVATE_" + object_id})


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/legacy/objects/broken":
            # A vulnerable handler without SDK integration cannot return bytes
            # through the protected edge.
            body = b'{"secret":"UNSIGNED_WIRE_PRIVATE"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        serve_object_read(self, guard, resolver)

    def do_HEAD(self):
        serve_object_read(self, guard, resolver)

    def log_message(self, *args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
print("http://127.0.0.1:%d" % server.server_port, flush=True)
server.serve_forever()

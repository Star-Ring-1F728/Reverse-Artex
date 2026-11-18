import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
from threading import Thread
import unittest

from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
from prepare_oidc import prepare


def b64(number):
    raw = number.to_bytes((number.bit_length() + 7) // 8)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class PrepareOIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key().public_numbers()
        cls.public = {"kty": "RSA", "kid": "key1", "use": "sig", "alg": "RS256", "n": b64(key.n), "e": b64(key.e)}

    def setUp(self):
        owner = self
        self.mode, self.paths = "valid", []
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                owner.paths.append(self.path)
                if owner.mode == "redirect":
                    self.send_response(302); self.send_header("Location", owner.origin + "/forbidden"); self.end_headers(); return
                if self.path.endswith("openid-configuration"):
                    value = {"issuer": owner.issuer, "jwks_uri": owner.issuer + "/keys"}
                    if owner.mode == "different-issuer": value["issuer"] += "-other"
                    if owner.mode == "different-origin": value["jwks_uri"] = "http://127.0.0.1:1/forbidden"
                    if owner.mode == "outside-realm": value["jwks_uri"] = owner.origin + "/forbidden"
                else:
                    key = dict(owner.public)
                    if owner.mode == "private-key": key["d"] = "forbidden-private"
                    value = {"keys": [key]}
                raw = json.dumps(value).encode()
                self.send_response(200); self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.origin = "http://127.0.0.1:" + str(self.server.server_port)
        self.issuer = self.origin + "/realms/test"
        self.worker = Thread(target=self.server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
        self.worker.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown(); self.server.server_close(); self.worker.join(2)

    def call(self):
        return prepare(self.issuer, "reverse-artex", "console", {"subject": {"principal": "alice", "tenant": "alpha"}})

    def test_fetches_only_pinned_public_issuer_keys(self):
        config, digest = self.call()
        self.assertEqual(config["keys"][0]["kid"], "key1")
        self.assertEqual(len(digest), 64)
        self.assertEqual(self.paths, ["/realms/test/.well-known/openid-configuration", "/realms/test/keys"])

    def test_discovery_cannot_redirect_or_escape_issuer_scope(self):
        for mode in ("redirect", "different-issuer", "different-origin", "outside-realm"):
            with self.subTest(mode=mode):
                self.mode, self.paths = mode, []
                with self.assertRaises(ValueError): self.call()
                self.assertEqual(self.paths, ["/realms/test/.well-known/openid-configuration"])

    def test_private_jwk_material_is_rejected(self):
        self.mode = "private-key"
        with self.assertRaises(ValueError): self.call()


if __name__ == "__main__": unittest.main()

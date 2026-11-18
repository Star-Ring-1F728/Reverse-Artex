import base64
import hashlib
import hmac
import json
from pathlib import Path
import sys
import time
import unittest
from email.message import Message
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from reverse_artex_guard import Guard, ObjectSnapshot
from reverse_artex_guard.http_server import serve_object_read


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def token(tenant="alpha", principal="alice", now=None):
    now = time.time() if now is None else now
    raw = json.dumps(dict(tenant=tenant, principal=principal, jti="test", iat=int(now), exp=int(now) + 600), separators=(",", ":")).encode()
    payload = b64(raw)
    return payload + "." + b64(hmac.digest(b"i" * 32, payload.encode(), "sha256"))


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.key = Ed25519PrivateKey.generate()
        self.now = time.time()
        self.guard = Guard(asset="asset", registry_digest="a" * 64, trust_epoch="e1", route_id="legacy",
                           template="/legacy/objects/{id}", namespace="objects", tenants=["alpha"],
                           key_id="sdk1", private_key=self.key.private_bytes_raw(),
                           identity_key=b"i" * 32, session_key=b"h" * 32, ingress_token="g" * 32,
                           max_body_bytes=1024, clock=lambda: self.now)
        self.headers = {"Authorization": "Bearer " + token(now=self.now), "X-Lab-Ingress": "g" * 32,
                        "X-RA-Registry": "a" * 64, "X-RA-Request-ID": "request", "X-RA-Nonce": "b" * 48}
        self.snapshot = ObjectSnapshot("one", "alpha", "alice", (), "acl1", "v1", {"secret": "OWNED_PRIVATE"})

    def read(self, snapshot=None, method="GET", path="/legacy/objects/one"):
        return self.guard.read(method, path, self.headers, lambda _: self.snapshot if snapshot is None else snapshot)

    def proof(self, representation):
        envelope = json.loads(representation.headers["X-RA-Release-Proof"])
        raw = base64.urlsafe_b64decode(envelope["payload"] + "=" * (-len(envelope["payload"]) % 4))
        sig = base64.urlsafe_b64decode(envelope["signature"] + "=" * (-len(envelope["signature"]) % 4))
        self.key.public_key().verify(sig, raw)
        return json.loads(raw)

    def test_owner_representation_is_immutable_and_binds_bytes(self):
        rep = self.read()
        self.assertEqual(rep.status, 200)
        self.snapshot.payload["secret"] = "changed later"
        self.assertIn(b"OWNED_PRIVATE", rep.body)
        proof = self.proof(rep)
        self.assertEqual(proof["body_sha256"], hashlib.sha256(rep.body).hexdigest())
        self.assertEqual(proof["body_length"], len(rep.body))
        self.assertEqual(proof["expires_ms"] - proof["issued_ms"], 5000)
        with self.assertRaises(TypeError):
            rep.headers["X-RA-Release-Proof"] = "changed"

    def test_other_owner_and_other_tenant_never_serialize_payload(self):
        for tenant, owner in (("alpha", "bob"), ("beta", "alice")):
            with self.subTest(tenant=tenant, owner=owner):
                snap = ObjectSnapshot("one", tenant, owner, (), "acl1", "v1", {"secret": "FOREIGN_PRIVATE"})
                rep = self.read(snap)
                self.assertEqual(rep.status, 403)
                self.assertNotIn(b"FOREIGN_PRIVATE", rep.body)
                self.assertEqual(self.proof(rep)["decision"], "deny")

    def test_explicit_grant_and_revocation_use_fresh_snapshot(self):
        granted = ObjectSnapshot("one", "alpha", "bob", ("alice",), "acl1", "v1", {"shared": True})
        revoked = ObjectSnapshot("one", "alpha", "bob", (), "acl2", "v1", {"shared": True})
        self.assertEqual(self.read(granted).status, 200)
        self.assertEqual(self.read(revoked).status, 403)

    def test_resolver_substitution_and_unavailable_fail_closed(self):
        wrong = ObjectSnapshot("other", "alpha", "alice", (), "acl1", "v1", {"secret": "FOREIGN_PRIVATE"})
        rep = self.read(wrong)
        self.assertEqual(rep.status, 503)
        self.assertNotIn(b"FOREIGN_PRIVATE", rep.body)
        def unavailable(_):
            raise RuntimeError("secret resolver details")
        rep = self.guard.read("GET", "/legacy/objects/one", self.headers, unavailable)
        self.assertEqual(rep.status, 503)
        self.assertNotIn(b"resolver details", rep.body)
        self.assertEqual(self.proof(rep)["decision"], "unknown")

    def test_head_checks_same_acl_with_empty_signed_body(self):
        rep = self.read(method="HEAD")
        self.assertEqual(rep.status, 200)
        self.assertEqual(rep.body, b"")
        self.assertEqual(self.proof(rep)["body_length"], 0)
        foreign = ObjectSnapshot("one", "alpha", "bob", (), "acl1", "v1", object())
        rep = self.read(foreign, method="HEAD")
        self.assertEqual(rep.status, 403)
        self.assertEqual(rep.body, b"")

    def test_body_limit_and_invalid_json_produce_unknown(self):
        for payload in ({"large": "x" * 2048}, {"number": float("nan")}, {"unsupported": object()}):
            snap = ObjectSnapshot("one", "alpha", "alice", (), "acl1", "v1", payload)
            rep = self.read(snap)
            self.assertEqual(rep.status, 503)
            self.assertEqual(self.proof(rep)["decision"], "unknown")

    def test_bad_ingress_registry_identity_and_paths_do_not_invoke_resolver(self):
        def unreachable(_):
            self.fail("untrusted request reached resolver")
        for key, value in (("X-Lab-Ingress", "forged"), ("X-RA-Registry", "stale"), ("Authorization", "Bearer forged"), ("X-RA-Nonce", "forged")):
            headers = dict(self.headers)
            headers[key] = value
            rep = self.guard.read("GET", "/legacy/objects/one", headers, unreachable)
            self.assertNotEqual(rep.status, 200)
            self.assertNotIn("X-RA-Release-Proof", rep.headers)
        for path in ("/legacy/objects/one?owner=bob", "/legacy/objects/one/two", "/legacy/objects/%6fne"):
            self.assertEqual(self.guard.read("GET", path, self.headers, unreachable).status, 400)

    def test_direct_sdk_rejects_duplicate_security_headers_before_resolving(self):
        for name in ("Authorization", "X-Lab-Ingress", "X-RA-Registry", "X-RA-Request-ID", "X-RA-Nonce"):
            for duplicate in (self.headers[name], "conflicting"):
                for method in ("GET", "HEAD"):
                    with self.subTest(name=name, duplicate=duplicate, method=method):
                        headers = Message()
                        for key, value in self.headers.items():
                            headers[key] = value
                        headers[name.lower()] = duplicate
                        calls = []
                        response = self.guard.read(method, "/legacy/objects/one", headers,
                                                   lambda oid: calls.append(oid) or self.snapshot)
                        self.assertEqual(response.status, 400)
                        self.assertEqual(calls, [])
                        self.assertNotIn(b"OWNED_PRIVATE", response.body)
                        self.assertNotIn("X-RA-Release-Proof", response.headers)
                        if method == "HEAD":
                            self.assertEqual(response.body, b"")

    def test_direct_sdk_normalizes_header_case_and_rejects_ambiguous_mapping(self):
        headers = {key.lower(): value for key, value in self.headers.items()}
        response = self.guard.read("GET", "/legacy/objects/one", headers, lambda _: self.snapshot)
        self.assertEqual(response.status, 200)
        headers["Authorization"] = self.headers["Authorization"]
        response = self.guard.read("GET", "/legacy/objects/one", headers, lambda _: self.fail("ambiguous request resolved"))
        self.assertEqual(response.status, 400)

    def test_http_server_adapter_uses_exact_representation(self):
        guard, snapshot = self.guard, self.snapshot
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                serve_object_read(self, guard, lambda _: snapshot)
            def do_HEAD(self):
                serve_object_read(self, guard, lambda _: snapshot)
            def log_message(self, *args):
                pass
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        worker = Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            for method in ("GET", "HEAD"):
                with urlopen(Request("http://127.0.0.1:%d/legacy/objects/one" % server.server_port,
                                     headers=self.headers, method=method), timeout=2) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(len(response.read()) > 0, method == "GET")
                    self.assertIn("X-RA-Release-Proof", response.headers)
        finally:
            server.shutdown()
            server.server_close()
            worker.join(2)


if __name__ == "__main__":
    unittest.main()

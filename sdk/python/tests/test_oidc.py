import base64
import copy
import hashlib
import json
import time
import unittest

import jwt
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes

from reverse_artex_guard import Guard, ApplicationSnapshot, ObjectSnapshot
from reverse_artex_guard.oidc import OIDCVerifier


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class OIDCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def setUp(self):
        self.now = int(time.time())
        numbers = self.key.public_key().public_numbers()
        self.config = {"schema": "oidc-rs256/1", "issuer": "http://127.0.0.1:18721/realms/test",
                       "audience": "reverse-artex", "client_id": "console", "tenant_claim": "ra_tenant",
                       "max_lifetime_seconds": 300,
                       "subjects": {"subject-alice": {"principal": "alice", "tenant": "alpha"}},
                       "keys": [{"kid": "key1", "n": b64(numbers.n.to_bytes(256)), "e": b64(numbers.e.to_bytes(3))}]}
        self.verifier = OIDCVerifier(self.config)
        self.claims = {"iss": self.config["issuer"], "aud": "reverse-artex", "azp": "console", "typ": "Bearer",
                       "sub": "subject-alice", "ra_tenant": "alpha", "jti": "onrtac:token-one", "sid": "session-one",
                       "iat": self.now, "exp": self.now + 60}

    def token(self, claims=None, headers=None):
        return jwt.encode(claims or self.claims, self.key, algorithm="RS256", headers={"kid": "key1", **(headers or {})})

    def raw_token(self, header, payload):
        raw = (b64(header) + "." + b64(payload)).encode("ascii")
        return raw.decode("ascii") + "." + b64(self.key.sign(raw, padding.PKCS1v15(), hashes.SHA256()))

    def test_valid_identity_uses_stable_subject_mapping_and_detached_pin(self):
        token = self.token()
        pin = self.verifier.digest
        self.config["subjects"]["subject-alice"]["principal"] = "attacker"
        self.config["keys"][0]["kid"] = "other"
        result = self.verifier.verify(token, self.now)
        self.assertEqual((result["principal"], result["tenant"]), ("alice", "alpha"))
        self.assertEqual(self.verifier.digest, pin)

    def test_wrong_scope_class_lifetime_and_claim_types_rejected(self):
        changes = [("iss", "https://other.invalid"), ("aud", "other"), ("azp", "other"),
                   ("sub", "unknown"), ("ra_tenant", "beta"), ("typ", "ID"),
                   ("exp", self.now), ("iat", self.now + 6), ("exp", self.now + 301),
                   ("exp", "9999999999"), ("iat", True), ("exp", self.now + .5),
                   ("sid", ""), ("jti", ""), ("aud", ["reverse-artex"] * 9)]
        for key, value in changes:
            with self.subTest(key=key, value=value):
                c = dict(self.claims, **{key: value})
                with self.assertRaises(ValueError): self.verifier.verify(self.token(c), self.now)
        for key in ("exp", "iat", "sid", "jti"):
            c = dict(self.claims); del c[key]
            with self.assertRaises(ValueError): self.verifier.verify(self.token(c), self.now)

    def test_unknown_key_remote_headers_and_algorithm_confusion_rejected(self):
        for header in ({"kid": "other"}, {"jku": "https://other.invalid/keys"}, {"crit": ["x"]}):
            with self.assertRaises(ValueError): self.verifier.verify(self.token(headers=header), self.now)
        unsigned = jwt.encode(self.claims, key=None, algorithm="none", headers={"kid": "key1"})
        hmac_token = jwt.encode(self.claims, b"h" * 64, algorithm="HS256", headers={"kid": "key1"})
        for token in (unsigned, hmac_token, self.token() + "=", "not.a.token"):
            with self.assertRaises(ValueError): self.verifier.verify(token, self.now)

    def test_duplicate_json_and_excessive_nesting_are_rejected(self):
        header = b'{"alg":"RS256","kid":"key1","typ":"JWT"}'
        payload = json.dumps(self.claims, separators=(",", ":")).encode()
        duplicate = b'{"sub":"subject-alice",' + payload[1:]
        deep = b'{"extra":' + b'[' * 1100 + b'0' + b']' * 1100 + b'}'
        duplicate_head = b'{"alg":"RS256","alg":"RS256","kid":"key1","typ":"JWT"}'
        for head, body in ((header, duplicate), (duplicate_head, payload), (header, deep)):
            with self.assertRaises(ValueError): self.verifier.verify(self.raw_token(head, body), self.now)

    def test_config_rejects_remote_http_and_ambiguous_issuer(self):
        for issuer in ("http://example.com/realm", "https://example.com/realm?", "https://example.com/realm#", "https://example.com/realm/", "https://example.com:99999/realm", "https://user@example.com/realm"):
            c = copy.deepcopy(self.config); c["issuer"] = issuer
            with self.assertRaises(ValueError): OIDCVerifier(c)
        c = copy.deepcopy(self.config); c["tenant_claim"] = "sub"
        with self.assertRaises(ValueError): OIDCVerifier(c)

    def test_guard_requires_identity_pin_and_session_resolver_then_binds_bytes(self):
        options = dict(asset="asset", registry_digest="a" * 64, trust_epoch="e1", route_id="modern",
                       template="/api/objects/{id}", namespace="objects", tenants=["alpha"], key_id="sdk1",
                       private_key=b"k" * 32, identity_key=b"", session_key=b"s" * 32, ingress_token="g" * 32,
                       oidc_config=self.config, identity_config_sha256=self.verifier.digest,
                       resolver_version="session-snapshot-v1", clock=lambda: self.now)
        for changed in ({"identity_config_sha256": "b" * 64}, {"resolver_version": "snapshot-v1"}):
            with self.assertRaises(ValueError): Guard(**dict(options, **changed))
        guard = Guard(**options)
        token = self.token()
        headers = {"Authorization": "Bearer " + token, "X-Lab-Ingress": "g" * 32, "X-RA-Registry": "a" * 64,
                   "X-RA-Request-ID": "request", "X-RA-Nonce": "b" * 48}
        seen = []
        def resolver(oid, identity):
            seen.append(identity)
            return ApplicationSnapshot(True, ObjectSnapshot(oid, "alpha", "alice", (), "acl1", "v1", {"value": "OWNED"}))
        rep = guard.read_application("GET", "/api/objects/1", headers, resolver)
        self.assertEqual(rep.status, 200)
        self.assertEqual(rep.body, b'{"value":"OWNED"}')
        self.assertEqual(seen[0].credential_sha256, hashlib.sha256(token.encode()).hexdigest())
        headers["Authorization"] = "Bearer invalid.token.value"
        def unreachable(*_): self.fail("invalid OIDC identity reached DB")
        self.assertEqual(guard.read_application("GET", "/api/objects/1", headers, unreachable).status, 401)

    def test_bounded_future_issued_at_and_audience_list_match_go_contract(self):
        c = dict(self.claims, aud=["extra", "reverse-artex"], iat=self.now + 4)
        self.assertEqual(self.verifier.verify(self.token(c), self.now)["principal"], "alice")


if __name__ == "__main__":
    unittest.main()

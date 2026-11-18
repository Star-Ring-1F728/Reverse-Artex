from dataclasses import dataclass
from types import MappingProxyType
import base64
import hashlib
import hmac
import json
import re
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from .clock import proof_time

_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_HEX = re.compile(r"[0-9a-f]{64}\Z")


def _json(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def _b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


@dataclass(frozen=True)
class ObjectSnapshot:
    """Resolver contract: ACL and payload come from one consistent DB snapshot.

    Mutations/revocations before this snapshot must be visible. A database
    transaction or revision comparison belongs inside the trusted resolver.
    """
    canonical_id: str
    tenant: str
    owner: str
    grants: tuple[str, ...]
    authz_revision: str
    content_revision: str
    payload: object


@dataclass(frozen=True)
class ReadIdentity:
    """Verified identity for an application lookup; contains no bearer token."""
    principal: str
    tenant: str
    credential_sha256: str


@dataclass(frozen=True)
class ApplicationSnapshot:
    """Session validity and optional object from one application DB snapshot.

    The resolver must compare the live session row with ReadIdentity before
    reading the object. A rejected session must have no object_snapshot.
    None for an authenticated session means the object does not exist.
    """
    session_valid: bool
    object_snapshot: ObjectSnapshot | None = None


@dataclass(frozen=True)
class AuthorizedRepresentation:
    status: int
    body: bytes
    headers: object


class Guard:
    """Owns fetch -> authorization -> serialization -> proof, never signs
    arbitrary handler bytes. Construct with operator-pinned configuration.
    HTTP adapters must send only the returned body and headers.
    """
    def __init__(self, *, asset, registry_digest, trust_epoch, route_id,
                 template, namespace, tenants, key_id, private_key,
                 identity_key, session_key, ingress_token, max_body_bytes=1048576,
                 clock=None, resolver_version="snapshot-v1", oidc_config=None,
                 identity_config_sha256=""):
        for value in (asset, trust_epoch, route_id, namespace, key_id):
            if not isinstance(value, str) or not _ID.fullmatch(value):
                raise ValueError("invalid guard configuration")
        if not _HEX.fullmatch(registry_digest) or not template.endswith("/{id}"):
            raise ValueError("invalid registry pin")
        base = template[:-5]
        if not base.startswith("/") or any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", x) for x in base[1:].split("/")):
            raise ValueError("invalid route template")
        if not tenants or len(tenants) > 64 or any(not _ID.fullmatch(t) for t in tenants):
            raise ValueError("invalid tenant registry")
        if not 1 <= max_body_bytes <= 1048576:
            raise ValueError("invalid response limit")
        if not isinstance(session_key, bytes) or len(session_key) < 32:
            raise ValueError("session key required")
        self._oidc = None
        if oidc_config is None:
            if identity_config_sha256 or not isinstance(identity_key, bytes) or len(identity_key) < 32:
                raise ValueError("identity key required")
        else:
            from .oidc import OIDCVerifier
            self._oidc = OIDCVerifier(oidc_config)
            if resolver_version != "session-snapshot-v1" or identity_config_sha256 != self._oidc.digest:
                raise ValueError("OIDC identity pin or session resolver mismatch")
        if not isinstance(ingress_token, str) or len(ingress_token) < 32:
            raise ValueError("private ingress credential required")
        if resolver_version not in ("snapshot-v1", "session-snapshot-v1"):
            raise ValueError("unsupported resolver contract")
        self._application = resolver_version == "session-snapshot-v1"
        self._key = Ed25519PrivateKey.from_private_bytes(private_key)
        self._config = dict(asset=asset, registry_digest=registry_digest, trust_epoch=trust_epoch,
                            route_id=route_id, namespace=namespace, key_id=key_id)
        self._base, self._tenants = base, frozenset(tenants)
        self._identity_key, self._session_key = identity_key, session_key
        self._ingress, self._max = ingress_token, max_body_bytes
        self._clock = time.time if clock is None else clock
        self._proof_clock = proof_time if clock is None else clock

    def _identity(self, header, now):
        if not isinstance(header, str) or not header.startswith("Bearer "):
            raise ValueError("authentication required")
        token = header[7:]
        if self._oidc is not None:
            claims = self._oidc.verify(token, now)
            return claims, hmac.new(self._session_key, token.encode("ascii"), hashlib.sha256).hexdigest()
        if len(token) > 2048:
            raise ValueError("authentication required")
        payload, signature = token.split(".")
        expected = _b64(hmac.digest(self._identity_key, payload.encode("ascii"), "sha256"))
        if not hmac.compare_digest(signature, expected):
            raise ValueError("authentication required")
        raw = base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
        if _b64(raw) != payload:
            raise ValueError("noncanonical identity")
        claims = json.loads(raw, object_pairs_hook=_unique)
        if set(claims) != {"principal", "tenant", "jti", "exp", "iat"}:
            raise ValueError("invalid identity fields")
        if any(not isinstance(claims[k], str) or not _ID.fullmatch(claims[k]) for k in ("principal", "tenant", "jti")):
            raise ValueError("invalid identity scope")
        exp, issued = claims["exp"], claims["iat"]
        if type(exp) is not int or type(issued) is not int or exp <= int(now) or issued > int(now) + 5 or not 0 < exp - issued <= 600:
            raise ValueError("expired identity")
        return claims, hmac.new(self._session_key, token.encode("ascii"), hashlib.sha256).hexdigest()

    def read(self, method, target, headers, resolver):
        """Headers are a case-insensitive HTTP mapping from a private ingress.
        Authentication failures return no proof; only the edge may release
        a successful signed representation. The resolver is trusted code.
        """
        return self._read(method, target, headers, resolver, application=False)

    def read_application(self, method, target, headers, resolver):
        """Resolve (object_id, ReadIdentity) in one session/ACL DB snapshot.

        Requires an operator-pinned session-snapshot-v1 route. The SDK still
        owns authorization, serialization and signing; the application cannot
        supply arbitrary response bytes or an allow decision.
        """
        return self._read(method, target, headers, resolver, application=True)

    def _read(self, method, target, headers, resolver, *, application):
        now = self._proof_clock()
        def error(status):
            body = b"" if method == "HEAD" else _json({"error": "unavailable" if status == 503 else "forbidden"})
            return AuthorizedRepresentation(status, body, MappingProxyType({"Content-Type": "application/json", "Cache-Control": "private, no-store"}))
        if application != self._application:
            return error(503)
        try:
            # Apply the same boundary for direct SDK and framework adapters.
            names = {name.lower(): name for name in (
                "Authorization", "X-Lab-Ingress", "X-RA-Registry", "X-RA-Request-ID", "X-RA-Nonce")}
            canonical = {}
            for name, value in headers.items():
                key = names.get(name.lower())
                if key is not None:
                    if key in canonical:
                        return error(400)
                    canonical[key] = value
            headers = canonical
            if method not in ("GET", "HEAD") or not target.startswith(self._base + "/"):
                return error(400)
            object_id = target[len(self._base) + 1:]
            if not _ID.fullmatch(object_id):
                return error(400)
            if not hmac.compare_digest(headers.get("X-Lab-Ingress", ""), self._ingress):
                return error(403)
            if headers.get("X-RA-Registry") != self._config["registry_digest"]:
                return error(503)
            request_id, nonce = headers.get("X-RA-Request-ID", ""), headers.get("X-RA-Nonce", "")
            if not _ID.fullmatch(request_id) or not re.fullmatch(r"[0-9a-f]{48}", nonce):
                return error(503)
            claims, session = self._identity(headers.get("Authorization", ""), self._clock())
            if claims["tenant"] not in self._tenants:
                return error(403)
        except (ValueError, TypeError, UnicodeError):
            return error(401)
        decision, status, payload = "unknown", 503, {"error": "unavailable"}
        authz, content = "unknown", "unknown"
        try:
            if application:
                identity = ReadIdentity(claims["principal"], claims["tenant"],
                                        hashlib.sha256(headers["Authorization"][7:].encode("ascii")).hexdigest())
                result = resolver(object_id, identity)
                if not isinstance(result, ApplicationSnapshot) or type(result.session_valid) is not bool:
                    raise ValueError("invalid application snapshot")
                if not result.session_valid:
                    if result.object_snapshot is not None:
                        raise ValueError("object read for rejected session")
                    return self._represent(method, object_id, claims, session, request_id, nonce,
                                           "unauthenticated", 401, "unknown", "unknown",
                                           _json({"error": "authentication required"}), now)
                if result.object_snapshot is None:
                    return self._represent(method, object_id, claims, session, request_id, nonce,
                                           "not_found", 404, "unknown", "unknown",
                                           _json({"error": "not found"}), now)
                snapshot = result.object_snapshot
            else:
                snapshot = resolver(object_id)
            if not isinstance(snapshot, ObjectSnapshot) or snapshot.canonical_id != object_id:
                raise ValueError("resolver identity mismatch")
            for value in (snapshot.tenant, snapshot.owner, snapshot.authz_revision, snapshot.content_revision):
                if not isinstance(value, str) or not _ID.fullmatch(value):
                    raise ValueError("invalid resolver snapshot")
            if type(snapshot.grants) is not tuple or len(snapshot.grants) > 256 or any(not isinstance(g, str) or not _ID.fullmatch(g) for g in snapshot.grants):
                raise ValueError("invalid grants")
            authz, content = snapshot.authz_revision, snapshot.content_revision
            if snapshot.tenant != claims["tenant"] or (snapshot.owner != claims["principal"] and claims["principal"] not in snapshot.grants):
                decision, status, payload = "deny", 403, {"error": "forbidden"}
            else:
                # No serializer callback or arbitrary-byte signing surface:
                # only this resolver snapshot is serialized by the SDK.
                decision, status, payload = "allow", 200, snapshot.payload
            body = _json(payload)
            if len(body) > self._max:
                raise ValueError("response limit")
        except Exception:
            # No resolver exception, payload, ACL, or credential enters logs.
            decision, status, body = "unknown", 503, _json({"error": "unavailable"})
        return self._represent(method, object_id, claims, session, request_id, nonce,
                               decision, status, authz, content, body, now)

    def _represent(self, method, object_id, claims, session, request_id, nonce,
                   decision, status, authz, content, body, now):
        if method == "HEAD":
            body = b""
        issued = int(self._proof_clock() * 1000)
        if issued < int(now * 1000) or issued - int(now * 1000) >= 5000:
            body = b"" if method == "HEAD" else _json({"error": "unavailable"})
            return AuthorizedRepresentation(503, body, MappingProxyType({
                "Content-Type": "application/json", "Cache-Control": "private, no-store"}))
        resource = hmac.new(self._session_key, _json([claims["tenant"], self._config["namespace"], object_id]), hashlib.sha256).hexdigest()
        proof = {k: v for k, v in self._config.items() if k != "namespace"}
        proof.update(schema="release-proof/1", request_id=request_id, nonce=nonce,
                     method=method, tenant=claims["tenant"], principal=claims["principal"],
                     session=session, resource_hmac=resource, action="read",
                     authz_revision=authz, content_revision=content, decision=decision,
                     status=status, body_length=len(body), body_sha256=hashlib.sha256(body).hexdigest(),
                     issued_ms=issued, expires_ms=issued + 5000)
        raw = _json(proof)
        envelope = _json({"key_id": self._config["key_id"], "payload": _b64(raw), "signature": _b64(self._key.sign(raw))}).decode("ascii")
        return AuthorizedRepresentation(status, body, MappingProxyType({"Content-Type": "application/json",
                    "Cache-Control": "private, no-store", "X-RA-Release-Proof": envelope}))

"""Pinned, offline Keycloak-compatible RS256 access-token verification.

No discovery, JWKS HTTP fetch, token introspection or claim-selected URLs occur
on a request. Operators pin issuer/audience/authorized client, public keys and
stable subject-to-application identity mappings in one versioned config.
"""
import base64
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit

import jwt
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers

_ID = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_TOKEN_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
_OPAQUE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
ADAPTER = "oidc-jwt-rs256-v1"


def _unique(pairs):
    result = {}
    for k, v in pairs:
        if k in result:
            raise ValueError("duplicate OIDC JSON key")
        result[k] = v
    return result


def _decode(raw, maximum):
    if not isinstance(raw, str) or not 0 < len(raw) <= maximum:
        raise ValueError("OIDC token rejected")
    decoded = base64.b64decode(raw + "=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != raw:
        raise ValueError("noncanonical OIDC encoding")
    return decoded


def _reject_number(_):
    raise ValueError("invalid OIDC number")


def _object(raw, maximum):
    if len(raw) > maximum:
        raise ValueError("OIDC JSON limit")
    result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_reject_number)
    if not isinstance(result, dict):
        raise ValueError("OIDC object required")
    def depth(value, level=0):
        if level > 32:
            raise ValueError("OIDC nesting limit")
        if isinstance(value, dict):
            for item in value.values(): depth(item, level + 1)
        elif isinstance(value, list):
            for item in value: depth(item, level + 1)
    depth(result)
    return result


def _issuer(raw):
    if not isinstance(raw, str) or not 0 < len(raw) <= 256 or raw.endswith("/") or any(c in raw for c in "?#%") or any(ord(c) < 33 or ord(c) > 126 or c in '<>"&\\' for c in raw):
        return False
    try:
        u = urlsplit(raw)
        if not u.hostname or u.username is not None or u.password is not None or u.query or u.fragment or "//" in u.path or "/../" in u.path or "%" in u.path:
            return False
        if u.port is not None and not 1 <= u.port <= 65535:
            return False
        return u.scheme == "https" or (u.scheme == "http" and ipaddress.ip_address(u.hostname).is_loopback)
    except ValueError:
        return False


class OIDCVerifier:
    @classmethod
    def from_json(cls, raw):
        return cls(_object(raw, 65536))

    def __init__(self, config):
        raw = json.dumps(config, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")).encode("ascii")
        c = _object(raw, 65536)
        if set(c) != {"schema", "issuer", "audience", "client_id", "tenant_claim", "max_lifetime_seconds", "subjects", "keys"}:
            raise ValueError("invalid OIDC configuration")
        if c["schema"] != "oidc-rs256/1" or not _issuer(c["issuer"]) or any(not isinstance(c[k], str) or not _ID.fullmatch(c[k]) for k in ("audience", "client_id", "tenant_claim")):
            raise ValueError("invalid OIDC configuration")
        if c["tenant_claim"] in {"iss", "sub", "aud", "typ", "azp", "exp", "iat", "nbf", "jti", "sid"} or type(c["max_lifetime_seconds"]) is not int or not 1 <= c["max_lifetime_seconds"] <= 600:
            raise ValueError("invalid OIDC scope")
        if not isinstance(c["subjects"], dict) or not 1 <= len(c["subjects"]) <= 256:
            raise ValueError("invalid subject mappings")
        for sub, mapping in c["subjects"].items():
            if not _OPAQUE.fullmatch(sub) or not isinstance(mapping, dict) or set(mapping) != {"principal", "tenant"} or any(not isinstance(v, str) or not _ID.fullmatch(v) for v in mapping.values()):
                raise ValueError("invalid subject mapping")
        if not isinstance(c["keys"], list) or not 1 <= len(c["keys"]) <= 8:
            raise ValueError("invalid OIDC keys")
        keys = {}
        for key in c["keys"]:
            if not isinstance(key, dict) or set(key) != {"kid", "n", "e"} or not isinstance(key["kid"], str) or not _OPAQUE.fullmatch(key["kid"]) or key["kid"] in keys:
                raise ValueError("invalid OIDC key")
            n, e = _decode(key["n"], 684), _decode(key["e"], 8)
            modulus, exponent = int.from_bytes(n), int.from_bytes(e)
            if not n or not e or n[0] == 0 or e[0] == 0 or modulus % 2 == 0 or not 2048 <= modulus.bit_length() <= 4096 or not 3 <= exponent <= 2147483647 or exponent % 2 != 1:
                raise ValueError("invalid RSA key")
            keys[key["kid"]] = RSAPublicNumbers(exponent, modulus).public_key()
        self._config, self._keys = c, keys
        self.digest = hashlib.sha256(raw).hexdigest()

    def verify(self, token, now):
        try:
            if not isinstance(token, str) or len(token) > 8192:
                raise ValueError()
            head, payload, signature = token.split(".")
            header = _object(_decode(head, 1024), 768)
            _decode(signature, 684)
            claims = _object(_decode(payload, 7500), 6144)
            if set(header) != {"alg", "kid", "typ"} or header["alg"] != "RS256" or header["typ"] != "JWT":
                raise ValueError()
            key = self._keys[header["kid"]]
            aud = claims.get("aud")
            audiences = [aud] if isinstance(aud, str) else aud
            if not isinstance(audiences, list) or not 1 <= len(audiences) <= 8 or any(not isinstance(a, str) or not 1 <= len(a) <= 256 for a in audiences):
                raise ValueError()
            # Signature/algorithm/issuer/audience use PyJWT. Explicit time
            # checks below use the caller clock, shared with the Go contract.
            jwt.decode(token, key, algorithms=["RS256"], issuer=self._config["issuer"], audience=self._config["audience"],
                       options={"require": ["exp", "iat", "sub", "iss", "aud"], "verify_exp": False, "verify_iat": False, "verify_nbf": False})
            issued, expires = claims["iat"], claims["exp"]
            if type(issued) is not int or type(expires) is not int or issued <= 0 or expires <= int(now) or issued > int(now) + 5 or not 0 < expires - issued <= self._config["max_lifetime_seconds"]:
                raise ValueError()
            if "nbf" in claims and (type(claims["nbf"]) is not int or claims["nbf"] > int(now)):
                raise ValueError()
            if claims.get("typ") != "Bearer" or claims.get("azp") != self._config["client_id"] or any(not isinstance(claims.get(k), str) or not _TOKEN_ID.fullmatch(claims[k]) for k in ("jti", "sid")):
                raise ValueError()
            mapping = self._config["subjects"][claims["sub"]]
            if claims.get(self._config["tenant_claim"]) != mapping["tenant"]:
                raise ValueError()
            return {"principal": mapping["principal"], "tenant": mapping["tenant"], "jti": claims["jti"], "iat": issued, "exp": expires}
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, jwt.PyJWTError):
            raise ValueError("OIDC identity rejected") from None

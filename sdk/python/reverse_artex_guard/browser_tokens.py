"""Separate ID/logout-token validation for the browser Authorization Code flow."""
import base64
import hashlib
import hmac
import jwt

from .oidc import OIDCVerifier, _object, _decode, _TOKEN_ID

LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"


def half_hash(value):
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest()[:16]).rstrip(b"=").decode("ascii")


class BrowserTokens:
    def __init__(self, config):
        self.access = OIDCVerifier(config)
        self.config = self.access._config  # Private detached snapshot in this package.

    def _signed(self, token, *, logout=False):
        if not isinstance(token, str) or len(token) > 8192:
            raise ValueError()
        head, payload, signature = token.split(".")
        header = _object(_decode(head, 1024), 768)
        claims = _object(_decode(payload, 7500), 6144)
        _decode(signature, 684)
        types = {"JWT", "logout+jwt"} if logout else {"JWT"}
        if set(header) != {"alg", "kid", "typ"} or header["alg"] != "RS256" or header["typ"] not in types:
            raise ValueError()
        aud = claims.get("aud")
        audiences = [aud] if isinstance(aud, str) else aud
        if not isinstance(audiences, list) or not 1 <= len(audiences) <= 8 or any(not isinstance(a, str) or not 1 <= len(a) <= 256 for a in audiences):
            raise ValueError()
        jwt.decode(token, self.access._keys[header["kid"]], algorithms=["RS256"], issuer=self.config["issuer"], audience=self.config["client_id"],
                   options={"require": ["iss", "aud", "iat"], "verify_exp": False, "verify_iat": False, "verify_nbf": False})
        if ("azp" in claims or len(audiences) > 1) and claims.get("azp") != self.config["client_id"]:
            raise ValueError()
        return claims

    def login(self, access, identity, nonce, code, created, now):
        try:
            mapped = self.access.verify(access, now)
            # This payload is used only after the existing signature verifier.
            ac = _object(_decode(access.split(".")[1], 7500), 6144)
            c = self._signed(identity)
            issued, expires = c["iat"], c["exp"]
            if type(issued) is not int or type(expires) is not int or not created - 5 <= issued <= int(now) + 5 or expires <= int(now) or not 0 < expires - issued <= self.config["max_lifetime_seconds"]:
                raise ValueError()
            if "nbf" in c and (type(c["nbf"]) is not int or c["nbf"] > now):
                raise ValueError()
            if c.get("typ") not in (None, "ID") or not isinstance(c.get("nonce"), str) or not hmac.compare_digest(c["nonce"], nonce):
                raise ValueError()
            if c["sub"] != ac["sub"] or c.get("sid") != ac["sid"]:
                raise ValueError()
            for key, value in (("at_hash", access), ("c_hash", code)):
                if key in c and (not isinstance(c[key], str) or not hmac.compare_digest(c[key], half_hash(value))):
                    raise ValueError()
            return dict(mapped, sub=ac["sub"], sid=ac["sid"], exp=min(expires, mapped["exp"]))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, jwt.PyJWTError):
            raise ValueError("browser identity rejected") from None

    def logout(self, token, now):
        try:
            c = self._signed(token, logout=True)
            issued = c["iat"]
            if type(issued) is not int or not int(now) - 60 <= issued <= int(now) + 5:
                raise ValueError()
            if c.get("events") != {LOGOUT_EVENT: {}} or "nonce" in c or c.get("typ") not in (None, "Logout"):
                raise ValueError()
            if "exp" in c and (type(c["exp"]) is not int or c["exp"] <= now or not 0 < c["exp"] - issued <= 600):
                raise ValueError()
            if "nbf" in c and (type(c["nbf"]) is not int or c["nbf"] > now):
                raise ValueError()
            if not isinstance(c.get("jti"), str) or not _TOKEN_ID.fullmatch(c["jti"]):
                raise ValueError()
            sub, sid = c.get("sub"), c.get("sid")
            if sub is None and sid is None:
                raise ValueError()
            if sub is not None and sub not in self.config["subjects"]:
                raise ValueError()
            if sid is not None and (not isinstance(sid, str) or not _TOKEN_ID.fullmatch(sid)):
                raise ValueError()
            return {"sub": sub, "sid": sid, "iat": issued, "jti": c["jti"]}
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, jwt.PyJWTError):
            raise ValueError("logout identity rejected") from None

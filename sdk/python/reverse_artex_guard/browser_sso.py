"""Keycloak BFF: Code/PKCE login and app-session-aware logout.

The lifecycle object implements create(digest, principal, tenant, expires),
active(digest, principal, tenant, now), revoke(digests). No bearer token is
returned by the session API. Deploy behind TLS with a private edge/upstream;
default memory state expires on restart; optional shared state is explicit.
"""
import base64
from contextlib import nullcontext
from dataclasses import dataclass
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler
import html
import json
import re
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from .browser_tokens import BrowserTokens
from .oidc import _issuer, _object

_OPAQUE = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class Unavailable(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes = b""
    headers: tuple = ()


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def origin(value):
    if not _issuer(value) or urllib.parse.urlsplit(value).path:
        raise ValueError("exact HTTPS origin or literal loopback HTTP origin required")
    return value


class BrowserSSO:
    def __init__(self, config, *, public_origin, lifecycle, client_secret=None, clock=time.time, capacity=1024, state_store=None):
        self.tokens = BrowserTokens(config)
        self.public_origin = origin(public_origin)
        self.authority = urllib.parse.urlsplit(public_origin).netloc
        self.secure = public_origin.startswith("https://")
        self.cookie_name = "__Host-ra_browser" if self.secure else "ra_browser_dev"
        self.tx_cookie = "__Host-ra_transaction" if self.secure else "ra_transaction_dev"
        self.issuer = self.tokens.config["issuer"]
        self.client_id = self.tokens.config["client_id"]
        if client_secret is not None and (not isinstance(client_secret, str) or not 32 <= len(client_secret) <= 4096 or not client_secret.isascii()):
            raise ValueError("invalid confidential client secret")
        if type(capacity) is not int or not 1 <= capacity <= 4096:
            raise ValueError("invalid session capacity")
        self.client_secret = client_secret
        self.lifecycle, self.clock, self.capacity = lifecycle, clock, capacity
        self.lock = threading.RLock()
        self.sessions, self.transactions, self.revocations, self.seen_logout = {}, {}, {}, {}
        self.closed = False
        self.http = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self._state_store = state_store
        if state_store is not None:
            state_store.bind(self, lifecycle)
            self.lock, self.lifecycle = state_store.lock, state_store.lifecycle
            self.sessions = state_store.maps["session"]
            self.transactions = state_store.maps["transaction"]
            self.revocations = state_store.maps["revocation"]
            self.seen_logout = state_store.maps["seen"]

    def _cookie(self, name, value, max_age):
        return ("Set-Cookie", f"{name}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}" + ("; Secure" if self.secure else ""))

    def cookie(self, raw, transaction=False):
        if not isinstance(raw, str) or len(raw) > 8192:
            return ""
        name = self.tx_cookie if transaction else self.cookie_name
        pairs = [part.strip().split("=", 1) for part in raw.split(";")]
        values = [p[1] for p in pairs if len(p) == 2 and p[0] == name]
        return values[0] if len(values) == 1 and _OPAQUE.fullmatch(values[0]) else ""

    def _prune(self, now):
        if self._state_store is not None:
            self._state_store.prune(now)
            return
        for state, tx in list(self.transactions.items()):
            if tx["expires"] <= now:
                del self.transactions[state]
        for store in (self.revocations, self.seen_logout):
            for key, value in list(store.items()):
                if value["expires"] <= now:
                    del store[key]
        expired = [key for key, s in self.sessions.items() if s["exp"] <= now]
        if expired:
            self.lifecycle.revoke([self.sessions[key]["digest"] for key in expired])
            for key in expired:
                del self.sessions[key]

    def _transaction(self, kind):
        now = self.clock()
        with self.lock:
            self._prune(now)
            if self.closed or len(self.transactions) >= self.capacity:
                raise Unavailable()
            state, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            tx = {"kind": kind, "binding": binding, "expires": now + 300, "created": int(now),
                  "nonce": secrets.token_urlsafe(32), "verifier": secrets.token_urlsafe(32)}
            self.transactions[state] = tx
        return state, tx

    def _consume(self, query, cookie, kind):
        if self.closed:
            raise Unavailable()
        state = query.get("state", "")
        if not _OPAQUE.fullmatch(state):
            raise ValueError()
        with self.lock:
            if self.closed:
                raise Unavailable()
            tx = self.transactions.get(state)
            if tx is None or tx["kind"] != kind or tx["expires"] <= self.clock() or not hmac.compare_digest(tx["binding"], cookie):
                raise ValueError()
            del self.transactions[state]  # One attempt, including token-exchange failure.
            return tx

    def login(self):
        state, tx = self._transaction("login")
        challenge = base64.urlsafe_b64encode(hashlib.sha256(tx["verifier"].encode("ascii")).digest()).rstrip(b"=").decode("ascii")
        location = self.issuer + "/protocol/openid-connect/auth?" + urllib.parse.urlencode({
            "client_id": self.client_id, "response_type": "code", "response_mode": "query", "scope": "openid",
            "redirect_uri": self.public_origin + "/auth/callback", "state": state, "nonce": tx["nonce"],
            "code_challenge": challenge, "code_challenge_method": "S256"})
        return Response(303, headers=(("Location", location), self._cookie(self.tx_cookie, tx["binding"], 300)))

    def exchange(self, code, verifier):
        form = {"grant_type": "authorization_code", "client_id": self.client_id, "code": code,
                "redirect_uri": self.public_origin + "/auth/callback", "code_verifier": verifier}
        if self.client_secret is not None:
            form["client_secret"] = self.client_secret
        req = urllib.request.Request(self.issuer + "/protocol/openid-connect/token", data=urllib.parse.urlencode(form).encode("ascii"),
                                     headers={"Accept": "application/json", "Accept-Encoding": "identity"})
        try:
            with self.http.open(req, timeout=5) as response:
                if response.status != 200 or response.headers.get("Content-Encoding", "identity") != "identity":
                    raise ValueError()
                value = _object(response.read(65537), 65536)
                if value.get("token_type", "").lower() != "bearer":
                    raise ValueError()
                return value["access_token"], value["id_token"]
        except urllib.error.HTTPError as error:
            error.close()
            raise ValueError("authorization code rejected") from None
        except (OSError, urllib.error.URLError):
            raise Unavailable() from None

    def _blocked(self, claims):
        if self._state_store is not None:
            return self._state_store.blocked(claims)
        for (sub, sid), marker in self.revocations.items():
            if (sub is None or claims["sub"] == sub) and (sid is None or claims["sid"] == sid) and (sid is not None or claims["iat"] <= marker["iat"]):
                return True
        return False

    def callback(self, query, transaction_cookie, previous_cookie=""):
        if set(query) - {"state", "code", "iss", "session_state", "error", "error_description"}:
            raise ValueError()
        tx = self._consume(query, transaction_cookie, "login")
        if "error" in query or query.get("iss", self.issuer) != self.issuer:
            raise ValueError()
        code = query.get("code", "")
        if not 1 <= len(code) <= 2048 or not code.isascii() or any(ord(c) < 33 or ord(c) > 126 for c in code):
            raise ValueError()
        access, identity = self.exchange(code, tx["verifier"])
        claims = self.tokens.login(access, identity, tx["nonce"], code, tx["created"], self.clock())
        with self.lock:
            self._prune(self.clock())
            if self.closed or self._blocked(claims):
                raise ValueError()
            if len(self.sessions) >= self.capacity and previous_cookie not in self.sessions:
                raise Unavailable()
            if previous_cookie in self.sessions:
                self.lifecycle.revoke([self.sessions[previous_cookie]["digest"]])
                del self.sessions[previous_cookie]
            key = secrets.token_urlsafe(32)
            session = dict(claims, access=access, identity=identity, csrf=secrets.token_urlsafe(32),
                           digest=hashlib.sha256(access.encode("ascii")).hexdigest())
            self.lifecycle.create(session["digest"], session["principal"], session["tenant"], session["exp"])
            self.sessions[key] = session
        return Response(303, headers=(("Location", "/"), self._cookie(self.cookie_name, key, max(1, int(claims["exp"] - self.clock()))),
                                       self._cookie(self.tx_cookie, "", 0)))

    def session(self, key):
        if self.closed:
            return None
        with self.lock:
            if self.closed:
                return None
            self._prune(self.clock())
            s = self.sessions.get(key)
            if s is None or self._blocked(s):
                return None
            if not self.lifecycle.active(s["digest"], s["principal"], s["tenant"], self.clock()):
                del self.sessions[key]
                return None
            return dict(s)

    def logout(self, key, csrf):
        with self.lock:
            session = self.session(key)
            if session is None or not isinstance(csrf, str) or not hmac.compare_digest(csrf, session["csrf"]):
                raise ValueError()
            # Prepare bounded return state before touching the current session.
            state, tx = self._transaction("logout")
            self.lifecycle.revoke([session["digest"]])
            del self.sessions[key]
        target = self.issuer + "/protocol/openid-connect/logout"
        fields = {"id_token_hint": session["identity"], "client_id": self.client_id,
                  "post_logout_redirect_uri": self.public_origin + "/auth/logged-out", "state": state}
        nonce = secrets.token_urlsafe(24)
        inputs = "".join('<input type="hidden" name="' + k + '" value="' + html.escape(v, quote=True) + '">' for k, v in fields.items())
        body = ('<!doctype html><html lang="ko"><meta charset="utf-8"><title>로그아웃 연결</title><p>로그아웃 중입니다.</p>'
                '<form id="logout" method="post" action="' + html.escape(target, quote=True) + '">' + inputs +
                '<noscript><button>Keycloak 로그아웃 계속</button></noscript></form><script nonce="' + nonce + '">document.getElementById("logout").submit()</script></html>').encode("utf-8")
        policy = "default-src 'none'; script-src 'nonce-" + nonce + "'; form-action " + urllib.parse.urlsplit(self.issuer).scheme + "://" + urllib.parse.urlsplit(self.issuer).netloc + " " + self.public_origin + "; base-uri 'none'; frame-ancestors 'none'"
        return Response(200, body, (("Content-Type", "text/html; charset=utf-8"), ("Content-Security-Policy", policy),
                                    self._cookie(self.cookie_name, "", 0), self._cookie(self.tx_cookie, tx["binding"], 300)))

    def logged_out(self, query, cookie):
        if set(query) != {"state"}:
            raise ValueError()
        self._consume(query, cookie, "logout")
        return Response(303, headers=(("Location", "/"), self._cookie(self.tx_cookie, "", 0), self._cookie(self.cookie_name, "", 0)))

    def backchannel(self, token):
        claims = self.tokens.logout(token, self.clock())
        with self.lock:
            if self.closed:
                raise Unavailable()
            self._prune(self.clock())
            if claims["jti"] in self.seen_logout:
                raise ValueError()
            if len(self.revocations) >= self.capacity * 2 or len(self.seen_logout) >= self.capacity * 2:
                raise Unavailable()
            matches = [key for key, s in self.sessions.items() if (claims["sub"] is None or s["sub"] == claims["sub"]) and
                       (claims["sid"] is None or s["sid"] == claims["sid"])]
            self.lifecycle.revoke([self.sessions[key]["digest"] for key in matches])
            expiry = self.clock() + self.tokens.config["max_lifetime_seconds"] + 65
            self.revocations[(claims["sub"], claims["sid"])] = {"iat": claims["iat"], "expires": expiry}
            self.seen_logout[claims["jti"]] = {"expires": expiry}
            for key in matches:
                del self.sessions[key]
        return Response(200)

    def begin_close(self):
        """Fence late work without waiting for an already admitted operation."""
        self.closed = True

    def close(self):
        self.begin_close()
        if self._state_store is not None:
            # Worker shutdown is local; other workers retain durable sessions.
            self.closed = True
            return
        with self.lock:
            self.closed = True
            self.lifecycle.revoke([s["digest"] for s in self.sessions.values()])
            self.sessions.clear()
            self.transactions.clear()


class BrowserSSOHandler(BaseHTTPRequestHandler):
    """Mount on a server with sso, edge_origin and allow_read(path) attributes.

    Only explicitly allowed GET/HEAD app reads are forwarded. App mutations need
    their own CSRF/authorization integration, never an automatic catch-all proxy.
    Override landing()/asset() to mount an app shell; /auth/* stays owned here.
    """
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass  # Never log callback URLs, codes, cookies or tokens.

    def landing(self):
        return Response(200, b"<a href='/auth/login'>SSO login</a>", (("Content-Type", "text/html; charset=utf-8"),))

    def asset(self):
        return Response(404)

    def _one(self, name, default=""):
        values = self.headers.get_all(name, [])
        if len(values) > 1:
            raise ValueError()
        return values[0] if values else default

    def _form(self):
        if self._one("Transfer-Encoding") or self._one("Content-Type") != "application/x-www-form-urlencoded":
            raise ValueError()
        length = self._one("Content-Length")
        if not length.isdecimal() or not 0 < int(length) <= 16384:
            raise ValueError()
        self.connection.settimeout(5)
        raw = self.rfile.read(int(length))
        if len(raw) != int(length):
            raise ValueError()
        return self._query(raw.decode("ascii"))

    @staticmethod
    def _query(raw):
        values = urllib.parse.parse_qs(raw, keep_blank_values=True, strict_parsing=True, max_num_fields=8, encoding="utf-8", errors="strict")
        if any(len(v) != 1 for v in values.values()):
            raise ValueError()
        return {k: v[0] for k, v in values.items()}

    def _reply(self, response):
        self.send_response(response.status)
        headers = list(response.headers)
        if not any(k.lower() == "content-security-policy" for k, _ in headers):
            headers.append(("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"))
        for key, value in headers:
            self.send_header(key, value)
        for key, value in (("Cache-Control", "no-store"), ("Pragma", "no-cache"), ("Referrer-Policy", "same-origin" if self.path == "/" else "no-referrer"),
                           ("X-Content-Type-Options", "nosniff"), ("Connection", "close")):
            self.send_header(key, value)
        if not any(k.lower() == "content-length" for k, _ in headers):
            self.send_header("Content-Length", str(len(response.body)))
        self.end_headers()
        self.close_connection = True
        if self.command != "HEAD" and response.body:
            self.wfile.write(response.body)

    def _proxy(self, sso, key):
        session = sso.session(key)
        if session is None:
            return Response(401, encoded({"error": "login_required"}), (("Content-Type", "application/json"),))
        # Browser credentials/RA headers are never passed to private ingress.
        req = urllib.request.Request(origin(self.server.edge_origin) + self.path, method=self.command,
                                     headers={"Authorization": "Bearer " + session["access"], "Accept-Encoding": "identity", "Accept": "application/json"})
        try:
            response = sso.http.open(req, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        except (OSError, urllib.error.URLError):
            raise Unavailable() from None
        with response:
            raw = response.read((1 << 20) + 1)
            if len(raw) > 1 << 20 or response.headers.get("Content-Encoding", "identity") != "identity" or 300 <= response.status < 400:
                raise Unavailable()
            headers = [("Content-Type", response.headers.get("Content-Type", "application/octet-stream"))]
            if self.command == "HEAD" and response.headers.get("Content-Length", "").isdecimal():
                headers.append(("Content-Length", response.headers["Content-Length"]))
            return Response(response.status, raw, tuple(headers))

    def _handle(self):
        sso = self.server.sso
        if self._one("Host") != sso.authority:
            return Response(400)
        if not self.path.startswith("/") or self.path.startswith("//") or "#" in self.path or len(self.path) > 8192:
            return Response(400)
        if self._one("Authorization") or any(k.lower().startswith(("x-ra-", "x-lab-")) for k in self.headers):
            return Response(400)
        cookie = self._one("Cookie")
        key, tx = sso.cookie(cookie), sso.cookie(cookie, True)
        path, _, query = self.path.partition("?")
        if path in ("/healthz", "/readyz") and callable(getattr(self.server, "probe", None)):
            if query:
                raise ValueError()
            if self.command not in ("GET", "HEAD"):
                return Response(405, headers=(("Allow", "GET, HEAD"),))
            return self.server.probe(path)
        if path == "/auth/backchannel-logout":
            if self.command != "POST" or query:
                return Response(405)
            fields = self._form()
            if set(fields) != {"logout_token"}:
                raise ValueError()
            return sso.backchannel(fields["logout_token"])
        if self.command == "POST":
            if path != "/auth/logout" or query:
                return Response(405)
            if self._one("Origin") != sso.public_origin:
                return Response(403)
            fields = self._form()
            if set(fields) != {"csrf"}:
                raise ValueError()
            return sso.logout(key, fields["csrf"])
        if self.command not in ("GET", "HEAD"):
            return Response(405)
        if path == "/auth/logout":
            return Response(405)
        if path == "/auth/login" and self.command == "GET" and not query:
            return sso.login()
        if path == "/auth/callback" and self.command == "GET":
            return sso.callback(self._query(query), tx, key)
        if path == "/auth/logged-out" and self.command == "GET":
            return sso.logged_out(self._query(query), tx)
        if path == "/auth/session" and not query:
            session = sso.session(key)
            data = {"authenticated": False} if session is None else {"authenticated": True, **{k: session[k] for k in ("principal", "tenant", "exp", "csrf")}}
            return Response(200, encoded(data), (("Content-Type", "application/json"),))
        if path == "/" and not query:
            return self.landing()
        if path == "/auth/ui.js" and not query:
            return self.asset()
        if self.server.allow_read(path):
            return self._proxy(sso, key)
        return Response(404)

    def do_GET(self):
        scope = getattr(self.server, "request_scope", None)
        manager = scope(self) if callable(scope) else nullcontext(True)
        with manager as admitted:
            try:
                if not admitted:
                    response = Response(503, encoded({"error": "authentication_unavailable"}),
                                        (("Content-Type", "application/json"), ("Retry-After", "1")))
                else:
                    # Reject unread GET bodies to prevent inconsistent proxy framing.
                    if self.command != "POST" and (self._one("Transfer-Encoding") or self._one("Content-Length", "0") != "0"):
                        raise ValueError()
                    response = self._handle()
            except (ValueError, UnicodeError, KeyError, TypeError, RecursionError):
                response = Response(400, encoded({"error": "request_rejected"}), (("Content-Type", "application/json"),))
            except Exception:
                response = Response(503, encoded({"error": "authentication_unavailable"}), (("Content-Type", "application/json"),))
            self._reply(response)

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_PATCH = do_GET

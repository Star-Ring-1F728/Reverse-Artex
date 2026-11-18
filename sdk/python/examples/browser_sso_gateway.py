#!/usr/bin/env python3
"""Run a small loopback portal backed by the browser SSO gateway."""
import argparse
import base64
import json
import math
import sys
import os
from pathlib import Path
import re
import stat
import sqlite3
from urllib.parse import urlsplit

from reverse_artex_guard.browser_sso import BrowserSSO, BrowserSSOHandler, Response, Unavailable, origin
from reverse_artex_guard.browser_server import BrowserSSOServer, run_browser_server
from reverse_artex_guard.oidc import _object
from sqlite_browser_sessions import SQLiteBrowserSessions
from reverse_artex_guard.sqlite_application import PROFILE, SQLiteApplicationStore
from reverse_artex_guard.sqlite_browser_state import SQLiteBrowserState
from reverse_artex_guard.browser_state_migration import transition_browser_state
from reverse_artex_guard.oidc import OIDCVerifier


PORTAL_HTML = """<!doctype html>
<html lang="ko">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="same-origin">
<title>Reverse Artex 보안 포털</title>
<script src="/auth/ui.js" defer></script>
</head>
<body>
<header><h1>Reverse Artex 보안 포털</h1></header>
<main>
<section aria-labelledby="account-heading">
<h2 id="account-heading">계정</h2>
<a id="login-link" href="/auth/login">SSO 로그인</a>
<div id="session-panel" hidden>
<p>사용자: <span id="principal">—</span></p>
<p>Tenant: <span id="tenant">—</span></p>
<p>세션 만료: <time id="expires">—</time></p>
<form id="logout-form" method="post" action="/auth/logout" hidden>
<input id="csrf" type="hidden" name="csrf" value="">
<button type="submit">로그아웃</button>
</form>
</div>
</section>
<section aria-labelledby="read-heading">
<h2 id="read-heading">업무 객체 읽기</h2>
<label for="object-id">객체 ID</label>
<input id="object-id" type="text" inputmode="numeric" autocomplete="off" maxlength="18">
<button type="button" data-route="api" disabled>Modern 객체 읽기</button>
<button type="button" data-route="legacy" disabled>Legacy 객체 읽기</button>
<pre id="result" aria-live="polite">로그인 후 객체 ID를 입력하세요.</pre>
</section>
</main>
</body>
</html>
"""


PORTAL_JS = r""""use strict";
const loginLink = document.getElementById("login-link");
const sessionPanel = document.getElementById("session-panel");
const logoutForm = document.getElementById("logout-form");
const csrfField = document.getElementById("csrf");
const objectId = document.getElementById("object-id");
const result = document.getElementById("result");
const buttons = Array.from(document.querySelectorAll("[data-route]"));
let authenticated = false;

function updateControls(value) {
  authenticated = value;
  loginLink.hidden = value;
  sessionPanel.hidden = !value;
  logoutForm.hidden = !value;
  for (const button of buttons) button.disabled = !value;
}

async function refreshSession() {
  try {
    const response = await fetch("/auth/session", {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
      headers: { Accept: "application/json" }
    });
    if (!response.ok) throw new Error("session unavailable");
    const session = await response.json();
    const signedIn = session.authenticated === true;
    updateControls(signedIn);
    if (signedIn) {
      document.getElementById("principal").textContent = String(session.principal || "—");
      document.getElementById("tenant").textContent = String(session.tenant || "—");
      const expires = Number(session.exp);
      document.getElementById("expires").textContent = Number.isFinite(expires)
        ? new Date(expires * 1000).toLocaleString("ko-KR")
        : "—";
      csrfField.value = typeof session.csrf === "string" ? session.csrf : "";
    } else {
      csrfField.value = "";
    }
  } catch (_error) {
    updateControls(false);
    csrfField.value = "";
    result.textContent = "로그인 상태를 확인할 수 없습니다.";
  }
}

for (const button of buttons) {
  button.addEventListener("click", async () => {
    const id = objectId.value.trim();
    if (!/^[1-9][0-9]{0,17}$/.test(id)) {
      result.textContent = "1부터 18자리까지의 객체 ID를 입력하세요.";
      return;
    }
    for (const item of buttons) item.disabled = true;
    result.textContent = "객체를 조회하고 있습니다…";
    try {
      const response = await fetch(`/${button.dataset.route}/objects/${id}`, {
        method: "GET",
        credentials: "same-origin",
        cache: "no-store",
        headers: { Accept: "application/json" }
      });
      const body = await response.text();
      result.textContent = `HTTP ${response.status}\n${body}`;
      if (response.status === 401) await refreshSession();
    } catch (_error) {
      result.textContent = "객체 조회를 완료하지 못했습니다.";
    } finally {
      for (const item of buttons) item.disabled = !authenticated;
    }
  });
}

refreshSession();
"""


class PortalHandler(BrowserSSOHandler):
    """Serve the Korean portal shell and its external JavaScript asset."""

    def landing(self):
        return Response(
            200,
            PORTAL_HTML.encode("utf-8"),
            (("Content-Type", "text/html; charset=utf-8"),),
        )

    def asset(self):
        return Response(
            200,
            PORTAL_JS.encode("utf-8"),
            (("Content-Type", "application/javascript; charset=utf-8"),),
        )


def allow_read(path):
    return (
        re.fullmatch(r"/(?:api|legacy)/objects/[1-9][0-9]{0,17}", path) is not None
        or path == "/api/search"
    )


def loopback_port(value):
    match = re.fullmatch(r"127\.0\.0\.1:([1-9][0-9]{0,4})", value)
    if match is None:
        raise argparse.ArgumentTypeError("listen must be 127.0.0.1:port")
    port = int(match.group(1))
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("listen port must be in 1..65535")
    return port


def shutdown_seconds(value):
    number = float(value)
    if not math.isfinite(number) or not .05 <= number <= 60:
        raise argparse.ArgumentTypeError("shutdown timeout must be in 0.05..60 seconds")
    return number


def connection_limit(value):
    number = int(value)
    if not 1 <= number <= 1024:
        raise argparse.ArgumentTypeError("max connections must be in 1..1024")
    return number


def read_identity_config(path):
    config_path = Path(path)
    info = config_path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise ValueError("identity config must be a regular file no larger than 64 KiB")
    with config_path.open("rb") as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError("identity config must be a regular file no larger than 64 KiB")
    return _object(raw.decode("utf-8"), 65536)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--identity-config", required=True, help="pinned OIDC JSON file, at most 64 KiB")
    parser.add_argument("--public-origin", required=True, help="exact browser-visible HTTPS origin or loopback HTTP origin")
    parser.add_argument("--edge-origin", required=True, help="exact private edge origin")
    parser.add_argument("--database", required=True, help="existing application SQLite database")
    parser.add_argument("--database-profile", choices=("legacy-session-v1", PROFILE), default="legacy-session-v1",
                        help="explicit existing database profile; never auto-migrate")
    parser.add_argument("--listen", required=True, type=loopback_port, help="loopback listener in 127.0.0.1:port form")
    parser.add_argument("--browser-state-key-env", help="environment variable containing a canonical base64 32-byte external state key; native profile only")
    parser.add_argument("--browser-state-additional-key-env", action="append", default=[], help="preload another external key for rolling rotation; at most three, environment names only")
    parser.add_argument("--browser-state-capacity", type=int, default=1024, help="exact persisted shared capacity (1..4096)")
    parser.add_argument("--browser-state-minimum-generation", type=int, default=0, help="external minimum accepted epoch generation")
    operations = parser.add_mutually_exclusive_group()
    operations.add_argument("--initialize-browser-state", action="store_true", help="explicitly initialize encrypted browser tables, then exit")
    operations.add_argument("--describe-browser-state", action="store_true", help="print authenticated public epoch/CAS status, then exit")
    operations.add_argument("--rotate-browser-state", action="store_true", help="atomically rotate encryption and lookup keys, then exit")
    operations.add_argument("--migrate-browser-state", action="store_true", help="atomically migrate the explicit context, then exit")
    parser.add_argument("--browser-state-target-key-env", help="external target key environment name for an explicit transition")
    parser.add_argument("--expected-state-epoch", help="compare-and-swap epoch from authenticated describe output")
    parser.add_argument("--state-operation-id", help="unique idempotency identifier (1..64 application identifier characters)")
    parser.add_argument("--target-identity-config", help="pinned target OIDC JSON; a changed pin requires revoke policy")
    parser.add_argument("--target-public-origin", help="exact target public origin; a changed origin requires revoke policy")
    parser.add_argument("--target-state-capacity", type=int, help="target shared capacity (1..4096)")
    parser.add_argument("--state-session-policy", choices=("preserve", "revoke"), default="preserve")
    parser.add_argument("--shutdown-timeout", type=shutdown_seconds, default=10, help="grace period in seconds before reporting an incomplete drain")
    parser.add_argument("--max-connections", type=connection_limit, default=64, help="bounded private listener connections (1..1024)")
    parser.add_argument("--shutdown-on-stdin-eof", action="store_true", help="allow an explicit local supervisor stdin EOF to stop this worker")
    parser.add_argument("--client-secret-env", help="environment variable name holding an optional confidential client secret")
    return parser



def read_state_key(name):
    if not isinstance(name, str) or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None:
        raise ValueError("browser state key source must be an environment variable name")
    value = os.environ.get(name, "")
    try:
        key = base64.b64decode(value, validate=True)
        if len(key) != 32 or base64.b64encode(key).decode("ascii") != value:
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError("external browser state key must be canonical base64 of 32 bytes") from None
    return key


def main(argv=None, *, runtime_runner=None, announce=None):
    runtime_runner = run_browser_server if runtime_runner is None else runtime_runner
    announce = print if announce is None else announce
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        config = read_identity_config(args.identity_config)
        public_origin = origin(args.public_origin)
        edge_origin = origin(args.edge_origin)
        public_parts = urlsplit(public_origin)
        if public_parts.scheme == "http" and (
            public_parts.hostname != "127.0.0.1" or (public_parts.port or 80) != args.listen
        ):
            raise ValueError("loopback public origin must match the listener port")
        database = Path(args.database).expanduser().resolve(strict=True)
        if not database.is_file():
            raise ValueError("database must be an existing regular file")
        client_secret = None
        if args.client_secret_env is not None:
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", args.client_secret_env) is None:
                raise ValueError("client-secret-env must be an environment variable name")
            client_secret = os.environ.get(args.client_secret_env)
            if client_secret is None:
                raise ValueError("client-secret environment variable is unset")
        lifecycle = SQLiteApplicationStore(database) if args.database_profile == PROFILE else SQLiteBrowserSessions(database)
        state_store = None
        transition = args.rotate_browser_state or args.migrate_browser_state
        admin = transition or args.initialize_browser_state or args.describe_browser_state
        if admin and (args.shutdown_on_stdin_eof or args.shutdown_timeout != 10 or args.max_connections != 64):
            raise ValueError("listener runtime options require server mode")
        target_flags = (args.browser_state_target_key_env, args.expected_state_epoch, args.state_operation_id,
                        args.target_identity_config, args.target_public_origin, args.target_state_capacity)
        if not transition and (any(v is not None for v in target_flags) or args.state_session_policy != 'preserve'):
            raise ValueError("transition options require explicit rotate-browser-state or migrate-browser-state")
        if args.browser_state_key_env is not None:
            if args.database_profile != PROFILE:
                raise ValueError("shared browser state requires the explicit native database profile")
            key = read_state_key(args.browser_state_key_env)
            additional = tuple(read_state_key(name) for name in args.browser_state_additional_key_env)
            options = dict(identity_digest=OIDCVerifier(config).digest, public_origin=public_origin,
                           capacity=args.browser_state_capacity)
            if args.initialize_browser_state:
                if additional or args.browser_state_minimum_generation:
                    raise ValueError("initialization accepts one key at generation zero")
                SQLiteBrowserState.initialize(lifecycle, key, **options)
                announce("Encrypted browser state initialized.", flush=True)
                return 0
            if transition:
                if args.browser_state_target_key_env is None:
                    raise ValueError("explicit transition requires browser-state-target-key-env")
                receipt = transition_browser_state(lifecycle, (key, *additional), identity_config=config,
                    public_origin=public_origin, capacity=args.browser_state_capacity,
                    target_key=read_state_key(args.browser_state_target_key_env),
                    expected_epoch=args.expected_state_epoch, operation_id=args.state_operation_id,
                    target_identity_config=read_identity_config(args.target_identity_config) if args.target_identity_config else None,
                    target_public_origin=args.target_public_origin, target_capacity=args.target_state_capacity,
                    session_policy=args.state_session_policy, mode='rotate' if args.rotate_browser_state else 'migrate',
                    minimum_generation=args.browser_state_minimum_generation)
                announce(json.dumps(receipt, sort_keys=True, separators=(",", ":")), flush=True)
                return 0
            state_store = SQLiteBrowserState(lifecycle, key, additional_keys=additional,
                minimum_generation=args.browser_state_minimum_generation, **options)
            if args.describe_browser_state:
                announce(json.dumps(state_store.describe(), sort_keys=True, separators=(",", ":")), flush=True)
                return 0
        elif (args.initialize_browser_state or args.describe_browser_state or transition or args.browser_state_additional_key_env
              or args.browser_state_capacity != 1024 or args.browser_state_minimum_generation):
            raise ValueError("shared state options require browser-state-key-env and a native database")
        sso = BrowserSSO(
            config,
            public_origin=public_origin,
            lifecycle=lifecycle,
            client_secret=client_secret,
            state_store=state_store,
            capacity=args.browser_state_capacity,
        )
    except (sqlite3.Error, Unavailable):
        parser.error("application or browser state database unavailable; inspect epoch and retry the same operation id")
    except (OSError, UnicodeError, ValueError, TypeError, KeyError) as error:
        parser.error(str(error))

    def ready():
        if sso.closed:
            return False
        return state_store.ready() if state_store is not None else lifecycle.ready()

    server = None
    try:
        server = BrowserSSOServer(("127.0.0.1", args.listen), PortalHandler, sso=sso,
            edge_origin=edge_origin, allow_read=allow_read, readiness_check=ready, max_connections=args.max_connections)
        report = runtime_runner(server, drain_timeout=args.shutdown_timeout,
            shutdown_stdin=sys.stdin.buffer if args.shutdown_on_stdin_eof else None,
            on_started=lambda: announce(public_origin, flush=True))
        announce(json.dumps(dict(drained=report.drained, timed_out=report.timed_out,
                              active_requests=report.active_requests, cleanup_complete=report.cleanup_complete),
                         sort_keys=True), flush=True)
        return 0 if report.drained else 2
    finally:
        if server is None:
            sso.close()
        else:
            server.stop(args.shutdown_timeout)


if __name__ == "__main__":
    raise SystemExit(main())
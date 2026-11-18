"""Trusted HTTP adapter for the lab App's SQLite session/object schema.

The original App stays the owner of login and business routes. This adapter
routes only the two registered object-read families through Guard with a
read-only session/ACL snapshot and mounts the fixture query predicate directly
at the private App ingress (the legacy forward proxy is intentionally bypassed).
"""
import hashlib
import hmac
import json
from http.server import ThreadingHTTPServer
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

from reverse_artex_guard.http_server import serve_application_read


class _Server(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True
    # The edge admits up to32 protected reads. The stdlib default backlog5
    # drops legitimate connection bursts well below that bound on large reads.
    request_queue_size = 64


class SQLiteSessionService:
    """Compose the existing handler with SDK reads without changing its file.

    ``guards`` maps the exact registered route prefixes (``/api`` and
    ``/legacy``) to product ``Guard`` instances. ``blocked_query`` is the
    fixture's narrow predicate from ``interaction-lab/http_filter.py``.
    """

    def __init__(self, app_module, resolver, guards, *, ingress_token,
                 blocked_query, sdk_responses_path, sdk_proofs_path, collect_timings=False,
                 persistent_audit_handles=False):
        if not isinstance(ingress_token, str) or len(ingress_token) < 32:
            raise ValueError("private ingress credential required")
        expected = {"/api", "/legacy"}
        if set(guards) != expected:
            raise ValueError("both exact object route guards are required")
        self.app = app_module
        self.resolver = resolver
        self.guards = dict(guards)
        self.ingress_token = ingress_token
        self.blocked_query = blocked_query
        self.sdk_responses_path = Path(sdk_responses_path)
        self.sdk_proofs_path = Path(sdk_proofs_path)
        self._write_lock = threading.Lock()
        self._lifecycle_lock = threading.Lock()
        self.persistent_audit_handles = bool(persistent_audit_handles)
        self._audit_handles = None
        self._audit_generation = 0
        self._audit_closing = True
        self._audit_failed = False
        self.collect_timings = collect_timings
        self._timing_lock = threading.Lock()
        self._timing_bounds_ns = tuple(int(value * 1_000_000) for value in
            (.1, .5, 1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2000, 5000))
        self._timings = {name: {"count": 0, "total_ns": 0, "max_ns": 0,
            "buckets": [0] * (len(self._timing_bounds_ns) + 1)}
            for name in ("guard", "resolver", "record", "record_lock_wait", "record_critical_section")}

        self.server = None
        self.thread = None

    def _record_timing(self, name, elapsed_ns):
        if not self.collect_timings:
            return
        with self._timing_lock:
            metric = self._timings[name]
            metric["count"] += 1
            metric["total_ns"] += elapsed_ns
            metric["max_ns"] = max(metric["max_ns"], elapsed_ns)
            bucket = next((index for index, bound in enumerate(self._timing_bounds_ns)
                           if elapsed_ns <= bound), len(self._timing_bounds_ns))
            metric["buckets"][bucket] += 1

    def timing_snapshot(self):
        # Fixed diagnostic counters contain no identity, credential, body,
        # authorization claim, or signed evidence and do not change decisions.
        with self._timing_lock:
            stages = {}
            for name, metric in self._timings.items():
                cumulative, values = 0, []
                for count in metric["buckets"]:
                    cumulative += count
                    values.append(cumulative)
                stages[name] = {"count": metric["count"], "total_ns": metric["total_ns"],
                    "max_ms": metric["max_ns"] / 1_000_000,
                    "cumulative_counts": values}
            return {"enabled": bool(self.collect_timings), "diagnostic_only": True,
                "upper_bounds_ms": [value / 1_000_000 for value in self._timing_bounds_ns],
                "stages": stages}

    def _record(self, prefix, handler, representation, *, audit_generation=None):
        proof = representation.headers.get("X-RA-Release-Proof", "")
        proof_sha = hashlib.sha256(proof.encode("ascii", "strict")).hexdigest() if proof else ""
        request_id = handler.headers.get("X-RA-Request-ID", "")
        method = handler.command
        route_id = "modern" if prefix == "/api" else "legacy"
        decision = "unknown"
        try:
            envelope = json.loads(proof)
            encoded = envelope["payload"]
            import base64
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            payload = json.loads(raw)
            if payload.get("request_id") == request_id and payload.get("route_id") == route_id:
                decision = payload.get("decision", "unknown")
        except (ValueError, TypeError, KeyError, UnicodeError):
            pass
        row = {
            "schema": "sdk-handler-response/1",
            "request_id": request_id,
            "route_id": route_id,
            "method": method,
            "decision": decision,
            "status": representation.status,
            "body_length": len(representation.body),
            "body_sha256": hashlib.sha256(representation.body).hexdigest(),
            "release_proof_sha256": proof_sha,
        }
        raw_row = (json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n").encode()
        def encode_proof():
            if proof:
                signed = {
                    "schema": "sdk-signed-release/1",
                    "request_id": request_id,
                    "route_id": route_id,
                    "method": method,
                    "status": representation.status,
                    "proof_sha256": proof_sha,
                    "proof": proof,
                }
                return (json.dumps(signed, sort_keys=True,
                                   separators=(",", ":")) + "\n").encode()
            return None

        # The opt-in writer moves proof encoding out of its shared critical
        # section. The default keeps its original per-request file lifecycle.
        proof_row = encode_proof() if self.persistent_audit_handles else None
        queued_ns = time.perf_counter_ns() if self.collect_timings else 0
        critical_ns = None
        try:
            with self._write_lock:
                acquired_ns = time.perf_counter_ns() if self.collect_timings else 0
                try:
                    if self.collect_timings:
                        self._record_timing("record_lock_wait", acquired_ns - queued_ns)
                    if self.persistent_audit_handles:
                        if (self._audit_closing or self._audit_failed or self._audit_handles is None
                                or audit_generation != self._audit_generation):
                            raise RuntimeError("SDK audit unavailable")
                        try:
                            self._append_audit_row(self._audit_handles[0], raw_row)
                            if proof_row is not None:
                                self._append_audit_row(self._audit_handles[1], proof_row)
                        except Exception:
                            # Preserve partial evidence. Never retry or reopen
                            # after an uncertain append, including across restart.
                            self._audit_failed = True
                            raise RuntimeError("SDK audit unavailable") from None
                    else:
                        self.sdk_responses_path.parent.mkdir(parents=True, exist_ok=True)
                        with self.sdk_responses_path.open("ab") as output:
                            output.write(raw_row)
                            output.flush()
                        proof_row = encode_proof()
                        if proof_row is not None:
                            self.sdk_proofs_path.parent.mkdir(parents=True, exist_ok=True)
                            with self.sdk_proofs_path.open("ab") as output:
                                output.write(proof_row)
                                output.flush()
                finally:
                    if self.collect_timings:
                        critical_ns = time.perf_counter_ns() - acquired_ns
        finally:
            if critical_ns is not None:
                self._record_timing("record_critical_section", critical_ns)

    @staticmethod
    def _append_audit_row(output, row):
        if output.write(row) != len(row):
            raise OSError("short SDK audit write")
        # Preserve the existing flush-only SDK logging contract. The Go edge's
        # independent durable approval remains required before client release.
        output.flush()

    def _close_audit_handles_locked(self):
        handles, self._audit_handles = self._audit_handles, None
        failed = False
        for output in handles or ():
            try:
                output.close()
            except Exception:
                self._audit_failed = failed = True
        return failed

    def handler_class(self, *, audit_generation=None):
        service = self
        generation = self._audit_generation if audit_generation is None else audit_generation

        class IntegratedApp(service.app.App):
            def do_HEAD(self):
                # The edge's exact coverage gate admits HEAD only for protected
                # object reads; the Guard then guarantees a bodyless response.
                return self.handle_request()

            def handle_scoped_request(self):
                trusted = hmac.compare_digest(
                    self.headers.get("X-Lab-Ingress", ""), service.ingress_token)
                if trusted and service.blocked_query(self.path):
                    body = b'{"error":"lab query rule"}'
                    self.send_response(403)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("X-RA-WAF-Blocked", "1")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    if self.command != "HEAD":
                        self.wfile.write(body)
                    return

                path = urlsplit(self.path).path
                prefix = next((candidate for candidate in ("/api", "/legacy")
                               if path.startswith(candidate + "/objects/")), None)
                if prefix is not None:
                    guard = service.guards[prefix]

                    class TracedGuard:
                        def read_application(_, method, target, headers, resolver):
                            if not service.collect_timings:
                                result = guard.read_application(method, target, headers, resolver)
                                service._record(prefix, self, result, audit_generation=generation)
                                return result
                            def timed_resolver(*args):
                                started = time.perf_counter_ns()
                                try:
                                    return resolver(*args)
                                finally:
                                    service._record_timing("resolver", time.perf_counter_ns() - started)
                            started = time.perf_counter_ns()
                            try:
                                result = guard.read_application(method, target, headers, timed_resolver)
                            finally:
                                service._record_timing("guard", time.perf_counter_ns() - started)
                            started = time.perf_counter_ns()
                            try:
                                service._record(prefix, self, result, audit_generation=generation)
                            finally:
                                service._record_timing("record", time.perf_counter_ns() - started)
                            return result

                    return serve_application_read(self, TracedGuard(), service.resolver)
                return super().handle_scoped_request()

        return IntegratedApp

    def start(self, database, *, host="127.0.0.1", port=0):
        with self._lifecycle_lock:
            if self.server is not None:
                raise RuntimeError("service already started")
            server = None
            try:
                if self.persistent_audit_handles:
                    with self._write_lock:
                        if self._audit_failed:
                            raise RuntimeError("SDK audit unavailable")
                        self._audit_generation += 1
                        self._audit_handles = []
                        for path in (self.sdk_responses_path, self.sdk_proofs_path):
                            path.parent.mkdir(parents=True, exist_ok=True)
                            self._audit_handles.append(path.open("ab"))
                        self._audit_closing = False
                server = _Server((host, port), self.handler_class(audit_generation=self._audit_generation))
                server.db = str(Path(database).resolve())
                server.fixed = False
                self.server = server
                self.thread = threading.Thread(target=server.serve_forever,
                                               kwargs={"poll_interval": .05}, daemon=True)
                self.thread.start()
                return "http://%s:%d" % server.server_address
            except BaseException:
                self.server = self.thread = None
                if self.persistent_audit_handles:
                    with self._write_lock:
                        self._audit_closing = True
                        self._close_audit_handles_locked()
                if server is not None:
                    server.server_close()
                raise

    def stop(self):
        with self._lifecycle_lock:
            server, thread = self.server, self.thread
            self.server = self.thread = None
            failed = False
            if self.persistent_audit_handles:
                with self._write_lock:
                    self._audit_closing = True
                    failed = self._close_audit_handles_locked()
            if server is not None:
                for cleanup in (server.shutdown, server.server_close):
                    try:
                        cleanup()
                    except Exception:
                        failed = True
            if thread is not None:
                try:
                    thread.join(timeout=3)
                    failed = thread.is_alive() or failed
                except Exception:
                    failed = True
            if failed:
                raise RuntimeError("owned SDK service shutdown failed")

from concurrent.futures import ThreadPoolExecutor
from email.message import Message
from http.server import BaseHTTPRequestHandler
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from reverse_artex_guard import ApplicationSnapshot
from reverse_artex_guard.guard import AuthorizedRepresentation
import test_application as fixture

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "examples"))
import sqlite_session_service as module


class App(BaseHTTPRequestHandler):
    def handle_request(self):
        return self.handle_scoped_request()

    def log_message(self, *_):
        pass


class FaultHandle:
    def __init__(self, output, fault):
        self.output, self.fault = output, fault

    def write(self, raw):
        if self.fault == "write":
            raise OSError("injected write error")
        if self.fault == "short":
            return self.output.write(raw[:-1])
        return self.output.write(raw)

    def flush(self):
        if self.fault == "flush":
            raise OSError("injected flush error")
        return self.output.flush()

    def close(self):
        self.output.close()
        if self.fault == "close":
            raise OSError("injected close error")


class SQLiteSessionServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ra-sdk-audit-")
        self.addCleanup(self.temp.cleanup)
        self.fx = fixture.ApplicationTests()
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.services = []

    def service(self, persistent=True, **kwargs):
        root = Path(self.temp.name) / str(len(self.services))
        s = module.SQLiteSessionService(SimpleNamespace(App=App),
            lambda *_: ApplicationSnapshot(True, self.fx.snapshot),
            {"/api": self.fx.guard, "/legacy": self.fx.guard},
            ingress_token="g" * 32, blocked_query=lambda _: False,
            sdk_responses_path=root / "responses.jsonl", sdk_proofs_path=root / "proofs.jsonl",
            persistent_audit_handles=persistent, **kwargs)
        self.services.append(s)
        self.addCleanup(s.stop)
        return s

    def start(self, service):
        return service.start(Path(self.temp.name) / "app.db")

    def representation(self, request_id="request"):
        headers = dict(self.fx.headers, **{"X-RA-Request-ID": request_id})
        rep = self.fx.guard.read_application("GET", "/legacy/objects/one", headers,
            lambda *_: ApplicationSnapshot(True, self.fx.snapshot))
        return SimpleNamespace(command="GET", headers=headers), rep

    def record(self, s, request_id="request"):
        handler, rep = self.representation(request_id)
        s._record("/legacy", handler, rep, audit_generation=s._audit_generation)

    def handler(self, cls):
        handler = cls.__new__(cls)
        handler.headers = Message()
        for key, value in self.fx.headers.items():
            handler.headers[key] = value
        handler.command, handler.path = "GET", "/legacy/objects/one"
        handler.wfile = io.BytesIO()
        handler.sent = []
        handler.send_response = lambda status: handler.sent.append(("status", status))
        handler.send_header = lambda *args: handler.sent.append(args)
        handler.end_headers = lambda: handler.sent.append(("end",))
        return handler

    def test_both_modes_produce_identical_flushed_rows_and_metrics(self):
        handler, rep = self.representation()
        outputs = []
        for persistent in (False, True):
            s = self.service(persistent, collect_timings=True)
            self.start(s)
            if not persistent:
                self.assertFalse(s.sdk_responses_path.exists())
            s._record("/legacy", handler, rep, audit_generation=s._audit_generation)
            s._record("/legacy", handler, AuthorizedRepresentation(503, b"unavailable", {}),
                      audit_generation=s._audit_generation)
            # Read before stop: every record must already be flushed.
            outputs.append((s.sdk_responses_path.read_bytes(), s.sdk_proofs_path.read_bytes()))
            stages = s.timing_snapshot()["stages"]
            self.assertEqual(stages["record_critical_section"]["count"], 2)
            self.assertEqual(stages["record_lock_wait"]["count"], 2)
        self.assertEqual(outputs[0], outputs[1])

    def test_concurrent_records_keep_complete_matching_order_in_both_files(self):
        s = self.service()
        self.start(s)
        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(lambda i: self.record(s, "request-" + str(i)), range(40)))
        responses = [json.loads(line) for line in s.sdk_responses_path.read_text().splitlines()]
        proofs = [json.loads(line) for line in s.sdk_proofs_path.read_text().splitlines()]
        self.assertEqual([r["request_id"] for r in responses], [r["request_id"] for r in proofs])
        self.assertEqual(len({r["request_id"] for r in responses}), 40)
        for response, proof in zip(responses, proofs):
            self.assertEqual(response["release_proof_sha256"], proof["proof_sha256"])

    def test_all_append_faults_fence_before_headers_and_remain_sticky(self):
        for index in (0, 1):
            for fault in ("write", "short", "flush"):
                with self.subTest(index=index, fault=fault):
                    s = self.service()
                    self.start(s)
                    wrapper = FaultHandle(s._audit_handles[index], fault)
                    s._audit_handles[index] = wrapper
                    handler = self.handler(s.handler_class())
                    with self.assertRaisesRegex(RuntimeError, "SDK audit unavailable"):
                        handler.handle_scoped_request()
                    self.assertEqual(handler.sent, [])
                    self.assertEqual(handler.wfile.getvalue(), b"")
                    self.assertTrue(s._audit_failed)
                    wrapper.fault = ""
                    with self.assertRaises(RuntimeError):
                        self.record(s, "later")
                    s.stop()
                    with self.assertRaises(RuntimeError):
                        self.start(s)
                    self.assertNotIn(b'"later"', s.sdk_responses_path.read_bytes())
                    if index == 1:
                        # The first append is retained as partial evidence.
                        rows = s.sdk_responses_path.read_text().splitlines()
                        self.assertEqual(len(rows), 1)
                        self.assertEqual(json.loads(rows[0])["request_id"], "request")

    def test_old_handler_generation_stays_fenced_after_restart(self):
        s = self.service()
        self.start(s)
        old = self.handler(s.handler_class())
        s.stop()
        self.start(s)
        with self.assertRaises(RuntimeError):
            old.handle_scoped_request()
        self.assertEqual(old.sent, [])
        self.assertFalse(s._audit_failed)
        current = self.handler(s.handler_class())
        current.handle_scoped_request()
        self.assertIn(("status", 200), current.sent)
        self.assertEqual(len(s.sdk_responses_path.read_text().splitlines()), 1)

    def test_stop_waits_for_active_recorder_then_rejects_late_records(self):
        s = self.service()
        self.start(s)
        entered, release, stopped = threading.Event(), threading.Event(), threading.Event()
        self.addCleanup(release.set)
        first, second = s._audit_handles

        class BlockingHandle(FaultHandle):
            def write(self, raw):
                entered.set()
                if not release.wait(2):
                    raise OSError("test writer release deadline")
                return super().write(raw)

        s._audit_handles[0] = BlockingHandle(first, "")
        with ThreadPoolExecutor(max_workers=2) as pool:
            writing = pool.submit(self.record, s)
            self.assertTrue(entered.wait(1))
            def stop():
                try: s.stop()
                finally: stopped.set()
            stopping = pool.submit(stop)
            self.assertFalse(stopped.wait(.03))
            self.assertFalse(first.closed)
            release.set()
            writing.result(timeout=2)
            stopping.result(timeout=2)
        self.assertTrue(first.closed and second.closed)
        with self.assertRaises(RuntimeError):
            self.record(s, "late")
        self.assertEqual(len(s.sdk_responses_path.read_text().splitlines()), 1)

    def test_second_open_failure_closes_first_and_allows_clean_retry(self):
        s = self.service()
        opened = []
        real_open = Path.open
        def opening(path, *args, **kwargs):
            if path == s.sdk_proofs_path:
                raise OSError("injected second open failure")
            output = real_open(path, *args, **kwargs)
            opened.append(output)
            return output
        with patch.object(Path, "open", opening):
            with self.assertRaises(OSError): self.start(s)
        self.assertTrue(opened[0].closed)
        self.assertIsNone(s._audit_handles)
        self.assertIsNone(s.server)
        self.assertTrue(s.sdk_responses_path.exists())
        self.start(s)
        self.record(s)

    def test_bind_and_thread_start_failures_close_both_handles(self):
        for stage in ("bind", "thread"):
            with self.subTest(stage=stage):
                s = self.service()
                opened = []
                real_open = Path.open
                def opening(path, *args, **kwargs):
                    output = real_open(path, *args, **kwargs)
                    opened.append(output)
                    return output
                target = "_Server" if stage == "bind" else "threading.Thread.start"
                with patch.object(Path, "open", opening):
                    with patch("sqlite_session_service." + target, side_effect=OSError("startup failed")):
                        with self.assertRaises(OSError): self.start(s)
                self.assertEqual(len(opened), 2)
                self.assertTrue(all(output.closed for output in opened))
                self.assertIsNone(s.server)
                self.assertIsNone(s._audit_handles)
                self.start(s)

    def test_close_faults_still_close_both_files_and_stop_listener(self):
        s = self.service()
        self.start(s)
        handles, server, thread = list(s._audit_handles), s.server, s.thread
        s._audit_handles = [FaultHandle(output, "close") for output in handles]
        with self.assertRaisesRegex(RuntimeError, "shutdown failed"):
            s.stop()
        self.assertTrue(all(output.closed for output in handles))
        self.assertFalse(thread.is_alive())
        self.assertEqual(server.fileno(), -1)
        self.assertTrue(s._audit_failed)
        s.stop()  # Already closed resources are not retried.
        with self.assertRaises(RuntimeError): self.start(s)

    def test_concurrent_start_has_one_owner_and_restarts_close_all_handles(self):
        s = self.service()
        def start():
            try:
                return self.start(s)
            except RuntimeError:
                return None
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: start(), range(2)))
        self.assertEqual(sum(value is not None for value in results), 1)
        for _ in range(3):
            handles, server, thread = list(s._audit_handles), s.server, s.thread
            s.stop()
            self.assertTrue(all(output.closed for output in handles))
            self.assertEqual(server.fileno(), -1)
            self.assertFalse(thread.is_alive())
            self.start(s)


if __name__ == "__main__":
    unittest.main()

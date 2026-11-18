"""Private loopback BFF readiness, request admission and graceful draining.

Health routes contain booleans only. No HTTP endpoint starts/stops a worker.
A timed-out drain is reported as incomplete; Python threads/SQL are not killed.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import ThreadingHTTPServer
import math
import signal
import socket
import threading
import time

from .browser_sso import BrowserSSO, Response, encoded, origin
from ._supervisor_input import SupervisorInput


@dataclass(frozen=True)
class ShutdownReport:
    drained: bool
    timed_out: bool
    active_requests: int
    cleanup_complete: bool


def _seconds(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not .05 <= value <= 60:
        raise ValueError("bounded shutdown timeout in 0.05..60 seconds required")
    return float(value)


class BrowserSSOServer(ThreadingHTTPServer):
    """Opt-in private server; active application requests include response writes.

    Readiness probes are not application work. On timeout, sockets and this
    controller close, but callers must treat the report as incomplete and retire
    the process. Already-started SQL is not cancelled or reported as rolled back.
    """
    daemon_threads = True
    block_on_close = False

    def __init__(self, address, handler, *, sso, edge_origin, allow_read,
                 readiness_check, max_connections=64, request_timeout=5):
        if type(address) is not tuple or len(address) != 2 or address[0] != '127.0.0.1' or type(address[1]) is not int or not 0 <= address[1] <= 65535:
            raise ValueError("private literal loopback listener required")
        if not isinstance(sso, BrowserSSO) or not callable(allow_read) or not callable(readiness_check):
            raise ValueError("browser controller and explicit readiness/read callbacks required")
        if type(max_connections) is not int or not 1 <= max_connections <= 1024:
            raise ValueError("max connections must be in 1..1024")
        self.request_timeout = _seconds(request_timeout)
        self.sso, self.edge_origin, self.allow_read = sso, origin(edge_origin), allow_read
        self.readiness_check, self.max_connections = readiness_check, max_connections
        self._condition = threading.Condition()
        self._probe_lock, self._stop_lock = threading.Lock(), threading.Lock()
        self._accepting, self._transport_closed = True, False
        self._active, self._connections, self._serve_id = 0, set(), None
        self.started, self._report = threading.Event(), None
        super().__init__(address, handler)

    @property
    def active_requests(self):
        with self._condition:
            return self._active

    def serve_forever(self, poll_interval=.05):
        with self._condition:
            if self._transport_closed or self._serve_id is not None:
                raise RuntimeError("browser listener already serving or closed")
            self._serve_id = threading.get_ident()
            self.started.set()
        try:
            super().serve_forever(poll_interval=poll_interval)
        finally:
            with self._condition:
                self._serve_id = None
                self._condition.notify_all()

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(self.request_timeout)
        return connection, address

    def process_request(self, request, client_address):
        with self._condition:
            accepted = not self._transport_closed and len(self._connections) < self.max_connections
            if accepted:
                self._connections.add(request)
        if not accepted:
            try:
                deadline = time.monotonic() + .2
                request.settimeout(.2)
                body = encoded({'error': 'authentication_unavailable'})
                request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nCache-Control: no-store\r\n'
                    b'Content-Type: application/json\r\nX-Content-Type-Options: nosniff\r\nContent-Length: '
                    + str(len(body)).encode('ascii') + b'\r\n\r\n' + body)
                # Half-close the response, then discard bounded transport bytes.
                # Closing with unread request data can abort the peer's 503 read
                # on Windows. Never parse/authenticate this rejected connection.
                request.shutdown(socket.SHUT_WR)
                remaining = 16384
                while remaining and time.monotonic() < deadline:
                    request.settimeout(max(.001, deadline - time.monotonic()))
                    data = request.recv(min(4096, remaining))
                    if not data:
                        break
                    remaining -= len(data)
            except OSError:
                pass
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            with self._condition:
                self._connections.discard(request)
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            with self._condition:
                self._connections.discard(request)
                self._condition.notify_all()

    def handle_error(self, *_):
        pass  # Never log callback URLs, request bodies or credentials.

    @contextmanager
    def request_scope(self, handler):
        probe = handler.command in ('GET', 'HEAD') and handler.path in ('/healthz', '/readyz')
        with self._condition:
            admitted = probe or (self._accepting and not self.sso.closed and not self._transport_closed)
            counted = admitted and not probe
            if counted:
                self._active += 1
        try:
            yield admitted
        finally:
            if counted:
                with self._condition:
                    self._active -= 1
                    self._condition.notify_all()

    def probe(self, path):
        if path == '/healthz':
            return Response(200, encoded({'live': True}), (('Content-Type', 'application/json'),))
        ready = False
        with self._condition:
            allowed = self._accepting and not self.sso.closed and not self._transport_closed and self._serve_id is not None
        if allowed and self._probe_lock.acquire(blocking=False):
            try:
                ready = self.readiness_check() is True
            except Exception:
                ready = False
            finally:
                self._probe_lock.release()
        with self._condition:
            ready = ready and self._accepting and not self.sso.closed and not self._transport_closed
        return Response(200 if ready else 503, encoded({'ready': bool(ready)}), (('Content-Type', 'application/json'),))

    def begin_drain(self):
        with self._condition:
            self._accepting = False
            self._condition.notify_all()

    def server_close(self):
        with self._condition:
            self._transport_closed, self._accepting = True, False
            connections = tuple(self._connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        super().server_close()

    def stop(self, timeout=10):
        timeout = _seconds(timeout)
        if threading.get_ident() == self._serve_id:
            raise RuntimeError("stop must run outside the serving thread")
        with self._stop_lock:
            if self._report is not None:
                return self._report
            deadline = time.monotonic() + timeout
            self.begin_drain()
            with self._condition:
                while self._active and time.monotonic() < deadline:
                    self._condition.wait(max(0, deadline - time.monotonic()))
                remaining = self._active
            self.sso.begin_close()  # Blocks late code-exchange installs after the deadline.
            cleanup = False
            if remaining == 0:
                try:
                    self.sso.close()
                    cleanup = True
                except Exception:
                    cleanup = False
            with self._condition:
                serving = self._serve_id is not None
            if serving:
                self.shutdown()
            self.server_close()
            timed_out = remaining != 0 or time.monotonic() > deadline
            self._report = ShutdownReport(remaining == 0 and cleanup and not timed_out, timed_out, remaining, cleanup)
            return self._report


def run_browser_server(server, *, drain_timeout=10, stop_event=None, shutdown_stdin=None,
                       on_started=None, install_signals=True):
    """Main-thread supervisor. Signals only set a flag; no locks/IO in handlers.

    Closing an explicitly supplied stdin stream is an optional local supervisor
    control. Windows TerminateProcess is a forced exit, not graceful shutdown.
    """
    _seconds(drain_timeout)
    if install_signals and threading.current_thread() is not threading.main_thread():
        raise ValueError("signal installation requires the main thread")
    input_source = SupervisorInput(shutdown_stdin) if shutdown_stdin is not None else None
    input_cancelled, input_thread = threading.Event(), None
    stop_event = threading.Event() if stop_event is None else stop_event
    ended, failures = threading.Event(), []
    signal_requested = False
    previous = {}
    def request_stop(*_):
        nonlocal signal_requested
        signal_requested = True
    def serve():
        try:
            server.serve_forever(poll_interval=.05)
        except BaseException:
            failures.append(True)
        finally:
            ended.set()
    def watch_stdin():
        try:
            while input_source.read(input_cancelled):
                pass
        except (OSError, ValueError):
            pass
        if not input_cancelled.is_set():
            stop_event.set()
    thread = threading.Thread(target=serve, name='browser-listener', daemon=True)
    report, thread_started = None, False
    try:
        if install_signals:
            for name in ('SIGINT', 'SIGTERM', 'SIGBREAK'):
                number = getattr(signal, name, None)
                if number is not None and number not in previous:
                    previous[number] = signal.signal(number, request_stop)
        thread.start()
        thread_started = True
        if not server.started.wait(2):
            raise RuntimeError("browser listener startup unavailable")
        if on_started is not None:
            on_started()
        if input_source is not None:
            input_thread = threading.Thread(target=watch_stdin, name='browser-supervisor-input', daemon=True)
            input_thread.start()
        while not signal_requested and not stop_event.is_set() and not ended.wait(.05):
            pass
    finally:
        input_cancelled.set()
        try:
            server.begin_drain()
            if input_thread is not None:
                input_thread.join(1)
            report = server.stop(drain_timeout)
            if thread_started:
                thread.join(.5)
        finally:
            for number, handler in previous.items():
                signal.signal(number, handler)
    if failures or thread.is_alive() or (input_thread is not None and input_thread.is_alive()):
        raise RuntimeError("browser listener stopped incompletely")
    return report

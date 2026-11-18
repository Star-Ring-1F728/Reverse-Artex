"""Opt-in Windows SCM host for the private browser worker.

No installation, credentials, registry changes or HTTP control endpoint.
The control callback reports STOP_PENDING and sets an event; all draining and
database cleanup stay on the worker thread. STOPPED is published once, last.
"""
from dataclasses import dataclass
import math
import os
import re
import threading

STOPPED, START_PENDING, STOP_PENDING, RUNNING = 1, 2, 3, 4
CONTROL_STOP, CONTROL_INTERROGATE, CONTROL_SHUTDOWN = 1, 4, 5
ACCEPT_STOP, ACCEPT_SHUTDOWN = 1, 4
ERROR_CALL_NOT_IMPLEMENTED = 120
ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061
ERROR_EXCEPTION_IN_SERVICE = 1064
ERROR_SERVICE_SPECIFIC_ERROR = 1066


def service_name(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9_.-]{0,63}', value) is None:
        raise ValueError('service name must be 1..64 ASCII identifier characters')
    return value


@dataclass(frozen=True)
class ServiceStatus:
    state: int
    controls_accepted: int = 0
    win32_exit_code: int = 0
    service_exit_code: int = 0
    checkpoint: int = 0
    wait_hint_ms: int = 0


class BrowserServiceHost:
    """Testable lifecycle; publishing STOPPED is the final application action."""
    def __init__(self, publish):
        if not callable(publish):
            raise ValueError('explicit SCM status publisher required')
        self.publish = publish
        self.stop_event = threading.Event()
        self._lock = threading.RLock()
        self.status = None
        self.report = None
        self.exit_code = 1
        self.stop_requested = self.failed = False
        self.drain_timeout = 10.0

    def _publish(self, status):
        self.status = status
        try:
            self.publish(status)
        except BaseException:
            self.failed = True
            raise

    def control(self, code):
        """SCM thread: bounded bookkeeping only, no socket/DB/drain operations."""
        try:
            with self._lock:
                state = None if self.status is None else self.status.state
                if code == CONTROL_INTERROGATE:
                    return 0  # SCM already has status; never republish STOPPED.
                if code not in (CONTROL_STOP, CONTROL_SHUTDOWN):
                    return ERROR_CALL_NOT_IMPLEMENTED
                if state not in (RUNNING, STOP_PENDING):
                    return ERROR_SERVICE_CANNOT_ACCEPT_CTRL
                if state == RUNNING:
                    self.stop_requested = True
                    self._publish(ServiceStatus(STOP_PENDING, checkpoint=1,
                        wait_hint_ms=min(62000, int(self.drain_timeout * 1000) + 2000)))
                self.stop_event.set()
                return 0
        except BaseException:
            self.abort()
            return ERROR_EXCEPTION_IN_SERVICE

    def abort(self):
        self.failed = True
        self.stop_requested = True
        self.stop_event.set()

    def run_server(self, server, *, drain_timeout=10, shutdown_stdin=None, on_started=None):
        if shutdown_stdin is not None:
            raise ValueError('SCM owns shutdown; stdin supervision is unavailable in service mode')
        if type(drain_timeout) not in (int, float) or not math.isfinite(drain_timeout) or not .05 <= drain_timeout <= 60:
            raise ValueError('bounded drain timeout required')
        self.drain_timeout = float(drain_timeout)
        from reverse_artex_guard.browser_server import run_browser_server
        def started():
            with self._lock:
                if self.status is None or self.status.state != START_PENDING:
                    raise RuntimeError('service startup state changed')
                self._publish(ServiceStatus(RUNNING, controls_accepted=ACCEPT_STOP | ACCEPT_SHUTDOWN))
            if on_started is not None:
                on_started()
        self.report = run_browser_server(server, drain_timeout=drain_timeout,
            stop_event=self.stop_event, on_started=started, install_signals=False)
        return self.report

    def execute(self, application):
        if not callable(application):
            raise ValueError('service application callback required')
        with self._lock:
            if self.status is not None:
                raise RuntimeError('service host is single use')
        returned = None
        try:
            with self._lock:
                self._publish(ServiceStatus(START_PENDING, checkpoint=1, wait_hint_ms=10000))
            returned = application(self)
        except BaseException:
            self.failed = True
        report = self.report
        complete = (report is not None and report.drained is True and report.cleanup_complete is True
                    and report.timed_out is False and report.active_requests == 0)
        if not self.failed and self.stop_requested and type(returned) is int and returned == 0 and complete:
            code = 0
        elif not self.failed and report is not None and not complete:
            code = 2
        else:
            code = 1
        with self._lock:
            self.exit_code = code
            # All application work/cleanup has returned. No heartbeat promises
            # progress while a blocked database/worker is doing no new work.
            try:
                self._publish(ServiceStatus(STOPPED,
                    win32_exit_code=0 if code == 0 else ERROR_SERVICE_SPECIFIC_ERROR,
                    service_exit_code=code))
            except BaseException:
                self.exit_code = 1
        return self.exit_code


class Win32ServiceAPI:
    """ctypes ABI boundary; only constructed on Windows, no pywin32 dependency."""
    def __init__(self):
        if os.name != 'nt':
            raise OSError('Windows SCM is unavailable on this platform')
        import ctypes
        from ctypes import wintypes
        self.ctypes = ctypes
        DWORD, LPWSTR, HANDLE = ctypes.c_uint32, wintypes.LPWSTR, wintypes.HANDLE
        self.Main = ctypes.WINFUNCTYPE(None, DWORD, ctypes.POINTER(LPWSTR))
        self.Control = ctypes.WINFUNCTYPE(DWORD, DWORD, DWORD, ctypes.c_void_p, ctypes.c_void_p)
        class NativeStatus(ctypes.Structure):
            _fields_ = [(name, DWORD) for name in (
                'service_type','state','controls','win32_exit','service_exit','checkpoint','wait_hint')]
        class Entry(ctypes.Structure):
            _fields_ = [('name', LPWSTR), ('main', ctypes.c_void_p)]
        self.NativeStatus, self.Entry = NativeStatus, Entry
        self.library = ctypes.WinDLL('advapi32', use_last_error=True)
        self.library.StartServiceCtrlDispatcherW.argtypes = (ctypes.POINTER(Entry),)
        self.library.StartServiceCtrlDispatcherW.restype = wintypes.BOOL
        self.library.RegisterServiceCtrlHandlerExW.argtypes = (LPWSTR, self.Control, ctypes.c_void_p)
        self.library.RegisterServiceCtrlHandlerExW.restype = HANDLE
        self.library.SetServiceStatus.argtypes = (HANDLE, ctypes.POINTER(NativeStatus))
        self.library.SetServiceStatus.restype = wintypes.BOOL
        self.handle = None
        self._callbacks = None

    def publish(self, status):
        if self.handle is None:
            raise RuntimeError('SCM status handle unavailable')
        native = self.NativeStatus(0x10, status.state, status.controls_accepted,
            status.win32_exit_code, status.service_exit_code, status.checkpoint, status.wait_hint_ms)
        if not self.library.SetServiceStatus(self.handle, self.ctypes.byref(native)):
            raise self.ctypes.WinError(self.ctypes.get_last_error())

    def dispatch(self, name, host, application):
        if threading.current_thread() is not threading.main_thread():
            raise ValueError('SCM dispatcher requires the process main thread')
        callback_errors = []
        @self.Control
        def control(code, _event_type, _event_data, _context):
            try:
                return host.control(code)
            except BaseException:
                callback_errors.append(True)
                host.abort()
                return ERROR_EXCEPTION_IN_SERVICE
        @self.Main
        def main(argc, argv):
            try:
                if argc < 1 or not argv or not argv[0] or argv[0].casefold() != name.casefold():
                    raise ValueError('SCM service name mismatch')
                self.handle = self.library.RegisterServiceCtrlHandlerExW(name, control, None)
                if not self.handle:
                    raise self.ctypes.WinError(self.ctypes.get_last_error())
                host.execute(application)
            except BaseException:
                callback_errors.append(True)
                host.abort()
        table = (self.Entry * 2)()
        table[0] = self.Entry(name, self.ctypes.cast(main, self.ctypes.c_void_p).value)
        # Keep callbacks/table alive through all ServiceMain/control callbacks.
        self._callbacks = (main, control, table)
        if not self.library.StartServiceCtrlDispatcherW(table):
            raise self.ctypes.WinError(self.ctypes.get_last_error())
        if callback_errors or host.status is None:
            raise RuntimeError('SCM callback failed')
        return host.exit_code


def run_windows_service(name, application, *, backend=None):
    service_name(name)
    backend = Win32ServiceAPI() if backend is None else backend
    host = BrowserServiceHost(backend.publish)
    return backend.dispatch(name, host, application)

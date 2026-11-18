"""Proof wall clock matched to the co-located Go edge on Windows.

Python 3.13+ time.time uses the precise Windows wall clock. The current Go
Windows runtime reads the periodically updated system time, so mixing the two
can put a freshly signed proof ahead of the edge's 5ms skew bound. Use the
same system-time source for proof timestamps only; token/session expiry still
uses the application's precise clock. No freshness tolerance is widened.
"""
import os
import time

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _system_time = _kernel.GetSystemTimeAsFileTime
    _system_time.argtypes = [ctypes.POINTER(wintypes.FILETIME)]
    _system_time.restype = None

    def proof_time():
        value = wintypes.FILETIME()
        _system_time(ctypes.byref(value))
        ticks = (value.dwHighDateTime << 32) | value.dwLowDateTime
        return (ticks - 116444736000000000) / 10000000
else:
    proof_time = time.time

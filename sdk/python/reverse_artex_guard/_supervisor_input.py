"""Cancellable, exclusively owned EOF-supervisor input.

Never hold a BufferedReader lock while waiting for a pipe writer. The caller
keeps stream ownership; descriptor input must not be read by another thread.
"""
import io
import os
import stat


class SupervisorInput:
    def __init__(self, stream):
        self.stream, self.fd, self.peek = stream, None, None
        if isinstance(stream, (io.BytesIO, io.StringIO)):
            return
        try:
            self.fd = stream.fileno()
            mode = os.fstat(self.fd).st_mode
        except (AttributeError, OSError, ValueError):
            raise ValueError("supervisor input must be a pipe, regular file or in-memory stream") from None
        if stat.S_ISREG(mode):
            return
        if not stat.S_ISFIFO(mode):
            raise ValueError("supervisor input must be a pipe, regular file or in-memory stream")
        if os.name == 'nt':
            import ctypes
            from ctypes import wintypes
            import msvcrt
            self.ctypes = ctypes
            self.handle = msvcrt.get_osfhandle(self.fd)
            kernel = ctypes.WinDLL('kernel32', use_last_error=True)
            self.peek = kernel.PeekNamedPipe
            self.peek.argtypes = (wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                                  ctypes.c_void_p, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p)
            self.peek.restype = wintypes.BOOL

    def read(self, cancelled, size=1024):
        """Return bytes/text, EOF, or None when cancelled, without closing input."""
        while not cancelled.is_set():
            if self.fd is None:
                return self.stream.read(size)
            if self.peek is not None:
                available = self.ctypes.c_ulong()
                if not self.peek(self.handle, None, 0, None, self.ctypes.byref(available), None):
                    error = self.ctypes.get_last_error()
                    if error in (109, 232):  # Broken/disconnected pipe is EOF.
                        return b''
                    raise self.ctypes.WinError(error)
                if available.value:
                    return os.read(self.fd, min(size, available.value))
                cancelled.wait(.05)
            elif stat.S_ISREG(os.fstat(self.fd).st_mode):
                return os.read(self.fd, size)
            else:
                import select
                if select.select([self.fd], [], [], .05)[0]:
                    return os.read(self.fd, size)
        return None

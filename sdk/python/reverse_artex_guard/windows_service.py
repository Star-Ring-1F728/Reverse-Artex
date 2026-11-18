"""SCM host API; the standalone module keeps service startup stdlib-only."""
from reverse_artex_windows_service import (
    BrowserServiceHost,
    ServiceStatus,
    Win32ServiceAPI,
    run_windows_service,
    service_name,
    STOPPED,
    START_PENDING,
    STOP_PENDING,
    RUNNING,
    CONTROL_STOP,
    CONTROL_INTERROGATE,
    CONTROL_SHUTDOWN,
    ACCEPT_STOP,
    ACCEPT_SHUTDOWN,
    ERROR_CALL_NOT_IMPLEMENTED,
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL,
    ERROR_EXCEPTION_IN_SERVICE,
    ERROR_SERVICE_SPECIFIC_ERROR
)

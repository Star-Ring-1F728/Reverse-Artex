#!/usr/bin/env python3
"""SCM-only reference BFF entry point; does not install or modify a service."""
import argparse
from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import stat
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from reverse_artex_windows_service import run_windows_service, service_name


def absolute_file(value):
    path = Path(value)
    if not path.is_absolute() or str(path).startswith(('\\\\', '//')):
        raise ValueError('local absolute file path required')
    return path


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError('duplicate service config key')
        value[key] = item
    return value


def load_gateway_args(config_path):
    path = absolute_file(config_path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
        raise ValueError('bounded regular service config required')
    with path.open('rb') as stream:
        raw = stream.read(65537)
    if len(raw) > 65536:
        raise ValueError('bounded regular service config required')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=_unique)
    if (type(value) is not dict or set(value) != {'schema', 'gateway_argv'}
            or value['schema'] != 'browser-sso-windows-service/1'):
        raise ValueError('explicit browser service schema required')
    args = value['gateway_argv']
    if (type(args) is not list or not 1 <= len(args) <= 64 or
            any(type(arg) is not str or not 1 <= len(arg) <= 4096 or '\0' in arg for arg in args)):
        raise ValueError('bounded gateway argument list required')
    if any(arg in ('-h','--help') for arg in args):
        raise ValueError('listener gateway arguments required')
    import browser_sso_gateway as gateway
    try:
        with io.StringIO() as sink, redirect_stderr(sink), redirect_stdout(sink):
            parsed = gateway.build_parser().parse_args(args)
    except SystemExit:
        raise ValueError('invalid listener gateway arguments') from None
    if (parsed.initialize_browser_state or parsed.describe_browser_state or parsed.rotate_browser_state
            or parsed.migrate_browser_state or parsed.shutdown_on_stdin_eof):
        raise ValueError('SCM service accepts listener mode only; no admin or stdin lifecycle')
    for name in ('identity_config','database'):
        candidate = absolute_file(getattr(parsed, name))
        if not candidate.is_file():
            raise ValueError('existing local absolute identity/database file required')
    return tuple(args)


def gateway_application(config_path):
    # Read config, initialize DB/key context and load crypto only in ServiceMain.
    def application(host):
        args = load_gateway_args(config_path)
        import browser_sso_gateway as gateway
        with io.StringIO() as sink, redirect_stderr(sink):
            return gateway.main(args, runtime_runner=host.run_server, announce=lambda *a, **k: None)
    return application


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service-name', required=True)
    parser.add_argument('--config', required=True)
    parser.add_argument('--dependency-path', help='explicit matching-ABI site-packages directory for a real base interpreter')
    parser.add_argument('--check', action='store_true', help='validate bounded listener config without SCM or a listener')
    args = parser.parse_args(argv)
    try:
        name = service_name(args.service_name)
        config_path = absolute_file(args.config)
        if args.dependency_path:
            dependencies = Path(args.dependency_path)
            if not dependencies.is_absolute() or str(dependencies).startswith(('\\\\','//')) or not dependencies.is_dir():
                raise ValueError('local absolute dependency directory required')
            # Do not execute .pth startup hooks; never spawn a venv redirector.
            sys.path.insert(0, str(dependencies))
        if args.check:
            load_gateway_args(config_path)
            print(json.dumps(dict(valid=True, configuration_only=True, listener_only=True, requires_scm=True)), flush=True)
            return 0
        return run_windows_service(name, gateway_application(config_path))
    except (OSError, ValueError, TypeError, KeyError, RuntimeError):
        # No config values, credentials or traceback are emitted by a service.
        if args.check:
            print(json.dumps(dict(valid=False)), flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

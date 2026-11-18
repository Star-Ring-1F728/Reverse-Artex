#!/usr/bin/env python3
"""Verify an unpacked public release and smoke-test its console in isolated state.

Uses Python's standard library only. Never connects to a model or production service.
The report contains counts and hashes, never console or sensor credentials.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import queue
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request


def sha256(path):
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for block in iter(lambda: source.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_MANIFEST_FILES = 10000
HASH_RE = re.compile(r'^[0-9a-f]{64}$')
VERSION_RE = re.compile(r'^[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?$')
WINDOWS_RESERVED_RE = re.compile(r'^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)', re.I)


def linked(attributes):
    return (stat.S_ISLNK(attributes.st_mode)
            or getattr(attributes, 'st_file_attributes', 0)
            & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 1024))


def payload_name(name):
    if not isinstance(name, str):
        raise ValueError('unsafe manifest path')
    path = PurePosixPath(name)
    if (not name or not path.parts or path.is_absolute() or str(path) != name or '..' in path.parts
            or any(ord(char) < 32 or ord(char) == 127 or char in '\\:<>|"*?' for char in name)
            or any(part.endswith((' ', '.')) or WINDOWS_RESERVED_RE.match(part) for part in path.parts)):
        raise ValueError('unsafe manifest path')
    return name


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate manifest JSON key')
        result[key] = value
    return result


def verify_manifest(directory):
    """Reject malformed, missing, altered, unlisted and linked payloads before execution."""
    directory = Path(directory)
    root_attributes = directory.lstat()
    if linked(root_attributes) or not stat.S_ISDIR(root_attributes.st_mode):
        raise ValueError('linked or invalid package directory')
    directory = directory.resolve()
    manifest_path = directory / 'manifest.json'
    attributes = manifest_path.lstat()
    if linked(attributes) or not stat.S_ISREG(attributes.st_mode):
        raise ValueError('linked or invalid release manifest')
    if attributes.st_size > MAX_MANIFEST_BYTES:
        raise ValueError('release manifest is too large')
    manifest = json.loads(manifest_path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)
    if (not isinstance(manifest, dict) or type(manifest.get('schema_version')) is not int
            or manifest['schema_version'] != 1):
        raise ValueError('unsupported release manifest')
    if (not isinstance(manifest.get('version'), str) or not VERSION_RE.fullmatch(manifest['version'])
            or manifest.get('target') not in ('windows-amd64', 'linux-amd64')):
        raise ValueError('invalid release manifest version or target')
    rows = manifest.get('files')
    if not isinstance(rows, list) or not 0 < len(rows) <= MAX_MANIFEST_FILES:
        raise ValueError('invalid manifest file inventory')
    expected, folded = {}, set()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {'path', 'size', 'sha256', 'mode'}:
            raise ValueError('invalid manifest file record')
        name = payload_name(row['path'])
        if name.casefold() == 'manifest.json' or name.casefold() in folded:
            raise ValueError('unsafe or duplicate manifest path')
        if (type(row['size']) is not int or row['size'] < 0
                or not isinstance(row['sha256'], str) or not HASH_RE.fullmatch(row['sha256'])
                or row['mode'] not in ('0644', '0755')):
            raise ValueError('invalid manifest file metadata')
        expected[name] = row
        folded.add(name.casefold())
    # Inspect entries before opening payloads: reject directory junctions as well as
    # file links, including on Python versions without Path.is_junction().
    actual, seen = set(), set()
    for parent, directories, files in os.walk(directory, followlinks=False):
        for entry in directories + files:
            path = Path(parent) / entry
            name = payload_name(path.relative_to(directory).as_posix())
            attributes = path.lstat()
            if linked(attributes):
                raise ValueError('linked payload entry')
            if not (stat.S_ISDIR(attributes.st_mode) or stat.S_ISREG(attributes.st_mode)):
                raise ValueError('non-regular payload entry')
            if name.casefold() in seen:
                raise ValueError('case-colliding payload entry')
            seen.add(name.casefold())
            if stat.S_ISREG(attributes.st_mode) and name != 'manifest.json':
                actual.add(name)
    missing = set(expected) - actual
    if missing:
        raise ValueError('missing payload file: ' + sorted(missing)[0])
    if actual != set(expected):
        raise ValueError('unlisted payload files')
    for name, row in expected.items():
        target = directory.joinpath(*PurePosixPath(name).parts)
        if target.stat().st_size != row['size'] or sha256(target) != row['sha256']:
            raise ValueError('payload integrity mismatch: ' + name)
    return manifest


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request(base, path, token=None, body=None, headers=None):
    outgoing = dict(headers or {})
    if token is not None:
        outgoing['Authorization'] = 'Bearer ' + token
    if body is not None:
        outgoing.setdefault('Content-Type', 'application/json')
    req = urllib.request.Request(base + path, data=body, headers=outgoing)
    # Keep credentials on the exact loopback endpoint selected by the caller.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(req, timeout=5) as response:
            raw = response.read(2 * 1024 * 1024)
            return response.status, raw
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(4096)


def stop_process(process):
    method = 'already-exited'
    if process.poll() is None:
        if os.name == 'nt':
            method = 'owned-process-termination'
            process.terminate()
        else:
            method = 'SIGTERM'
            process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            method = 'forced-kill'
            process.kill()
            process.wait(timeout=5)
    return method


def smoke(directory, state, report):
    binary = directory / ('reverse-artex.exe' if os.name == 'nt' else 'reverse-artex')
    launch = [str(binary), '-console'] if os.name == 'nt' else ['sh', str(directory / 'start.sh')]
    report['entrypoint'] = binary.name if os.name == 'nt' else 'start.sh'
    config = state / 'config.json'
    evidence = state / 'data'
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith('RA_')}
    environment['GOMAXPROCS'] = '2'
    previous_key = None
    initial_sensor = None

    def check(name, condition):
        report['checks'].append({'name': name, 'passed': bool(condition)})
        if not condition:
            raise RuntimeError('check failed: ' + name)

    for generation in range(2):
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        base = 'http://127.0.0.1:' + str(port)
        process = subprocess.Popen(
            [*launch, '-listen', '127.0.0.1:' + str(port),
             '-config', str(config), '-out', str(evidence)],
            cwd=state, env=environment, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace',
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
        lines = queue.Queue()

        def collect(stream):
            try:
                for line in stream:
                    match = re.search(r'/#token=([a-f0-9]{64})', line)
                    if match:
                        lines.put(match.group(1))
            finally:
                stream.close()

        reader = threading.Thread(target=collect, args=(process.stdout,), daemon=True)
        reader.start()
        try:
            deadline = time.monotonic() + 25
            key = None
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise RuntimeError('console exited before readiness')
                try:
                    key = lines.get(timeout=0.1)
                except queue.Empty:
                    continue
                while time.monotonic() < deadline:
                    try:
                        status, raw = request(base, '/console/api/status', key)
                        if status == 200:
                            break
                    except OSError:
                        time.sleep(0.05)
                break
            if key is None:
                raise RuntimeError('console readiness deadline exceeded')

            status, raw = request(base, '/console/api/status', key)
            check('ready-generation-' + str(generation + 1), status == 200)
            current = json.loads(raw)
            check('observe-default-' + str(generation + 1),
                  current.get('mode') == 'observe' and not current.get('policy_forwarding_configured'))
            saved = json.loads(config.read_text(encoding='utf-8'))
            sensor = saved['sensor_token']
            check('generated-private-config', len(sensor) >= 32)
            if generation:
                check('console-key-rotates', key != previous_key)
                check('sensor-token-persists', sensor == initial_sensor)
                check('old-console-key-rejected', request(base, '/console/api/status', previous_key)[0] == 401)
                check('event-persists-after-restore', current['evidence']['record_counts'].get('events', 0) == 1)
                check('sensor-token-is-not-console-key', request(base, '/console/api/status', sensor)[0] == 401)
                continue
            previous_key, initial_sensor = key, sensor
            check('anonymous-console-rejected', request(base, '/console/api/status')[0] == 401)
            check('foreign-host-rejected', request(base, '/console/api/status', key,
                  headers={'Host': 'untrusted.invalid:' + str(port)})[0] == 403)
            check('foreign-origin-rejected', request(base, '/console/api/sample', key, b'',
                  {'Origin': 'https://untrusted.invalid'})[0] == 403)
            status, html = request(base, '/')
            check('embedded-ui', status == 200 and b'Reverse Artex' in html)
            counts = current['evidence']['record_counts']
            check('new-state-is-empty', counts.get('events', 0) == 0)
            status, raw = request(base, '/console/api/sample', key, b'')
            sample = json.loads(raw)
            check('sample-detects-twelve-events', status == 200 and sample.get('events') == 12
                  and any(row.get('rule_id') == 'RA-002' for row in sample.get('alerts', [])))
            check('sample-is-isolated', sample.get('live_evidence_changed') is False
                  and sample.get('policy_actions') == 0)
            example = directory / 'docs/examples/http-sample.jsonl'
            check('downloadable-sample-included', example.is_file())
            status, raw = request(base, '/console/api/analyze', key, example.read_bytes(),
                                  {'Content-Type': 'application/x-ndjson'})
            parsed = json.loads(raw)
            check('file-upload-example', status == 200 and parsed.get('events') == 12
                  and parsed.get('policy_actions') == 0 and parsed.get('live_evidence_changed') is False)
            status, raw = request(base, '/console/api/status', key)
            check('analysis-keeps-live-ledger-empty', json.loads(raw)['evidence']['record_counts'] == counts)
            event = json.loads(example.read_text(encoding='utf-8').splitlines()[0])
            now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            event.update(event_id='public-release-smoke-event', request_id='public-release-smoke-request',
                         event_time=now, ingest_time=now)
            payload = json.dumps(event).encode()
            check('anonymous-sensor-rejected', request(base, '/v1/events', body=payload)[0] == 401)
            check('console-key-is-not-sensor-token', request(base, '/v1/events', key, payload)[0] == 401)
            check('sensor-event-accepted', request(base, '/v1/events', sensor, payload)[0] == 202)
            status, raw = request(base, '/console/api/status', key)
            check('live-event-recorded', json.loads(raw)['evidence']['record_counts'].get('events', 0) == 1)
        finally:
            method = stop_process(process)
            reader.join(timeout=2)
            report['processes'].append({'generation': generation + 1, 'exit_code': process.returncode,
                                        'stopped': process.poll() is not None,
                                        'stop_method': method})
            if os.name != 'nt':
                report['checks'].append({'name': 'graceful-sigterm-' + str(generation + 1),
                                         'passed': method == 'SIGTERM' and process.returncode == 0})
            check_socket = socket.socket()
            try:
                check_socket.settimeout(1)
                closed = check_socket.connect_ex(('127.0.0.1', port)) != 0
            finally:
                check_socket.close()
            report['checks'].append({'name': 'listener-closed-' + str(generation + 1), 'passed': closed})
            if not closed:
                raise RuntimeError('owned listener did not close')

        if generation == 0:
            restored = state / 'restored state'
            restored.mkdir(mode=0o700)
            config = Path(shutil.copy2(config, restored / 'config.json'))
            evidence = Path(shutil.copytree(evidence, restored / 'data'))
            recovery = subprocess.run([str(binary), '-recover-check', '-out', str(evidence)],
                                      cwd=state, env=environment, capture_output=True, timeout=25)
            check('backed-up-collector-passes-recovery-check',
                  recovery.returncode == 0 and
                  b'collector recovery verified; policy evidence pending: 0' in recovery.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path,
                        help='freshly extracted package root (before starting the application)')
    parser.add_argument('--out', required=True, type=Path, help='new isolated output directory, outside package')
    parser.add_argument('--static-only', action='store_true', help='verify hashes without executing the binary')
    args = parser.parse_args()
    directory, out = args.directory.resolve(), args.out.resolve()
    if out == directory or directory in out.parents:
        parser.error('--out must be outside the package directory')
    out.mkdir(mode=0o700, parents=True, exist_ok=False)
    report = {'schema': 'reverse-artex-public-release-smoke/1', 'passed': False, 'checks': [],
              'processes': [], 'real_model_calls': 0, 'production_approval': False,
              'native_platform': platform.system(), 'graceful_windows_shutdown_verified': False}
    try:
        manifest = verify_manifest(args.directory)
        report['target'] = manifest['target']
        report['version'] = manifest['version']
        report['manifest_sha256'] = sha256(directory / 'manifest.json')
        report['checks'].append({'name': 'all-package-file-hashes', 'passed': True})
        if not args.static_only:
            expected = 'windows-amd64' if os.name == 'nt' else 'linux-amd64' if sys.platform.startswith('linux') else None
            if manifest['target'] != expected or platform.machine().lower() not in ('amd64', 'x86_64'):
                raise ValueError('native platform mismatch; use --static-only for cross-built packages')
            smoke(directory, out, report)
        report['passed'] = all(row['passed'] for row in report['checks'])
    except Exception as error:
        # Error details from the application or HTTP responses may contain credentials.
        report['failure'] = type(error).__name__ + ': ' + str(error)
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'passed': report['passed'], 'checks': len(report['checks']),
                      'report': str(out / 'report.json'), 'failure': report.get('failure')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

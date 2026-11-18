"""Exercise the packaged console with a real browser and synthetic events."""

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import queue
import re
import socket
import subprocess
import sys
import threading
import time

from playwright.sync_api import expect, sync_playwright

from verify_public_release import request, sha256, stop_process, verify_manifest


@contextmanager
def console(installation, working_directory, port):
    address = f'127.0.0.1:{port}'
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('RA_')}
    if os.name == 'nt':
        launch = [str(installation / 'reverse-artex.exe'), '-console', '-config', 'config.json']
        cwd = installation
    else:
        launch = ['sh', str(installation / 'start.sh')]
        cwd = working_directory
    process = subprocess.Popen([*launch, '-listen', address], cwd=cwd, env=env, stdout=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0,
                               stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace')
    keys = queue.Queue()

    def read_key():
        with process.stdout as stream:
            for line in stream:
                match = re.search(r'/#token=([a-f0-9]{64})', line)
                if match:
                    keys.put(match.group(1))

    reader = threading.Thread(target=read_key, daemon=True)
    reader.start()
    try:
        key = keys.get(timeout=15)
        until = time.monotonic() + 2
        while time.monotonic() < until:
            if process.poll() is not None:
                raise RuntimeError('local console exited before readiness')
            try:
                with socket.create_connection(('127.0.0.1', port), timeout=0.2):
                    break
            except OSError:
                time.sleep(0.025)
        else:
            raise RuntimeError('local console listener unavailable')
        yield key
    finally:
        method = stop_process(process)
        reader.join(timeout=2)
        if os.name == 'nt' and method != 'owned-process-termination':
            raise RuntimeError('packaged Windows console did not remain available until cleanup')
        if os.name != 'nt' and (method != 'SIGTERM' or process.returncode != 0):
            raise RuntimeError('packaged Linux launcher did not exit cleanly')


def validate(installation, out, chromium, report):
    manifest = verify_manifest(installation)
    target = 'windows-amd64' if os.name == 'nt' else 'linux-amd64' if sys.platform.startswith('linux') else None
    if manifest['target'] != target:
        raise ValueError('expected a freshly extracted beta archive for this platform')
    report['target'] = target
    report['manifest_sha256'] = sha256(installation / 'manifest.json')
    sample = installation / 'docs/examples/http-sample.jsonl'
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    with sync_playwright() as playwright, playwright.chromium.launch(
            executable_path=chromium, headless=True, args=['--disable-background-networking']) as browser:
        report['chromium_version'] = browser.version
        context = browser.new_context(service_workers='block')
        context.route('**/*', lambda route: route.continue_() if route.request.url.startswith(base + '/') else route.abort())
        page = context.new_page()
        page.set_default_timeout(8000)
        page_errors = []
        page.on('pageerror', lambda _: page_errors.append(True))
        with console(installation, out, port) as first:
            report['phase'] = 'bare-console'
            page.goto(base + '/')
            expect(page.locator('#login')).to_be_visible()
            expect(page.locator('#application')).to_be_hidden()
            report['phase'] = 'access-link-in-existing-tab'
            page.goto(base + '/#token=' + first)
            expect(page.locator('#metric-mode')).to_have_text('OBSERVE · 관측')
            expect(page.locator('#metric-events')).to_have_text('0')
            if page.url != base + '/':
                raise RuntimeError('console did not clear the startup fragment')
            report['checks'].append('private-first-launch')

            report['phase'] = 'sample-and-upload'
            page.locator('#first-sample').click()
            expect(page.locator('#analysis-result .analysis-stats strong').first).to_have_text('12')
            expect(page.locator('#analysis-result .analysis-stats strong').last).to_have_text('0')
            with page.expect_response(lambda response: response.url == base + '/console/api/analyze'
                                      and response.request.method == 'POST') as upload:
                page.locator('#event-file').set_input_files(sample)
                page.locator('#analyze-form button').click()
            body = upload.value.json()
            if upload.value.status != 200 or body.get('events') != 12 or body.get('live_evidence_changed') is not False:
                raise RuntimeError('packaged upload example did not remain isolated')
            page.locator('nav [data-view="overview"]').click()
            expect(page.locator('#metric-events')).to_have_text('0')
            report['checks'].append('browser-sample-and-file-analysis-isolated')

            report['phase'] = 'sensor-to-events'
            config = installation / 'config.json'
            if (not config.is_file() or not (installation / 'data/collector').is_dir()
                    or (os.name != 'nt' and config.stat().st_mode & 0o077)):
                raise RuntimeError('first launch did not create the expected local private state')
            now = datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
            event = json.loads(sample.read_text(encoding='utf-8').splitlines()[0])
            event.update(event_id='beta-browser-event', request_id='beta-browser-request',
                         event_time=now, ingest_time=now)
            sensor = json.loads(config.read_text(encoding='utf-8'))['sensor_token']
            status, _ = request(base, '/v1/events', sensor, json.dumps(event).encode())
            if status != 202:
                raise RuntimeError('authorized fixture event was refused')
            page.locator('nav [data-view="events"]').click()
            expect(page.locator('#event-rows')).to_contain_text('beta-browser-event')
            report['checks'].append('authorized-event-visible')

        report['phase'] = 'restart-existing-browser'
        with console(installation, out, port) as second:
            if first == second:
                raise RuntimeError('console key did not rotate')
            page.reload()
            expect(page.locator('#login-error')).to_be_visible()
            expect(page.locator('#application')).to_be_hidden()
            page.goto(base + '/#token=' + second)
            expect(page.locator('#metric-events')).to_have_text('1')
            report['checks'].append('old-browser-key-rejected-and-evidence-reopened')
        context.close()
        if page_errors:
            raise RuntimeError('unexpected browser script error')
    report.update(passed=True, phase='completed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--installation', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    parser.add_argument('--chromium', default='/usr/bin/chromium')
    args = parser.parse_args()
    installation, out = args.installation.resolve(), args.out.resolve()
    if installation == out or installation in out.parents:
        parser.error('use a report directory outside the installation')
    out.mkdir(mode=0o700)
    report = {'passed': False, 'checks': [], 'scope': 'owned loopback and synthetic event'}
    try:
        validate(installation, out, args.chromium, report)
    except Exception as error:
        # Browser exceptions can include navigation URLs carrying local credentials.
        report['error_type'] = type(error).__name__
    (out / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

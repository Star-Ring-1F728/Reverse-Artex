"""Owned subprocess transition fixture. Keys arrive over stdin, never files.

The optional pre-commit barrier is test-only, outside the production API. It
holds the real SQLite transaction after transition work and before COMMIT so
TerminateProcess can prove crash rollback. No service or public endpoint.
"""
import base64
from contextlib import contextmanager
import json
from pathlib import Path
import sys
import time
from unittest.mock import patch

from reverse_artex_guard.browser_state_migration import transition_browser_state
from reverse_artex_guard.sqlite_application import SQLiteApplicationStore


def main():
    config = json.loads(sys.stdin.readline())
    app = SQLiteApplicationStore(config['database'])
    original = SQLiteApplicationStore._write
    @contextmanager
    def barrier(self):
        with original(self) as db:
            yield db
            if config.get('entered'):
                Path(config['entered']).write_text('pre-commit', encoding='ascii')
                deadline = time.monotonic() + 10
                while not Path(config['release']).exists():
                    if time.monotonic() > deadline: raise TimeoutError('owned transition barrier deadline')
                    time.sleep(.02)
    with patch.object(SQLiteApplicationStore, '_write', barrier):
        result = transition_browser_state(app, tuple(base64.b64decode(k, validate=True) for k in config['source_keys']),
            identity_config=config['oidc'], public_origin=config['public_origin'], capacity=config.get('capacity', 1024),
            target_key=base64.b64decode(config['target_key'], validate=True),
            expected_epoch=config['expected_epoch'], operation_id=config['operation_id'],
            target_identity_config=config.get('target_oidc'), target_public_origin=config.get('target_public_origin'),
            target_capacity=config.get('target_capacity'), session_policy=config.get('session_policy', 'preserve'),
            mode=config.get('mode', 'rotate'), minimum_generation=config.get('minimum_generation', 0))
    print(json.dumps(result, sort_keys=True), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print('owned transition rejected', file=sys.stderr)
        raise SystemExit(1)

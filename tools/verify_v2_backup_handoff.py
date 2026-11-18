"""Check a stopped V2 backup against an independently trusted journal head."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import stat
import subprocess


SHA256 = re.compile(r'[0-9a-f]{64}\Z')


def regular(path, limit):
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ValueError('backup contains a link or oversized file')
    return info


def integrity(backup, generation):
    expected = {'v2.jsonl', 'v2.jsonl.owner', 'v2.jsonl.retained/CURRENT', 'v2.jsonl.retained/IDENTITY.json'}
    expected.update(f'v2.jsonl.retained/segment-{i:06d}.jsonl' for i in range(generation + 1))
    expected.update(f'v2.jsonl.retained/checkpoint-{i:06d}.json' for i in range(1, generation + 1))
    retained = backup / 'v2.jsonl.retained'
    if not stat.S_ISDIR(retained.lstat().st_mode):
        raise ValueError('backup uses an invalid retained directory')
    root_names = {p.name for p in backup.iterdir()}
    segments = {f'v2.jsonl.retained/{p.name}' for p in retained.iterdir()}
    if root_names != {'backup.json', 'v2.jsonl', 'v2.jsonl.owner', 'v2.jsonl.retained'} or segments != expected - {'v2.jsonl', 'v2.jsonl.owner'}:
        raise ValueError('backup file set differs from the sealed layout')
    files = []
    for name in sorted(expected):
        path = backup / name
        info = regular(path, 64 << 20)
        with path.open('rb') as stream:
            digest = hashlib.file_digest(stream, 'sha256').hexdigest()
        files.append({'path': name, 'bytes': info.st_size, 'sha256': digest})
    return files


def verify(backup, registry, verifier, expected_head):
    if not SHA256.fullmatch(expected_head):
        raise ValueError('expected journal head must be a SHA-256 value')
    if not stat.S_ISDIR(backup.lstat().st_mode):
        raise ValueError('backup root must be a real directory')
    receipt = backup / 'backup.json'
    regular(receipt, 1 << 20)
    manifest = json.loads(receipt.read_bytes())
    if manifest['schema'] != 'retained-journal-backup/1' or manifest['journal'] != 'v2.jsonl':
        raise ValueError('unsupported backup manifest')
    expected = manifest['verification']
    generation = expected['retention']['generation']
    if expected['journal_head_sha256'] != expected_head or type(generation) is not int or not 1 <= generation <= 1024:
        raise ValueError('backup differs from the pinned source head or generation')
    files = integrity(backup, generation)
    if sorted(manifest['files'], key=lambda entry: entry['path']) != files:
        raise ValueError('backup bytes differ from its inventory')
    result = subprocess.run([str(verifier.resolve()), '-state', str((backup / 'v2.jsonl').absolute()),
                             '-protection-registry', str(registry.resolve())], capture_output=True, timeout=600)
    if result.returncode:
        raise ValueError('journal replay failed')
    actual = json.loads(result.stdout)['verification']
    if (actual['journal_head_sha256'] != expected_head or actual['sequence'] != expected['sequence']
            or actual['pending_unknown'] != 0 or not (actual['passed'] and actual['read_only'] and actual['audit_available'])):
        raise ValueError('journal replay does not confirm a clean handoff at the pinned head')
    if files != integrity(backup, generation):
        raise ValueError('backup changed during verification')
    return {'passed': True, 'journal_head_sha256': expected_head, 'sequence': actual['sequence'],
            'file_count': len(files), 'verified_observations': actual['total_observations']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('backup', 'registry', 'verifier'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--expected-head', required=True, help='source journal head from an independent operator record')
    args = parser.parse_args()
    try:
        result = verify(args.backup, args.registry, args.verifier, args.expected_head)
    except (OSError, TypeError, KeyError, ValueError, subprocess.TimeoutExpired) as error:
        print(json.dumps({'passed': False, 'error': str(error)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

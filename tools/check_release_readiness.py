#!/usr/bin/env python3
"""Check release checksums, version, source provenance, and current-tree freshness.

Run from a source checkout after packaging. This does not execute binaries,
qualify security effectiveness, or authenticate a downloaded checksum's source.
Use verify_public_release.py separately for extracted payload/runtime checks.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat

HASH = re.compile(r'^[0-9a-f]{64}$')
TARGETS = {'windows-amd64', 'linux-amd64'}


def digest(path):
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(block)
    return result.hexdigest()


def relative_name(name):
    if not isinstance(name, str) or not name or '\\' in name or ':' in name:
        raise ValueError('unsafe release input path')
    pure = PurePosixPath(name)
    if pure.is_absolute() or '..' in pure.parts or str(pure) != name:
        raise ValueError('unsafe release input path')
    for part in pure.parts:
        if any(ord(char) < 32 for char in part) or part.endswith((' ', '.')):
            raise ValueError('unsafe release input path')
    if not pure.parts:
        raise ValueError('unsafe release input path')
    return name


def safe_file(root, name):
    relative_name(name)
    path = root
    for part in PurePosixPath(name).parts:
        path = path / part
        attributes = path.lstat()
        if stat.S_ISLNK(attributes.st_mode) or getattr(attributes, 'st_file_attributes', 0) & 0x400:
            raise ValueError('linked release input')
    if not path.is_file():
        raise ValueError('release input is not a regular file')
    return path


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError('duplicate JSON field')
        result[name] = value
    return result


def read_json(root, name):
    path = safe_file(root, name)
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError('release metadata is too large')
    return json.loads(path.read_text(encoding='utf-8-sig'), object_pairs_hook=unique_object)


def current_input_names(source_root):
    # Use this checkout's explicit release selection, including newly added files.
    from package_release import build_inputs, public_inputs
    return set(build_inputs(source_root) + public_inputs(source_root))


def audit_release(source_root, release_dir):
    source_root, release_dir = Path(source_root).resolve(), Path(release_dir).resolve()
    version = safe_file(source_root, 'VERSION').read_text(encoding='utf-8-sig').strip()
    build = read_json(release_dir, 'build-manifest.json')
    source = read_json(release_dir, 'source-inputs.json')
    if not isinstance(build, dict) or not isinstance(source, dict):
        raise ValueError('release metadata must be JSON objects')
    if type(build.get('schema_version')) is not int or build['schema_version'] != 1 or build.get('version') != version:
        raise ValueError('release version does not match source VERSION')
    if build.get('source') != source:
        raise ValueError('build and source inventory identities disagree')
    records = source.get('inputs')
    if not isinstance(records, list) or not records:
        raise ValueError('source inventory is empty or invalid')
    fingerprint = hashlib.sha256(json.dumps(records, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
    if source.get('sha256') != fingerprint:
        raise ValueError('source inventory fingerprint mismatch')
    archives = build.get('archives')
    if not isinstance(archives, list) or not archives:
        raise ValueError('archive inventory is empty or invalid')
    expected_names = {'build-manifest.json', 'source-inputs.json'}
    targets = set()
    for row in archives:
        if (not isinstance(row, dict) or not isinstance(row.get('target'), str)
                or row['target'] not in TARGETS or row['target'] in targets):
            raise ValueError('invalid or duplicate archive target')
        targets.add(row['target'])
        extension = '.zip' if row['target'] == 'windows-amd64' else '.tar.gz'
        expected = 'reverse-artex-' + version + '-' + row['target'] + extension
        if row.get('path') != expected or not HASH.fullmatch(str(row.get('sha256', ''))):
            raise ValueError('invalid archive identity')
        path = safe_file(release_dir, expected)
        if (type(row.get('size')) is not int or path.stat().st_size != row['size']
                or digest(path) != row['sha256']):
            raise ValueError('archive does not match build manifest')
        expected_names.add(expected)
    checksum_path = safe_file(release_dir, 'SHA256SUMS')
    if checksum_path.stat().st_size > 65536:
        raise ValueError('checksum inventory is too large')
    checksums = {}
    for line in checksum_path.read_text(encoding='ascii').splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  ([^/\\]+)', line)
        if not match or match[2].casefold() in checksums:
            raise ValueError('invalid or duplicate checksum record')
        checksums[match[2].casefold()] = (match[2], match[1])
    if {name for name, _ in checksums.values()} != expected_names:
        raise ValueError('checksum inventory does not match release files')
    for name, expected in checksums.values():
        if digest(safe_file(release_dir, name)) != expected:
            raise ValueError('release checksum mismatch')
    drift, seen = [], set()
    selected = current_input_names(source_root)
    for row in records:
        if not isinstance(row, dict) or set(row) != {'path', 'size', 'sha256', 'mode'}:
            raise ValueError('invalid source input record')
        name = relative_name(row['path'])
        if (not isinstance(name, str) or name.casefold() in seen or type(row['size']) is not int
                or row['size'] < 0 or not HASH.fullmatch(str(row['sha256'])) or row['mode'] not in ('0644', '0755')):
            raise ValueError('invalid or duplicate source input')
        seen.add(name.casefold())
        if name not in selected:
            drift.append({'path': name, 'reason': 'no-longer-selected'})
            continue
        try:
            path = safe_file(source_root, name)
        except FileNotFoundError:
            drift.append({'path': name, 'reason': 'missing'})
            continue
        if path.stat().st_size != row['size'] or digest(path) != row['sha256']:
            drift.append({'path': name, 'reason': 'changed'})
    for name in sorted(selected - {row['path'] for row in records}):
        relative_name(name)
        drift.append({'path': name, 'reason': 'new-release-input'})
    return {'schema': 'reverse-artex-release-freshness/1', 'passed': not drift,
            'version': version, 'targets': sorted(targets), 'source_inputs_checked': len(records),
            'source_sha256': source['sha256'], 'current_tree_drift': drift,
            'production_approval': False, 'payload_runtime_checked': False,
            'checksum_source_authenticated': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--release-dir', required=True, type=Path)
    parser.add_argument('--source-root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--out', type=Path, help='optional new JSON report; existing files are never overwritten')
    args = parser.parse_args()
    if args.out and args.out.exists():
        parser.error('--out already exists; choose a new report path')
    try:
        report = audit_release(args.source_root, args.release_dir)
    except (OSError, ValueError, TypeError, KeyError) as error:
        report = {'schema': 'reverse-artex-release-freshness/1', 'passed': False,
                  'failure': type(error).__name__ + ': ' + str(error), 'production_approval': False}
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, indent=2)
            stream.write('\n')
    print(json.dumps(report, indent=2))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())

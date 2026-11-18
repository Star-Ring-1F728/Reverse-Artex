"""Host reader for committed responses in the defensive qualification queue."""
import json
from pathlib import Path

MAX_RECORD_BYTES = 128 << 10


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate transport record key')
        result[key] = value
    return result


def reject_constant(_):
    raise ValueError('nonfinite transport record value')


def read_committed_record(path: Path):
    """Read a bounded record once both the data file and its marker are visible."""
    marker = path.with_suffix(path.suffix + '.complete')
    if not path.is_file() or not marker.is_file():
        return None
    with path.open('rb') as record, marker.open('rb') as completion:
        raw = record.read(MAX_RECORD_BYTES + 1)
        marked = completion.read(MAX_RECORD_BYTES + 1)
    if len(raw) > MAX_RECORD_BYTES or (marked and marked != raw):
        raise ValueError('completion marker differs from its bounded record')
    value = json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError('transport record must be a JSON object')
    return value

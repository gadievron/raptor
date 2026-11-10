"""Verify a complete append-only APT history window."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sys


def _read_stable(path: Path):
    with path.open('rb') as stream:
        first = os.fstat(stream.fileno())
        data = stream.read()
        last = os.fstat(stream.fileno())
        current = path.stat()
    fields = lambda stat: (stat.st_dev, stat.st_ino, stat.st_size, stat.st_mtime_ns)
    if fields(first) != fields(last) or fields(last) != fields(current) or len(data) != last.st_size:
        raise ValueError('history changed while reading')
    return data, last


def _complete(data: bytes, *, empty_ok: bool):
    if data and not data.endswith(b'\n'):
        raise ValueError('history must end at a line boundary')
    active = False
    transactions = 0
    for line in data.splitlines():
        if not line.strip():
            continue
        if line.startswith(b'Start-Date:'):
            if active:
                raise ValueError('nested or incomplete history transaction')
            active = True
        elif line.startswith(b'End-Date:'):
            if not active:
                raise ValueError('history ends a transaction without a start')
            active = False
            transactions += 1
        elif not active:
            raise ValueError('history content outside a transaction')
    if active or (not transactions and not empty_ok):
        raise ValueError('no complete new history transactions')


def snapshot(history: Path, output: Path):
    if output.resolve() == history.resolve():
        raise ValueError('snapshot must not overwrite history')
    data, stat = _read_stable(history)
    _complete(data, empty_ok=True)
    output.write_text(json.dumps({'version': 1, 'device': stat.st_dev,
        'inode': stat.st_ino, 'size': len(data),
        'prefix_sha256': hashlib.sha256(data).hexdigest()}, sort_keys=True)+'\n', encoding='utf-8')


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate snapshot key')
        result[key] = value
    return result


def extract(history: Path, metadata: Path, output: Path):
    if output.resolve() in {history.resolve(), metadata.resolve()}:
        raise ValueError('window must not overwrite history or snapshot')
    state = json.loads(metadata.read_text(encoding='utf-8'), object_pairs_hook=_unique)
    keys = {'version', 'device', 'inode', 'size', 'prefix_sha256'}
    if (not isinstance(state, dict) or set(state) != keys
            or any(type(state[k]) is not int or state[k] < 0 for k in keys-{'prefix_sha256'})
            or state['version'] != 1 or not isinstance(state['prefix_sha256'], str)
            or not re.fullmatch('[0-9a-f]{64}', state['prefix_sha256'])):
        raise ValueError('invalid history snapshot')
    data, stat = _read_stable(history)
    size = state['size']
    if ((stat.st_dev, stat.st_ino) != (state['device'], state['inode'])
            or size > len(data)
            or hashlib.sha256(data[:size]).hexdigest() != state['prefix_sha256']):
        raise ValueError('history identity or prior prefix changed')
    if size and data[size-1:size] != b'\n':
        raise ValueError('snapshot ends inside a history line')
    suffix = data[size:]
    _complete(suffix, empty_ok=False)
    output.write_bytes(suffix)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    start = sub.add_parser('snapshot')
    start.add_argument('history', type=Path)
    start.add_argument('metadata', type=Path)
    finish = sub.add_parser('extract')
    for name in ('history', 'metadata', 'output'):
        finish.add_argument(name, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == 'snapshot':
            snapshot(args.history, args.metadata)
        else:
            extract(args.history, args.metadata, args.output)
    except (OSError, ValueError) as exc:
        print(f'[apt-history-window] {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

#!/usr/bin/env python3
"""Refresh the bundled MPL-2.0 PSL from its authoritative HTTPS source."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import sys
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.domains.public_suffix import PSL_PATH, parse_suffix_list

DEST = PSL_PATH
URL = 'https://publicsuffix.org/list/public_suffix_list.dat'


def refresh_summary(previous: bytes, current: bytes) -> str:
    """Describe the exact downloaded snapshot and rule changes by section."""
    def metadata(data, name):
        match = re.search(rf'^// {name}: ([A-Za-z0-9_.:-]{{1,100}})$',
                          data.decode('utf-8'), re.MULTILINE)
        return match.group(1) if match else 'not provided'

    def sections(data):
        rules = {'ICANN': set(), 'PRIVATE': set()}
        section = None
        for line in data.decode('utf-8').splitlines():
            for name in rules:
                if line == f'// ===BEGIN {name} DOMAINS===':
                    section = name
                elif line == f'// ===END {name} DOMAINS===':
                    section = None
            if section is not None and line and not line.startswith('//'):
                rules[section].add(line)
        return rules

    before, after = sections(previous), sections(current)
    lines = [
        '## Public Suffix List refresh', '',
        f'Source: {URL}', '',
        f'- Previous version: `{metadata(previous, "VERSION")}`',
        f'- Downloaded version: `{metadata(current, "VERSION")}`',
        f'- Upstream commit: `{metadata(current, "COMMIT")}`',
        f'- Previous SHA-256: `{hashlib.sha256(previous).hexdigest()}`',
        f'- Downloaded SHA-256: `{hashlib.sha256(current).hexdigest()}`',
        f'- Snapshot bytes: {len(previous)} → {len(current)}', '',
        '| Rule section | Previous | Downloaded | Added | Removed |',
        '| --- | ---: | ---: | ---: | ---: |',
    ]
    for name in before:
        lines.append(f'| {name} | {len(before[name])} | {len(after[name])} | '
                     f'{len(after[name] - before[name])} | {len(before[name] - after[name])} |')
    lines += ['', 'Snapshot unchanged.' if previous == current else
              'Snapshot changed. Counts cover unique rule lines, including wildcard and '
              'exception rules; comment or version-only changes can leave counts unchanged.', '',
              'Review the list diff for changes to public and private hosting boundaries.', '']
    return '\n'.join(lines)


def main(summary_file: Path | None = None):
    with urlopen(URL, timeout=60) as response:
        data = response.read(4_000_001)
    if len(data) > 4_000_000:
        raise ValueError('public suffix list exceeds size limit')
    parse_suffix_list(data.decode('utf-8'))
    summary = refresh_summary(DEST.read_bytes(), data) if summary_file is not None else ''
    # Validate before replacing; a failed refresh preserves the last good list.
    with tempfile.NamedTemporaryFile(dir=DEST.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
    try:
        temporary.chmod(0o644)
        os.replace(temporary, DEST)
    finally:
        temporary.unlink(missing_ok=True)
    if summary_file is not None:
        summary_file.write_text(summary, encoding='utf-8')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--summary-file', type=Path, help='Write snapshot provenance and rule changes as Markdown')
    main(parser.parse_args().summary_file)

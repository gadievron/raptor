#!/usr/bin/env python3
"""Refresh the bundled MPL-2.0 PSL from its authoritative HTTPS source."""
import os
from pathlib import Path
import sys
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from core.domains.public_suffix import PSL_PATH, parse_suffix_list

DEST = PSL_PATH
URL = 'https://publicsuffix.org/list/public_suffix_list.dat'


def main():
    with urlopen(URL, timeout=60) as response:
        data = response.read(4_000_001)
    if len(data) > 4_000_000:
        raise ValueError('public suffix list exceeds size limit')
    parse_suffix_list(data.decode('utf-8'))
    # Validate before replacing; a failed refresh preserves the last good list.
    with tempfile.NamedTemporaryFile(dir=DEST.parent, delete=False) as output:
        temporary = Path(output.name)
        output.write(data)
    try:
        temporary.chmod(0o644)
        os.replace(temporary, DEST)
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    main()

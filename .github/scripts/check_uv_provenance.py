#!/usr/bin/env python3
"""Collect the exact installed uv binary's upstream image binding for CI verification."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.http import HttpError
from core.oci.client import RegistryError
from core.security.log_sanitisation import sanitise_for_terminal
from packages.sca.sbom_inventory.uv_provenance import prepare


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        prepare(args.audit_dir, args.out)
    except (OSError, ValueError, TypeError, KeyError, HttpError, RegistryError) as error:
        parser.exit(1, "uv provenance unavailable: " + sanitise_for_terminal(str(error)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

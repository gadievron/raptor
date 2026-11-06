"""Inspect, compare and export SBOM evidence offline, without generating HTML."""
from __future__ import annotations

import argparse
import logging
from pathlib import Path
import sys
import zipfile

from core.json import dumps_artifact, save_json
from core.logging import configure_cli_logging
from core.security.log_sanitisation import sanitise_for_terminal, escape_nonprintable
from .compare import compare
from .inventory import read_inventory
from .model import selected
from .output import inventory_document, csv_inventory, export_notices, markdown, write_inventory
from .source import Source


def parser():
    result = argparse.ArgumentParser(prog="raptor-sca sbom", description=__doc__,
        epilog="Examples:\n  raptor-sca sbom inspect sbom.cdx.json --out audit\n  raptor-sca sbom diff baseline/inventory.json current/inventory.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = result.add_subparsers(dest="command", required=True)
    inspect = commands.add_parser("inspect", help="inspect an SBOM or collected evidence", description="Inspect declarations, supplied dependency links and retained notice/ownership evidence. No network or image code is executed.",
        epilog="Examples:\n  raptor-sca sbom inspect container-sbom.zip --out audit\n  raptor-sca sbom inspect sbom.spdx.json --license MIT --format csv",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    notices = commands.add_parser("notices", help="export original licence and notice bytes", description="Export retained original bytes and a portable index to a new directory. External licence URLs are never fetched.",
        epilog="Examples:\n  raptor-sca sbom notices container-sbom.zip --out notices\n  raptor-sca sbom notices sbom.cdx.json --license MIT --out mit-notices",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    for sub in (inspect, notices):
        sub.add_argument("input", type=Path, help="CycloneDX 1.5 / SPDX 2.3 JSON, audit snapshot, evidence ZIP or directory")
        sub.add_argument("--license", dest="license_id", help="exact declaration operand, including AND/OR expressions (default: all)")
        sub.add_argument("--package", help="exact package name, occurrence ID or Package URL (default: all)")
        sub.add_argument("--scope", choices=("packages", "source-candidates", "subjects"), help="inventory scope (default: all, kept separate)")
    inspect.add_argument("--format", choices=("text", "json", "csv"), default="text", help="stdout format (default: text)")
    inspect.add_argument("--out", type=Path, help="also write inventory.json, inventory.csv and summary.md (default: stdout only)")
    notices.add_argument("--out", type=Path, required=True, help="new export directory; existing paths are refused")
    diff = commands.add_parser("diff", help="compare two inventories or audit snapshots", description="Compare occurrences, versions, declarations and notice fingerprints. Ambiguous matches remain explicit; notice text updates are informational.",
        epilog="Examples:\n  raptor-sca sbom diff old.cdx.json new.cdx.json\n  raptor-sca sbom diff old/inventory.json new/inventory.json --out changes.json",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    diff.add_argument("baseline", type=Path)
    diff.add_argument("current", type=Path)
    diff.add_argument("--out", type=Path, help="also save comparison JSON (default: stdout only)")
    return result


def _emit(value):
    # JSON escapes controls and BIDI/non-ASCII for terminal-safe machine output.
    print(dumps_artifact(value, ensure_ascii=True))


def main(argv=None):
    args = parser().parse_args(argv)
    configure_cli_logging(logging.WARNING)
    try:
        if args.command == "diff":
            with Source(args.baseline) as source:
                before, _ = read_inventory(source)
            with Source(args.current) as source:
                after, _ = read_inventory(source)
            result = compare(before, after)
            if args.out:
                save_json(args.out, result, stream=True)
            _emit(result)
            return 0
        with Source(args.input) as source:
            inventory, embedded = read_inventory(source)
            records = selected(inventory, license_id=args.license_id, package=args.package, scope=args.scope)
            if args.command == "notices":
                result = export_notices(args.out, inventory, records, source, embedded,
                                        include_unassociated=not any((args.license_id, args.package, args.scope)))
                _emit(result)
            else:
                if args.out:
                    write_inventory(args.out, inventory, records)
                if args.format == "json":
                    _emit(inventory_document(inventory, records))
                elif args.format == "csv":
                    sys.stdout.write(csv_inventory(records))
                else:
                    print(escape_nonprintable(markdown(inventory, records), preserve_newlines=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, RecursionError, zipfile.BadZipFile) as error:
        print("raptor-sca sbom: " + sanitise_for_terminal(str(error)), file=sys.stderr)
        return 2

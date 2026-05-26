"""``raptor-sca suppress`` — operator UX for the suppression overlay.

The substrate (``packages/sca/suppressions.py``) parses
``.raptor-sca-suppress.yml`` and applies its entries to scan
findings. This module exposes that substrate as a CLI so
operators can:

  * ``list``    — see what's currently suppressed in a target dir
  * ``check``   — validate entries against a fresh ``findings.json``
                  and surface stale (orphan) entries that no
                  longer match anything

The pre-fix UX gap: operators added entries when they reviewed a
finding, but as deps got upgraded the suppressed advisories
quietly disappeared from scan output — leaving the suppression
file with stale entries no one noticed. ``check`` makes that
state visible.

A future ``add`` action will append entries from a finding ID +
reason; deferred until operator demand surfaces (the YAML hand-
edit flow works fine for the common case)."""

from __future__ import annotations

import argparse
import json
import logging
import sys
from datetime import date
from pathlib import Path
from typing import List, Sequence

from .suppressions import (
    SUPPRESS_FILENAME,
    SuppressionEntry,
    load,
)

logger = logging.getLogger(__name__)


def main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="raptor-sca suppress",
        description="Inspect and validate the suppression overlay.",
    )
    sub = parser.add_subparsers(dest="action", required=True)

    p_list = sub.add_parser(
        "list", help="show all entries in the suppression file",
    )
    p_list.add_argument(
        "--target", default=".",
        help="target directory containing the suppression file "
             "(default: cwd)",
    )
    p_list.add_argument(
        "--json", action="store_true", dest="emit_json",
        help="emit JSON instead of the operator-readable table",
    )

    p_check = sub.add_parser(
        "check",
        help="validate entries match a fresh findings.json — "
             "surface stale (orphan) entries",
    )
    p_check.add_argument(
        "--target", default=".",
        help="target directory containing the suppression file "
             "(default: cwd)",
    )
    p_check.add_argument(
        "--findings", required=True,
        help="path to findings.json from a recent scan",
    )

    args = parser.parse_args(argv)

    if args.action == "list":
        return _cmd_list(Path(args.target).resolve(),
                          emit_json=args.emit_json)
    if args.action == "check":
        return _cmd_check(
            target=Path(args.target).resolve(),
            findings_path=Path(args.findings).resolve(),
        )
    parser.error(f"unknown action {args.action!r}")
    return 2


def _cmd_list(target: Path, *, emit_json: bool) -> int:
    suppress_path = target / SUPPRESS_FILENAME
    if not suppress_path.exists():
        print(f"raptor-sca suppress: no {SUPPRESS_FILENAME} in "
              f"{target}", file=sys.stderr)
        return 1
    entries = load(suppress_path)
    if emit_json:
        print(json.dumps(
            [_entry_to_dict(e) for e in entries], indent=2,
        ))
        return 0
    if not entries:
        print(f"raptor-sca suppress: {suppress_path} has no entries.")
        return 0
    today = date.today()
    print(f"raptor-sca suppress: {len(entries)} entry(ies) in "
          f"{suppress_path}")
    for e in entries:
        kind, target_label = _describe_entry(e)
        bits: List[str] = [kind, target_label]
        if e.expires:
            note = ("EXPIRED" if e.is_expired(today)
                     else f"until {e.expires}")
            bits.append(note)
        bits.append(f"reason: {e.reason}")
        print("  · " + " · ".join(bits))
    return 0


def _cmd_check(*, target: Path, findings_path: Path) -> int:
    suppress_path = target / SUPPRESS_FILENAME
    if not suppress_path.exists():
        print(f"raptor-sca suppress: no {SUPPRESS_FILENAME} in "
              f"{target} — nothing to check", file=sys.stderr)
        return 1
    if not findings_path.exists():
        print(f"raptor-sca suppress: {findings_path} not found",
              file=sys.stderr)
        return 2
    entries = load(suppress_path)
    if not entries:
        print(f"raptor-sca suppress: {suppress_path} has no entries.")
        return 0
    rows = json.loads(findings_path.read_text(encoding="utf-8"))
    if not isinstance(rows, list):
        print("raptor-sca suppress: findings.json top-level is not a "
              "list", file=sys.stderr)
        return 2

    today = date.today()
    expired: List[SuppressionEntry] = []
    matched: List[SuppressionEntry] = []
    orphan: List[SuppressionEntry] = []
    for e in entries:
        if e.is_expired(today):
            expired.append(e)
            continue
        if any(e.matches(r) for r in rows):
            matched.append(e)
        else:
            orphan.append(e)

    print(f"raptor-sca suppress: checked {len(entries)} entry(ies) "
          f"against {len(rows)} finding(s)")
    print(f"  · {len(matched)} active (entry matches a current finding)")
    print(f"  · {len(orphan)} orphan (entry matches no current finding "
          "— consider removing)")
    print(f"  · {len(expired)} expired (entry's `expires` date has "
          "passed)")
    if orphan:
        print()
        print("Orphan entries:")
        for e in orphan:
            kind, label = _describe_entry(e)
            print(f"  · {kind} · {label} · reason: {e.reason}")
    if expired:
        print()
        print("Expired entries:")
        for e in expired:
            kind, label = _describe_entry(e)
            print(f"  · {kind} · {label} · expired {e.expires}")
    # Exit 1 if there's anything actionable so CI gates can fail
    # the build when operators leave stale entries lying around.
    return 1 if (orphan or expired) else 0


def _describe_entry(e: SuppressionEntry) -> "tuple[str, str]":
    if e.finding_id:
        return ("finding_id", e.finding_id)
    if e.advisory_id:
        return ("advisory_id", e.advisory_id)
    pkg = ":".join(p for p in (e.ecosystem, e.name, e.version) if p)
    if pkg:
        return ("package", pkg)
    return ("?", "(no matcher)")


def _entry_to_dict(e: SuppressionEntry) -> dict:
    return {
        "reason": e.reason,
        "expires": e.expires.isoformat() if e.expires else None,
        "finding_id": e.finding_id,
        "advisory_id": e.advisory_id,
        "ecosystem": e.ecosystem,
        "name": e.name,
        "version": e.version,
    }

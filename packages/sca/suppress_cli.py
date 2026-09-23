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
import sys
from datetime import date
from pathlib import Path

from core.json import load_json
from core.security.log_sanitisation import sanitise_for_terminal as _sft

from .parsers._safe_read import scan_root_context
from .suppressions import (
    SUPPRESS_FILENAME,
    SuppressionEntry,
    load,
)
from typing import TYPE_CHECKING

import json

# findings.json artifacts are RAPTOR-written run output — the
# findings-class budget.
from .kinds import MAX_FINDINGS_BYTES as _MAX_FINDINGS_BYTES

if TYPE_CHECKING:
    from collections.abc import Sequence


def main(argv: Sequence[str]) -> int:
    # Escaping-console chokepoint: this subcommand runs as its own
    # libexec-dispatched process; with no logging config,
    # logging.lastResort would relay WARNING+ foreign text (YAMLError
    # text quoting a hostile suppressions file) to the TTY with a
    # plain formatter.
    from .cli import _configure_logging  # local import: avoid cycle
    _configure_logging(0)
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
    # argparse ``choices`` makes an unknown action unreachable;
    # parser.error raises SystemExit if that invariant ever breaks.
    parser.error(f"unknown action {args.action!r}")


def _cmd_list(target: Path, *, emit_json: bool) -> int:
    suppress_path = target / SUPPRESS_FILENAME
    if not suppress_path.exists():
        print(f"raptor-sca suppress: no {SUPPRESS_FILENAME} in "
              f"{target}", file=sys.stderr)
        return 1
    # Scan-root context: an overlay symlink resolving inside the
    # target is honoured (monorepo shared-config); escapes refused.
    with scan_root_context(target):
        entries = load(suppress_path)
    if emit_json:
        # The entries come from the SCANNED target's suppress file —
        # hostile bytes in reasons/ids must not reach the terminal as
        # live controls. ensure_ascii keeps the JSON lane valid for
        # parsing consumers while escaping C1 controls (dumps_display
        # is ensure_ascii=False and passes them raw).
        print(json.dumps(
            [_entry_to_dict(e) for e in entries], indent=2,
            ensure_ascii=True, default=str,
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
        bits: list[str] = [kind, target_label]
        if e.expires:
            note = ("EXPIRED" if e.is_expired(today)
                     else f"until {_sft(str(e.expires), max_len=32)}")
            bits.append(note)
        bits.append(f"reason: {_sft(e.reason)}")
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
    with scan_root_context(target):
        entries = load(suppress_path)
    if not entries:
        print(f"raptor-sca suppress: {suppress_path} has no entries.")
        return 0
    try:
        rows = load_json(
            findings_path, strict=True, max_bytes=_MAX_FINDINGS_BYTES,
        )
        if rows is None:
            # Strict load_json soft-returns None for a missing file.
            raise FileNotFoundError(findings_path)
    except (OSError, ValueError) as exc:
        # Decode/OS errors on a target-adjacent file can quote hostile
        # bytes — escape before the terminal.
        print(f"raptor-sca suppress: cannot read {findings_path}: "
              f"{_sft(str(exc))}", file=sys.stderr)
        return 2
    if not isinstance(rows, list):
        print("raptor-sca suppress: findings.json top-level is not a "
              "list", file=sys.stderr)
        return 2
    # Hand-edited / third-party findings.json may contain stray
    # non-dict elements — soft-skip like the thresholds gate
    # (FindingRow.from_row) two lines over in the same CLI, rather
    # than crash the CI-gate helper with an AttributeError inside
    # SuppressionEntry.matches.
    rows = [r for r in rows if isinstance(r, dict)]

    today = date.today()
    expired: list[SuppressionEntry] = []
    matched: list[SuppressionEntry] = []
    orphan: list[SuppressionEntry] = []
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
            print(f"  · {kind} · {label} · reason: {_sft(e.reason)}")
    if expired:
        print()
        print("Expired entries:")
        for e in expired:
            kind, label = _describe_entry(e)
            print(f"  · {kind} · {label} · expired "
                  f"{_sft(str(e.expires), max_len=32)}")
    # Exit 1 if there's anything actionable so CI gates can fail
    # the build when operators leave stale entries lying around.
    return 1 if (orphan or expired) else 0


def _describe_entry(e: SuppressionEntry) -> tuple[str, str]:
    """Kind + label for one entry. The label fields come from the
    scanned target's suppress YAML — escape control bytes here so
    every print site downstream is terminal-safe by construction."""
    if e.finding_id:
        return ("finding_id", _sft(e.finding_id, max_len=128))
    if e.advisory_id:
        return ("advisory_id", _sft(e.advisory_id, max_len=128))
    pkg = ":".join(p for p in (e.ecosystem, e.name, e.version) if p)
    if pkg:
        return ("package", _sft(pkg, max_len=128))
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

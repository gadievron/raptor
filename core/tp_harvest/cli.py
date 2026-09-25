"""Operator CLI for the true-positive harvest flywheel.

Dispatched by ``libexec/raptor-tp-harvest``. Three surfaces:

* ``raptor-tp-harvest <run-dir>`` — harvest the run's confirmed
  findings into records + rule candidates + backlog pointers.
* ``raptor-tp-harvest <run-dir> --status`` — show the manifest and
  disclosure backlog without harvesting.
* ``raptor-tp-harvest <run-dir> --label <harvest-id> ...`` — the
  per-finding provenance flip that emits a corpus label.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

from core.json.jsonl import load_jsonl
from core.security.log_sanitisation import sanitise_for_terminal
from core.tp_harvest import harvest as harvest_mod
from core.tp_harvest import labels as labels_mod

_MAX_BACKLOG_BYTES = 8 * 1024 * 1024


def _title(status: str) -> str:
    return status.replace("_", " ").title() if status else "(none)"


def _term(text: Any) -> str:
    """Terminal-grade sanitisation for target-/tool-derived text
    (escape non-printables AND bound length)."""
    return sanitise_for_terminal(str(text), max_len=512)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="raptor-tp-harvest",
        description=(
            "Harvest a run's confirmed true positives into detection-rule "
            "candidates and provenance-gated corpus label records."),
    )
    parser.add_argument("run_dir", help="Run output directory to harvest.")
    parser.add_argument(
        "--status", action="store_true",
        help="Show the harvest manifest + disclosure backlog; no harvest.")
    parser.add_argument(
        "--no-candidates", action="store_true",
        help="Skip rule-candidate generation this pass.")
    parser.add_argument(
        "--json", action="store_true",
        help="Emit the summary as JSON.")

    flip = parser.add_argument_group(
        "label flip (per finding — emits one corpus label)")
    flip.add_argument(
        "--label", metavar="HARVEST_ID",
        help="Harvest id (from the manifest) to flip into a corpus label.")
    flip.add_argument(
        "--provenance", choices=sorted(labels_mod.VALID_PROVENANCE),
        help="Provenance assertion. Required with --label; without it the "
             "finding stays on the disclosure backlog (default-closed).")
    flip.add_argument("--bug-class", help="Corpus bug class for the label.")
    flip.add_argument("--rationale", help="Label rationale (why it grades "
                                          "finding at this pin).")
    flip.add_argument("--cve", default="",
                      help="Public anchor: CVE id (public provenance).")
    flip.add_argument("--fix-commit", default="",
                      help="Public anchor: upstream fix commit sha/URL.")
    flip.add_argument("--labeler", default="operator",
                      help="Labeler identity recorded on the label.")
    flip.add_argument("--repo",
                      help="Upstream repo identity for the SourcePin.")
    flip.add_argument("--sha", default="",
                      help="Pin sha. Default: derived from the target tree "
                           "(refused when the tree is dirty).")
    flip.add_argument("--channel", default="",
                      help="Optional corpus channel tag.")
    flip.add_argument(
        "--labels-base", default="",
        help="Label store base directory (default: the local private "
             "corpus label store).")
    return parser


def _print_summary(summary: dict[str, Any]) -> None:
    out = sys.stdout
    out.write(f"tp-harvest: {summary['run_dir']}\n")
    if summary["command"]:
        out.write(f"  command: {_term(summary['command'])}\n")
    out.write(f"  findings seen: {summary['findings_total']}\n")
    out.write(f"  newly harvested: {len(summary['harvested'])}\n")
    for hid in summary["harvested"]:
        out.write(f"    {hid}\n")
    if summary["skipped"]:
        out.write("  skipped:\n")
        for reason, count in sorted(summary["skipped"].items()):
            out.write(f"    {reason}: {count}\n")
    for note in summary["notes"]:
        out.write(f"  note: {note}\n")
    out.write(f"  manifest: {summary['manifest']}\n")


def _cmd_status(run_dir: Path, as_json: bool) -> int:
    manifest = harvest_mod.load_manifest(run_dir)
    backlog_rows = load_jsonl(
        harvest_mod.backlog_path(run_dir),
        max_total_bytes=_MAX_BACKLOG_BYTES)
    if as_json:
        sys.stdout.write(json.dumps(
            {"manifest": manifest, "backlog": backlog_rows},
            indent=2, ensure_ascii=True, default=str) + "\n")
        return 0
    entries = manifest.get("entries", {})
    if not isinstance(entries, dict):
        entries = {}
    sys.stdout.write(f"tp-harvest status: {run_dir}\n")
    if not entries:
        sys.stdout.write("  nothing harvested yet (empty manifest)\n")
        return 0
    # Every manifest value printed here is attacker-influencible (an
    # imported run dir ships its own manifest): hid keys are shown
    # only when they match the harvest-id charset, everything else is
    # terminal-sanitised.
    for hid, entry in sorted(entries.items(), key=lambda kv: str(kv[0])):
        if not isinstance(entry, dict):
            continue
        hid_disp = (hid if isinstance(hid, str)
                    and _HARVEST_ID_RE.fullmatch(hid)
                    else f"(invalid id) {_term(hid)}")
        action = entry.get("action", "?")
        action_disp = (action if action in ("harvested", "skipped")
                       else f"(unknown) {_term(action)}")
        status = _term(_title(str(entry.get("status", ""))))
        line = f"  {hid_disp}  {action_disp}  {status}"
        if action == "skipped":
            line += f"  ({_term(entry.get('skip_reason', '')) })"
        if entry.get("record_tampered"):
            line += "  [record tampered]"
        if entry.get("oracle_verified"):
            line += "  [oracle-verified]"
        if entry.get("label"):
            line += "  [labelled]"
        elif action == "harvested":
            line += "  [on disclosure backlog]"
        sys.stdout.write(line + "\n")
    sys.stdout.write(f"  backlog pointers: {len(backlog_rows)}\n")
    return 0


# Harvest ids are finding_signature hex (32 chars today; accept the
# labeled-attempts 8-64 range). Validated BEFORE the id is used to
# build a records/ path — a free-form value must never steer the
# file lookup outside the run's records directory.
_HARVEST_ID_RE = re.compile(r"[0-9a-f]{8,64}")


def _cmd_label(args: argparse.Namespace, run_dir: Path) -> int:
    if not _HARVEST_ID_RE.fullmatch(args.label):
        sys.stderr.write(
            f"invalid harvest id {_term(args.label)!r}: expected "
            "lowercase hex (see the manifest / --status)\n")
        return 2
    missing = [name for name, val in (
        ("--provenance", args.provenance),
        ("--bug-class", args.bug_class),
        ("--rationale", args.rationale),
        ("--repo", args.repo),
    ) if not val]
    if missing:
        sys.stderr.write(
            f"--label requires {_term(', '.join(missing))}\n")
        return 2

    # Gate first: a provenance refusal must precede pin derivation
    # (emit_label re-checks — defence in depth).
    try:
        labels_mod.check_provenance(
            args.provenance, cve=args.cve, fix_commit=args.fix_commit)
    except labels_mod.ProvenanceGateError as exc:
        sys.stderr.write(f"label refused: {_term(exc)}\n")
        return 1

    record = harvest_mod.load_record(run_dir, args.label)
    if record is None:
        sys.stderr.write(
            f"no harvest record {args.label} under {run_dir} — run the "
            "harvest first (raptor-tp-harvest <run-dir>)\n")
        return 1

    sha = args.sha
    if not sha:
        pin = labels_mod.derive_target_pin(record.target_path)
        if not pin or not pin.get("commit"):
            sys.stderr.write(
                "cannot derive a pin sha from the target tree — pass "
                "--sha explicitly\n")
            return 1
        # Fail-closed on dirtiness: only a PROVEN-clean tree (dirty is
        # False) may auto-pin. None means the probes could not tell —
        # unknowable is not clean, and a label pinned to a sha whose
        # working tree may not match it is a corrupt pin.
        if pin.get("dirty") is not False:
            state = ("dirty" if pin.get("dirty")
                     else "of unknowable dirtiness")
            sys.stderr.write(
                f"target tree is {state}: the span content may not "
                "match the derived sha — pass --sha explicitly to "
                "override\n")
            return 1
        sha = str(pin["commit"])

    labels_base = (Path(args.labels_base) if args.labels_base
                   else labels_mod.default_labels_base())
    try:
        path = labels_mod.emit_label(
            record,
            bug_class=args.bug_class,
            rationale=args.rationale,
            labeler=args.labeler,
            provenance=args.provenance,
            repo=args.repo,
            sha=sha,
            labels_base=labels_base,
            cve=args.cve,
            fix_commit=args.fix_commit,
            channel=args.channel,
        )
    except ValueError as exc:
        # Gate/schema messages can embed target-derived identifiers.
        sys.stderr.write(f"label refused: {_term(exc)}\n")
        return 1
    harvest_mod.record_label_emitted(run_dir, args.label, path)
    # The label filename embeds the target-derived function_id.
    sys.stdout.write(f"label written: {_term(path)}\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        sys.stderr.write(f"not a directory: {run_dir}\n")
        return 1

    # Structure gate on every surface that reads or writes under
    # tp-harvest/ (harvest_run re-checks internally for API callers).
    try:
        harvest_mod.refuse_symlinked_harvest_dir(run_dir)
    except harvest_mod.HostileRunDirError as exc:
        sys.stderr.write(f"refusing run dir: {_term(exc)}\n")
        return 1

    if args.status:
        return _cmd_status(run_dir, args.json)
    if args.label:
        return _cmd_label(args, run_dir)

    summary = harvest_mod.harvest_run(
        run_dir, with_candidates=not args.no_candidates)
    if args.json:
        sys.stdout.write(json.dumps(summary, indent=2, ensure_ascii=True,
                                    default=str) + "\n")
    else:
        _print_summary(summary)
    return 0

"""Portable suppression inventory/check views over native captured groups."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets
from .suppressions import SUPPRESS_FILENAME

DETAIL_LIMIT = 100


def suppression_result(args, capture, status):
    from .suppress_cli import _entry_to_dict
    payload = {}
    counts = {}
    for label in ("entries", "matched", "orphan", "expired"):
        entries = capture.get(label)
        if entries is None:
            continue
        counts[label] = len(entries)
        rows = [_entry_to_dict(entry) for entry in entries[:DETAIL_LIMIT]]
        payload[label] = [{key: sanitise_string(redact_secrets(value), max_chars=2000) if isinstance(value, str)
                           else value for key, value in row.items()} for row in rows]
    payload.update({"mode": args.action, "native exit status": status,
                    "finding count checked": capture.get("finding_count"),
                    "evaluation date": capture.get("evaluated_on"), "recorded counts": counts})
    notes = ["Suppression matches do not validate their security rationale. Orphans are relative to the supplied findings, not proof of remediation.",
             "Entries are captured from the native loader; empty entries do not establish overlay validity. Native parser warnings remain authoritative.",
             "Report details are bounded to 100 entries per group and 2000 characters per text field; counts retain full native totals."]
    state = "failed" if status == 2 or "entries" not in capture else "completed"
    if args.action == "check" and "finding_count" not in capture:
        notes.append("Findings were not checked; matched/orphan/expired classifications are unavailable.")
    if state == "failed":
        notes.append("Native suppression inventory/check did not complete; retain its nonzero status.")
    target = Path(args.target).resolve()
    artifacts = [{"path": str(target / SUPPRESS_FILENAME)}]
    if args.action == "check":
        artifacts.append({"path": str(Path(args.findings).resolve())})
    return NativeResult("sca-suppress", str(target), "sca-suppress", payload, state=state, diagnostics=notes,
                        metrics={"Mode": args.action, "Native exit status": status, **counts}, artifacts=artifacts,
                        stages=[StageEnvelope("suppression " + args.action, state, producer="sca")])


def complete_suppression_report(args, options, capture, status):
    output = options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(suppression_result(args, capture, status), root,
                                      stem="sca-suppress", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional suppression report unavailable (" + type(error).__name__ + "); native status retained", file=sys.stderr)
        return None

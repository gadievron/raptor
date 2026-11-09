"""Portable overlay verification views; verification owns verdicts and scans."""
from __future__ import annotations

import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.log_sanitisation import sanitise_for_terminal

DETAIL_LIMIT = 100
BUCKETS = ("new", "resolved", "suppression_added", "suppression_lifted", "persistent")


def verification_result(*, target, proposed, applied, delta, summary, osv_degraded, exit_code,
                        before_findings, after_findings, out_dir, baseline_reused):
    notes = ["Observed comparison for the selected proposed overlay. Absence alone does not establish complete remediation or equal scan coverage.",
             "Only persistent findings in applied files gate targeted verification; unrelated backlog is retained separately."]
    if osv_degraded:
        notes.append("Verdict unavailable: advisory coverage was incomplete in a before/after scan; resolved/new counts cannot be trusted. Re-run verification when advisory data is available.")
    payload = {"summary": dict(summary), "exit_code": exit_code, "advisory coverage degraded": osv_degraded,
               "baseline reused": baseline_reused, "applied files": [str(path) for path in applied[:DETAIL_LIMIT]],
               "recorded applied files": len(applied), "category counts": {key: len(getattr(delta, key)) for key in BUCKETS}}
    for key in BUCKETS:
        rows = getattr(delta, key)
        payload[key] = rows[:DETAIL_LIMIT]
        if len(rows) > DETAIL_LIMIT:
            notes.append(f"{key.replace('_', ' ')}: report captures {DETAIL_LIMIT} of {len(rows)} observations; native findings retain the full evidence.")
    if len(applied) > DETAIL_LIMIT:
        notes.append(f"Report lists {DETAIL_LIMIT} of {len(applied)} applied files; delta.json retains the complete file list.")
    return NativeResult("sca-verify", str(target), out_dir.name, payload,
                        state="partial" if osv_degraded else "completed", diagnostics=notes,
                        metrics={**summary, "verification exit code": exit_code, "applied files": len(applied)},
                        metadata={"Proposed overlay": str(proposed), "Baseline findings": str(before_findings),
                                  "Current findings": str(after_findings)},
                        stages=[StageEnvelope("overlay comparison", "partial" if osv_degraded else "completed", producer="sca")],
                        artifacts=[{"path": str(path)} for path in [before_findings, after_findings, out_dir / "delta.md", out_dir / "delta.json"]])


def complete_verify_report(args, **observations):
    try:
        result = verification_result(**observations, baseline_reused=bool(args.findings))
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_native_result(result, root, stem="sca-verify", options=args._report_options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional verification report unavailable (" + type(error).__name__ + "); native artifacts and exit status retained"), file=sys.stderr)
        return None

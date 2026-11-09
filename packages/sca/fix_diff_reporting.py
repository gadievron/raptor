"""Portable, bounded receipts over completed upstream fix discovery calls."""
from __future__ import annotations

import sys

from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.security.prompt_output_sanitise import sanitise_string
from core.security.redaction import redact_secrets

DETAIL_LIMIT = 100
_FIELDS = ("ok", "cve_id", "output_dir", "exit_code", "repository_url", "fix_commit",
           "files_changed", "error_class", "error_detail")


def fix_diff_result(results, *, dropped=0, findings_path=None, summary_path=None, error=None):
    rows = []
    notes = ["A discovered fix pointer is not proof that a scanned dependency contains that fix or is exploitable."]
    for result in results[:DETAIL_LIMIT]:
        row = {}
        for key in _FIELDS:
            if key not in result:
                continue
            value = result[key]
            if isinstance(value, str):
                value = sanitise_string(redact_secrets(value), max_chars=2000)
            elif value is not None and not isinstance(value, (bool, int, float)):
                value = "Unsupported field type: " + type(value).__name__
            row[key] = value
        rows.append(row)
    resolved = sum(bool(row["ok"]) for row in results)
    pointers = sum(bool(row.get("fix_commit")) for row in results if row["ok"])
    metrics = {"Attempted CVE entries": len(results), "Successful discovery entries": resolved,
               "Recorded fix pointers": pointers,
               "Failed discovery entries": len(results) - resolved, "Unattempted over cap": dropped}
    state = "failed" if error else "partial" if dropped or resolved != len(results) or pointers != resolved else "completed"
    if error:
        notes.append(error)
    elif not results:
        notes.append("No CVE-identified entries were selected; no discovery calls ran. This is not a clean vulnerability assessment.")
    if pointers != resolved:
        notes.append("Some successful native discovery entries have no recorded fix pointer; missing pointers remain unavailable.")
    if dropped:
        notes.append(f"{dropped} CVE entries beyond the native discovery cap were not attempted.")
    notes.append("Report includes at most 100 result rows and 2000 characters per text field; native summary.json retains full discovery output.")
    artifacts = [{"path": str(path)} for path in (findings_path, summary_path) if path is not None]
    return NativeResult("sca-fix-diff", str(findings_path) if findings_path else "explicit CVE selection", "sca-fix-diff",
                        {"results": rows, "recorded counts": metrics, "input error": error},
                        state=state, diagnostics=notes, metrics=metrics, artifacts=artifacts,
                        stages=[StageEnvelope("upstream fix discovery", state, producer="sca")])


def complete_fix_diff_report(options, results, **metadata):
    output = options.output
    root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
    try:
        return complete_native_result(fix_diff_result(results, **metadata), root,
                                      stem="sca-fix-diff", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print("Optional fix-diff report unavailable (" + type(error).__name__ + "); native result retained", file=sys.stderr)
        return None

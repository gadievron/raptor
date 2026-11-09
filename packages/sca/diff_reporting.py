"""Portable presentation of recorded SCA comparisons; no new analysis."""
from __future__ import annotations

from dataclasses import asdict
import sys

from core.reporting.builders import build_document
from core.reporting.document import Block, ReportContext, StageEnvelope
from core.reporting.service import complete_reporting
from core.security.log_sanitisation import sanitise_for_terminal

DETAIL_LIMIT = 100
BUCKETS = ("new", "resolved", "suppression_added", "suppression_lifted", "persistent")


def build_diff_document(delta, *, baseline: str, current: str, threshold: str,
                        include_suppressed: bool, show_persistent: bool, exit_code: int):
    counts = {key: len(getattr(delta, key)) for key in BUCKETS}
    notes = ["Comparison of supplied findings only. Resolved means absent from the selected current findings; it does not establish remediation or equal scan coverage."]
    blocks = [Block("table", title="Recorded comparison", columns=["Category", "Findings"],
                    rows=[[key.replace("_", " "), count] for key, count in counts.items()]),
              Block("paragraph", text=f"New-finding gate: {'triggered' if exit_code else 'not triggered'}; severity threshold {threshold}; new KEV matches also trigger the gate."),
              Block("paragraph", text="Suppressed findings " + ("included" if include_suppressed else "excluded") + " from new/resolved categories; suppression changes are reported separately.")]
    for key in BUCKETS:
        rows = getattr(delta, key)
        if key == "persistent" and not show_persistent:
            continue
        shown = rows[:DETAIL_LIMIT]
        cells = []
        for row in shown:
            sca = row.get("sca") if isinstance(row.get("sca"), dict) else {}
            raw_advisory = sca.get("advisory")
            advisory = raw_advisory if isinstance(raw_advisory, dict) else {}
            cells.append([str(sca.get("ecosystem") or "unknown"), str(sca.get("name") or "unknown"),
                          str(sca.get("version") or "unknown"), str(advisory.get("id") or row.get("vuln_type") or "unknown"),
                          str(row.get("severity") or "unknown"), bool(row.get("suppressed")), bool(sca.get("in_kev")),
                          str(sca.get("epss") if sca.get("epss") is not None else "unknown"),
                          str(row.get("suppression_reason") or "not recorded")])
        blocks.append(Block("table", title=key.replace("_", " ").capitalize(),
                            columns=["Ecosystem", "Package", "Version", "Advisory / signal", "Severity", "Suppressed", "KEV", "EPSS", "Suppression reason"], rows=cells))
        if len(shown) < len(rows):
            notes.append(f"{key.replace('_', ' ')}: showing {len(shown)} of {len(rows)} rows; native --json output retains the complete comparison.")
    context = ReportContext("sca-diff", "sca-diff", target=current, state="completed",
                            stages=[StageEnvelope("compare", "completed", producer="sca")], diagnostics=notes,
                            artifacts=[{"path": baseline}, {"path": current}],
                            extensions={"raptor.findings_available": False, "raptor.metrics": counts,
                                        "raptor.result_sections": [asdict(block) for block in blocks],
                                        "raptor.selection": {"baseline": baseline, "current": current,
                                                             "include_suppressed": include_suppressed,
                                                             "show_persistent": show_persistent,
                                                             "fail_on_severity": threshold, "gate_exit_code": exit_code}})
    document = build_document(context, title="SCA findings comparison", blocks=blocks)
    document.summary.update(counts)
    return context, document


def complete_diff_report(args, delta, *, exit_code: int):
    try:
        context, document = build_diff_document(delta, baseline=args.a, current=args.b,
                                                threshold=args.fail_on_severity,
                                                include_suppressed=args.include_suppressed,
                                                show_persistent=args.show_persistent, exit_code=exit_code)
        output = args._report_options.output
        root = output if output.is_dir() or not output.suffix else output.parent / ("." + output.stem + "-report")
        return complete_reporting(context, root, stem="sca-diff", options=args._report_options,
                                  document=document, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as error:
        print(sanitise_for_terminal("Optional comparison report unavailable (" + type(error).__name__ + "); native output and gate status retained"), file=sys.stderr)
        return None

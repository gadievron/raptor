"""Optional readiness exports over one already completed scorecard audit."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary

from .audit import AuditReport
from .audit_document import build_audit_document


def prepare(options: ReportOptions, source: Path) -> Path:
    root = source.parent / "portable-reports" / "scorecard-audit"
    if not options.enabled:
        return root
    options = options.validate()
    if options.output is None:
        raise ValueError("Read-only audit exports require --report-output")
    chosen = options.output
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    for format in options.formats:
        filename = dict(options.filenames).get(format, "scorecard-audit" + get_renderer(format).extension)
        path = chosen if is_file else chosen / filename
        if path.resolve() == source.resolve():
            raise ValueError("Portable audit output cannot replace the source scorecard")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def emit(report: AuditReport, options: ReportOptions, status: int) -> None:
    try:
        source = Path(report.scorecard_path)
        root = prepare(options, source)
        document = build_audit_document(report)
        limited = bool(document.extensions["raptor.truncated_fields"] or document.extensions["raptor.event_rows_omitted"]
                       or document.extensions["raptor.class_rows_omitted"])
        notes = [*document.diagnostics, "Recorded readiness reason: " + document.blocks[0].text,
                 "The audit result supplies integrity flags, not detailed rejected-row accounting or target execution coverage. No historical run identity is adopted."]
        context = ReportContext("scorecard-audit", "unknown", target=str(document.metadata["Scorecard"]),
                                state="partial" if limited or report.sidecar_demoted or report.key_unusable else "unknown" if report.verdict == "no-data" else "completed",
                                diagnostics=notes, artifacts=[{"path": str(source.resolve()), "role": "source scorecard; preserved"}],
                                extensions={"raptor.findings_available": False, "raptor.metrics": {
                                    "Native audit exit status": status, "Recorded readiness verdict": report.verdict,
                                    "Distinct models": report.total_models, "Distinct decision classes": report.total_decision_classes,
                                    "Native cells": report.total_cells, "Native event-type rows": len(report.event_type_summaries),
                                    "Sidecar demoted": report.sidecar_demoted, "Integrity key unusable": report.key_unusable},
                                    "raptor.audit_capture": document.to_dict(), "raptor.capture_limited": limited,
                                    "raptor.read_quality": {"completeness": "unknown", "rejected_rows": None,
                                                            "reason": "not supplied by audit result API"}})
        if not options.enabled:
            summary = build_operator_summary(context)
            notice = unrefreshed_report_notice(root)
            if notice:
                summary.diagnostics.append(notice)
            print(render_operator_summary(summary), file=sys.stderr, end="")
            return
        document.snapshot_id = context.snapshot_id
        complete_reporting(context, root, document=document, stem="scorecard-audit", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — optional presentation cannot change the native readiness gate
        print("Optional scorecard audit report unavailable (" + type(exc).__name__ + "); native audit retained", file=sys.stderr)

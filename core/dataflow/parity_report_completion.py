"""Developer parity CLI: capture once, then present and optionally export."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from core.reporting.document import ReportContext, StageEnvelope
from core.reporting.options import ReportOptions, add_report_arguments, options_from_args
from core.reporting.service import complete_reporting
from core.reporting.summary import build_operator_summary, render_operator_summary

from .parity_document import build_parity_document
from .sanitizer_cut_parity import ParitySummary
from .sanitizer_cut_parity_report import build_baseline_summary, render_baseline_report


def prepare(options: ReportOptions) -> Path | None:
    if not options.enabled:
        return None
    options = options.validate()
    if options.output is None:
        raise ValueError("Parity baseline exports require --report-output")
    output = options.output
    is_file = options.output_is_file or (bool(output.suffix) and not output.is_dir())
    return output.parent / ("." + output.stem + "-report") if is_file else output


def emit(summary: ParitySummary, options: ReportOptions) -> None:
    """Optional presentation cannot change native fixture/gate behaviour."""
    try:
        root = prepare(options)
        document = build_parity_document(summary, title="Sanitizer-cut parity — first baseline report",
                                         synthetic_baseline=True)
        context = ReportContext("sanitizer-cut-parity", "unknown", target="synthetic baseline",
                                state="partial" if document.extensions["raptor.capture_limited"] else "completed",
                                stages=[StageEnvelope("fixture-measurement", "completed", producer="sanitizer-cut parity baseline",
                                                      reason="One returned synthetic fixture summary; not a real horizon gate window")],
                                expected_stages=["fixture-measurement"], diagnostics=list(document.diagnostics),
                                extensions={"raptor.findings_available": False, "raptor.metrics": dict(document.summary),
                                            "raptor.parity_capture": document.to_dict()})
        if not options.enabled:
            quick = build_operator_summary(context)
            quick.diagnostics.append("Full exports disabled; previous custom destinations are not refreshed.")
            print(render_operator_summary(quick), file=sys.stderr, end="")
            return
        assert root is not None
        document.snapshot_id = context.snapshot_id
        complete_reporting(context, root, document=document, stem="sanitizer-cut-parity", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — optional exports cannot change the native informational exit
        print("Optional parity report unavailable (" + type(exc).__name__ + "); native measurement retained", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Measure the synthetic sanitizer-cut parity baseline and print Markdown. This is not the real horizon gate window. Existing sanitizer-cut settings are preserved.")
    add_report_arguments(parser)
    args = parser.parse_args(argv)
    options = options_from_args(args, parser)
    if not (args.report_format or args.report_output or args.no_report):
        options = ReportOptions(enabled=False)
    try:
        prepare(options)
    except ValueError as exc:
        parser.error(str(exc))
    summary = build_baseline_summary()
    print(render_baseline_report(summary))
    emit(summary, options)
    return 0

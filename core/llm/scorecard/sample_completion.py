"""Optional sample exports over the CLI's single scorecard read."""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

from core.reporting.document import Block, ReportContext, ReportDocument
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.security.redaction import redact_secrets

from .sample_document import build_sample_document
from .scorecard import DecisionClassStats


def prepare(options: ReportOptions, scorecard: Path) -> Path:
    root = scorecard.parent / "portable-reports" / "scorecard-samples"
    if not options.enabled:
        return root
    if options.output is None:
        raise ValueError("Read-only scorecard exports require --report-output")
    options = options.validate()
    chosen = options.output or root
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    overrides = dict(options.filenames)
    for format in options.formats:
        path = chosen if is_file else chosen / overrides.get(format, "scorecard-samples" + get_renderer(format).extension)
        if path.resolve() == scorecard.resolve():
            raise ValueError("Portable samples cannot replace the source scorecard")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def emit(args: argparse.Namespace, stats: list[DecisionClassStats], status: int) -> None:
    options = getattr(args, "_report_options", None)
    if options is None:
        return  # native sample text is already a mechanical human-readable view
    try:
        source = Path(args.path)
        root = prepare(options, source)
        captured = [build_sample_document(stat) for stat in stats[:25]]
        omitted_cells = max(0, len(stats) - len(captured))
        capture_limited = bool(omitted_cells or any(document.extensions.get("raptor.truncated_fields")
                               or document.summary.get("Samples omitted") or document.summary.get("Additional fields omitted")
                               for document in captured))
        notes = ["Only retained samples from this scorecard read are captured; counts are not a complete model-call history. No scorecard reread, routing change or model call was made for reporting.",
                 "No historical run identity or execution coverage is inferred. Sample reasoning is untrusted diagnostic data, not finding validation."]
        if omitted_cells:
            notes.append(f"Portable cell capture limited: {omitted_cells} of {len(stats)} matched cells omitted; original scorecard data is unchanged.")
        if capture_limited:
            notes.append("Some sample fields or records were truncated or omitted from portable capture; inspect the cell limitations. Captured text is not the complete retained sample data.")
        if not stats:
            notes.append("No cells matched the requested selection; this does not establish that the model has no historical calls.")
        if any(not stat.trusted for stat in stats):
            notes.append("Some matched cells came from an unverified read; these samples grant no routing or validation authority.")
        context = ReportContext("scorecard-samples", "unknown", target=redact_secrets(str(args.decision_class))[:2000],
                                state="failed" if status else "partial" if capture_limited or any(not stat.trusted for stat in stats) else "completed",
                                diagnostics=notes, artifacts=[{"path": str(source.resolve()), "role": "source scorecard; preserved"}],
                                extensions={"raptor.findings_available": False, "raptor.metrics": {
                                    "Native exit status": status, "Matched cells": len(stats),
                                    "Retained samples in matched cells": sum(len(stat.disagreement_samples) for stat in stats),
                                    "Unverified matched cells": sum(not stat.trusted for stat in stats)},
                                    "raptor.captured_sample_cells": [document.to_dict() for document in captured],
                                    "raptor.omitted_sample_cells": omitted_cells, "raptor.sample_capture_limited": capture_limited})
        if not options.enabled:
            summary = build_operator_summary(context)
            notice = unrefreshed_report_notice(root)
            if notice:
                summary.diagnostics.append(notice)
            print(render_operator_summary(summary), file=sys.stderr, end="")
            return
        blocks = [Block("section", title=document.title, children=[
            Block("table", columns=["Field", "Value"], rows=[[key, value] for key, value in {**document.metadata, **document.summary}.items()]),
            Block("list", title="Cell limitations", items=document.diagnostics), *document.blocks]) for document in captured]
        document = ReportDocument("Scorecard disagreement samples", "scorecard-samples", context.snapshot_id,
                                  blocks=blocks, diagnostics=notes)
        complete_reporting(context, root, document=document, stem="scorecard-samples", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — optional exports cannot alter native introspection status
        print("Optional scorecard sample report unavailable (" + type(exc).__name__ + "); native sample view retained", file=sys.stderr)

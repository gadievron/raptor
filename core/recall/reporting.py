"""Optional portable recall exports; detector and measurement work stays native."""
from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
import sys

from core.reporting.document import ReportContext
from core.reporting.options import options_from_args
from core.reporting.service import complete_reporting, unrefreshed_report_notice

from .score import LABEL_CLASS, SEGREGATION_NOTE, build_recall_document


def prepare_recall_report(args, out_dir: Path, target: Path) -> None:
    options = getattr(args, "_report_options", None) or options_from_args(args)
    args._report_options = options
    if not options.enabled or not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        return
    destination = options.output or out_dir / "portable-reports"
    root = destination if destination.is_dir() or not destination.suffix else destination.parent
    root = root.resolve()
    if root.is_relative_to(target.resolve()):
        raise ValueError("Portable recall reports must be outside the measured source tree")
    if root.is_relative_to(out_dir.resolve()) and not root.is_relative_to((out_dir / "portable-reports").resolve()):
        raise ValueError("Portable recall reports within a run must use its portable-reports directory; native measurement files are reserved")
    if destination.resolve() == Path(args.manifest).resolve():
        raise ValueError("Portable recall reports cannot replace the ground-truth manifest")


def complete_recall_report(args, report, out_dir: Path, *, warm_present: bool = False):
    options = getattr(args, "_report_options", None) or options_from_args(args)
    if not options.enabled:
        notice = unrefreshed_report_notice(out_dir / "portable-reports")
        if (out_dir / "report.md").exists():
            notice = "Full report files disabled; prior report.md was not refreshed"
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        return None
    try:
        document = build_recall_document(report)
        notes = [SEGREGATION_NOTE, "This is captured detector recall, not a vulnerability validation or a model reliability score. No detector was rerun for export."]
        if warm_present:
            notes.append("Native report.json also contains mechanical-warm suppression measurements; this portable view shows raw recall only and does not project those auxiliary measurements.")
        document.diagnostics.extend(notes)
        context = ReportContext(
            "recall-evaluation", "unknown", target=report.manifest_name, state="completed",
            artifacts=[{"path": str((out_dir / "report.json").resolve())},
                       {"path": str((out_dir / "report.md").resolve())},
                       {"path": str(Path(args.manifest).resolve())}],
            diagnostics=notes,
            extensions={"raptor.findings_available": False,
                        "raptor.metrics": {"Expected findings": report.expected_total, "Found expected findings": report.found_total,
                                           "Labelled-clean region hits": report.clean_region_fp_count},
                        "raptor.measurement_role": LABEL_CLASS,
                        "raptor.warm_measurements_not_projected": warm_present,
                        "raptor.recall_metadata": document.metadata,
                        "raptor.result_sections": [asdict(block) for block in document.blocks],
                        "raptor.recall_summary": document.summary},
        )
        document.snapshot_id = context.snapshot_id
        root = out_dir / "portable-reports"
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        return complete_reporting(context, root, document=document, stem="recall-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as exc:
        print("Optional recall export unavailable (" + type(exc).__name__ + "); native measurement retained", file=sys.stderr)
        return None

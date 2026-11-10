"""Quick views and optional publication over a captured offline replay."""
from __future__ import annotations

from pathlib import Path
import sys
from typing import TYPE_CHECKING

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary

if TYPE_CHECKING:
    from .replay import ReplayReport


def prepare(options: ReportOptions | None, sources: list[Path], native_output: Path | None) -> Path:
    inputs = {path.resolve() for path in sources}
    native = {native_output.resolve(), native_output.with_suffix(native_output.suffix + ".json").resolve()} if native_output else set()
    if native & inputs:
        raise ValueError("Replay output cannot replace a source report")
    root = (native_output.parent / ("." + native_output.stem + "-portable")) if native_output else Path("out/panel-replay/portable")
    if options is None or not options.enabled:
        return root
    if options.output is None and native_output is None:
        raise ValueError("Replay exports require --report-output or a native --out destination")
    options = options.validate()
    chosen = options.output or root
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    overrides = dict(options.filenames)
    for format in options.formats:
        path = chosen if is_file else chosen / overrides.get(format, "panel-replay-summary" + get_renderer(format).extension)
        if path.resolve() in inputs | native:
            raise ValueError("Portable replay output cannot replace source or native report artifacts")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def complete(report: ReplayReport, options: ReportOptions | None, native_output: Path | None) -> None:
    from .replay_document import build_document
    sources = [Path(path) for path in report.sources]
    root = prepare(options, sources, native_output)
    metrics = {"Source reports": len(report.sources), "Panel records": report.total_panels,
               "Findings with usable panel": report.total_findings_with_panel,
               "No recorded verdict (excluded from flip rates)": report.n_no_recorded_verdict,
               "Flip rate": report.flip_rate, "Flips to exploitable rate": report.flip_to_exploitable_rate,
               "Flips to not-exploitable rate": report.flip_to_not_exploitable_rate}
    context = ReportContext("panel-replay", "unknown", target="recorded panel corpus", state="completed",
                            diagnostics=["Offline estimator comparison only; rendering neither validates findings nor changes recorded verdicts.",
                                         "No historical run identity or execution coverage is inferred. Findings without a recorded verdict are excluded from flip-rate denominators."],
                            artifacts=[{"path": str(path.resolve()), "role": "replay source report"} for path in sources]
                                      + ([{"path": str(native_output.resolve()), "role": "native replay report"},
                                          {"path": str(native_output.with_suffix(native_output.suffix + '.json').resolve()), "role": "native replay JSON"}] if native_output else []),
                            extensions={"raptor.findings_available": False, "raptor.metrics": metrics})
    if options is None or not options.enabled:
        summary = build_operator_summary(context)
        notice = unrefreshed_report_notice(root)
        if notice:
            summary.diagnostics.append(notice)
        print(render_operator_summary(summary), file=sys.stderr, end="")
        return
    document = build_document(report)
    context.diagnostics.extend(document.diagnostics)
    document.snapshot_id = context.snapshot_id
    complete_reporting(context, root, document=document, stem="panel-replay-summary", options=options, stream=sys.stderr)

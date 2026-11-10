"""Programmatic completion hook. Reports are optional; the quick view is not."""
from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
from typing import Callable, TextIO

from core.security.log_sanitisation import sanitise_for_terminal

from .builders import build_document
from .document import Block, ReportContext, ReportDocument
from .options import ReportOptions
from .summary import OperatorSummary, build_operator_summary, render_operator_summary
from .writer import Publication, publish_report, publish_summary, write_summary


@dataclass
class ReportingResult:
    summary: OperatorSummary
    publication: Publication | None = None
    diagnostics: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def capture_failure_summary(kind: str, run_id: str, target: str, output_dir: Path, *, cause: Exception,
                            artifacts: list[dict] | None = None, stem: str = "report", stream=None) -> ReportingResult:
    """Keep a fresh minimal handoff when domain capture itself is unavailable."""
    message = f"Structured report capture failed ({type(cause).__name__}); original command results are retained"
    context = ReportContext(kind, run_id, target=target, state="partial", diagnostics=[message],
                            artifacts=list(artifacts or []), extensions={"raptor.findings_available": False})
    result = complete_reporting(context, output_dir, stem=stem, options=ReportOptions(enabled=False), stream=stream)
    result.errors.append(message)
    result.diagnostics.append(message)
    if stream is None:
        logging.getLogger(__name__).warning("%s", message)
    return result


def unrefreshed_report_notice(output_dir: Path) -> str | None:
    """A disabled export retains previous files; never parse them as current."""
    try:
        present = (Path(output_dir) / "reporting-manifest.json").exists()
    except OSError:
        return "Full report files disabled; prior artifact freshness could not be checked"
    if present:
        return "Full report files disabled; prior report artifacts were not refreshed"
    return None


def complete_reporting(context: ReportContext, output_dir: Path, *, stem: str = "report",
                       options: ReportOptions | None = None, document: ReportDocument | None = None,
                       blocks: list[Block] | None = None, stream: TextIO | None = None,
                       show_suppressed: bool = False, expected_generation: str | None = None,
                       document_factory: Callable[[ReportContext], ReportDocument] | None = None) -> ReportingResult:
    options = (options or ReportOptions()).validate()
    try:
        summary = build_operator_summary(context, show_suppressed=show_suppressed)
    except (ValueError, TypeError, KeyError) as exc:
        summary = OperatorSummary(f"RAPTOR {context.kind.title()} Summary", context.target, "partial",
                                  len(context.findings), [], {},
                                  diagnostics=[f"Detailed summary unavailable ({type(exc).__name__}); inspect source artifacts"])
    result = ReportingResult(summary)
    if not options.enabled:
        notice = unrefreshed_report_notice(output_dir)
        if notice:
            summary.diagnostics.append(notice)
    # Print useful results before optional persistence/rendering. A failed
    # filesystem cannot take the completed scanner's quick view away.
    if stream is not None:
        print(render_operator_summary(summary), file=stream, end="")
    try:
        if options.enabled:
            document = document or (document_factory(context) if document_factory else build_document(context, summary=summary, blocks=blocks))
            result.publication = publish_report(context, document, output_dir, stem=stem, options=options,
                                                expected_generation=expected_generation, summary=summary,
                                                summary_writer=write_summary)
            result.diagnostics.extend(result.publication.diagnostics)
            result.errors.extend(result.publication.failed_formats)
        else:
            publish_summary(summary, output_dir, context=context, expected_generation=expected_generation,
                            summary_writer=write_summary)
    except (OSError, ValueError, TypeError) as exc:
        result.diagnostics.append(f"Report persistence failed ({type(exc).__name__}); analysis results are retained")
        result.errors.append(result.diagnostics[-1])
    if result.diagnostics:
        result.summary.diagnostics.extend(result.diagnostics)
        try:
            guard = result.publication.generation if result.publication and result.publication.committed else expected_generation
            publish_summary(result.summary, output_dir, context=context, expected_generation=guard,
                            summary_writer=write_summary)
        except (OSError, ValueError, TypeError):
            pass  # the original persistence failure remains visible below
        if stream is not None:
            for diagnostic in result.diagnostics:
                print(f"Warning: {sanitise_for_terminal(str(diagnostic), max_len=2000)}", file=stream)
        else:
            for diagnostic in result.diagnostics:
                logging.getLogger(__name__).warning("%s", sanitise_for_terminal(str(diagnostic), max_len=2000))
    return result

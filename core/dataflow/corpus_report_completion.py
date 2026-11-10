"""Optional exports of one captured trust-corpus query snapshot."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import ReportContext, StageEnvelope, digest
from core.reporting.options import ReportOptions
from core.reporting.renderers import get_renderer
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.reporting.summary import build_operator_summary, render_operator_summary
from core.security.redaction import redact_secrets

from .report_documents import build_corpus_document
from .trust_corpus_report import CorpusReport


def prepare(options: ReportOptions, source: Path) -> Path:
    root = source.parent / "portable-reports" / "trust-corpus"
    if not options.enabled:
        return root
    options = options.validate()
    if options.output is None:
        raise ValueError("Read-only corpus exports require --report-output")
    chosen = options.output
    is_file = options.output_is_file or (bool(chosen.suffix) and not chosen.is_dir())
    for format in options.formats:
        filename = dict(options.filenames).get(format, "trust-corpus" + get_renderer(format).extension)
        path = chosen if is_file else chosen / filename
        if path.resolve() == source.resolve():
            raise ValueError("Portable corpus output cannot replace the source database")
    return chosen.parent / ("." + chosen.stem + "-report") if is_file else chosen


def emit(report: CorpusReport, source: Path, options: ReportOptions) -> None:
    try:
        root = prepare(options, source)
        document = build_corpus_document(report)
        displayed_source = redact_secrets(str(source))
        target = displayed_source[:2000]
        if len(displayed_source) > 2000:
            document.diagnostics.append("Source database display truncated to 2000 characters; the context artifact reference retains the source path.")
            document.extensions["raptor.capture_limited"] = True
        document.metadata["Source database"] = target
        document.metadata["Whole corpus completion"] = "not supplied"
        document.snapshot_id = ""
        document.snapshot_id = digest(document.to_dict())
        read_state = report.read_state if report.read_state in {"completed", "failed", "unknown"} else "unknown"
        limited = document.extensions["raptor.capture_limited"]
        errors = sum(report.pipeline_errors.values())
        context = ReportContext("trust-corpus", "unknown", target=target,
                                state="partial" if read_state == "failed" or limited or errors else "completed" if read_state == "completed" else "unknown",
                                stages=[StageEnvelope("source-read", read_state, producer="trust-corpus query",
                                                      reason=str(document.metadata["Source read reason"]),
                                                      extensions={"raptor.metrics": {"captured_rows": report.read_rows}})],
                                expected_stages=["source-read"], diagnostics=list(document.diagnostics),
                                artifacts=[{"path": str(source.resolve()), "role": "read-only source database; preserved"}],
                                extensions={"raptor.findings_available": False, "raptor.metrics": dict(document.summary),
                                            "raptor.corpus_capture": document.to_dict(), "raptor.corpus_completion": "unknown"})
        if not options.enabled:
            summary = build_operator_summary(context)
            summary.diagnostics.append("Full exports disabled; previous custom destinations are not refreshed.")
            notice = unrefreshed_report_notice(root)
            if notice:
                summary.diagnostics.append(notice)
            print(render_operator_summary(summary), file=sys.stderr, end="")
            return
        document.snapshot_id = context.snapshot_id
        complete_reporting(context, root, document=document, stem="trust-corpus", options=options, stream=sys.stderr)
    except Exception as exc:  # noqa: BLE001 — optional files cannot alter the native snapshot display
        print("Optional trust-corpus report unavailable (" + type(exc).__name__ + "); native snapshot retained", file=sys.stderr)

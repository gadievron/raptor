"""Portable diagrams captured from the same native directory render."""
from __future__ import annotations

from pathlib import Path
import sys

from core.reporting.document import Block
from core.reporting.results import NativeResult
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.security.redaction import redact_secrets

from .reporting import directory_blocks_from_rendered

_MAX_CAPTURE_CHARS = 1_000_000


def complete_diagram_report(args, content: str | None, out_dir: Path, target: str | None, sources: list[Path]):
    options = args._report_options
    if not options.enabled:
        notice = unrefreshed_report_notice(out_dir)
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if content is None or not (args.report_format or args.report_output):
        return None
    if not getattr(args, "_source_capture_complete", True):
        print("Portable diagram export unavailable (source reference limit exceeded); native output retained and prior portable files were not refreshed", file=sys.stderr)
        return None
    try:
        capture_complete = len(content) <= _MAX_CAPTURE_CHARS
        captured_content = redact_secrets(content) if capture_complete else ""
        secrets_redacted = capture_complete and captured_content != content
        blocks = (directory_blocks_from_rendered(captured_content, include_findings_summary=True) if capture_complete else
                  [Block("paragraph", text="Portable diagram capture exceeded its size limit; complete native output remains available.",
                         extensions={"raptor.diagram_capture_limited": True})])
        diagram_count = sum(block.kind == "diagram" for block in blocks)
        if not blocks:
            blocks = [Block("paragraph", text="No diagram sections were captured. Native output retains any source availability notes.")]
        notes = ["This receipt freezes one native directory render. No extra analysis, graph query or second render is performed for reporting.",
                 "Renderer completion does not establish input completeness or validation. Native section errors, provenance and truncation warnings remain attached to the captured diagrams."]
        if not capture_complete:
            notes.append("Portable diagram capture exceeded its size limit; complete native output remains available.")
        notes.append("Portable diagram content uses the shared secret-redaction policy; original native output is retained separately.")
        result = NativeResult("diagrams", redact_secrets(target or str(out_dir)), "unknown", {"captured_diagrams": diagram_count, "capture_complete": capture_complete, "secrets_redacted": secrets_redacted},
                              state="completed" if capture_complete else "partial", blocks=blocks, metrics={"Diagrams captured": diagram_count},
                              artifacts=[{"path": str((out_dir / "diagrams.md").resolve()),
                                          "role": "protected native output; previous contents are not imported as evidence"},
                                         *({"path": str(path.expanduser().resolve())} for path in dict.fromkeys(sources))],
                              diagnostics=notes)
        context, document = result.build()
        captured_snapshot_id = document.snapshot_id
        for block in document.blocks:
            if block.kind == "diagram":
                block.source_refs = [captured_snapshot_id]
                block.extensions["input_snapshot_id"] = captured_snapshot_id
        root = out_dir
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        return complete_reporting(context, root, document=document, stem="diagram-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError, KeyError) as exc:
        print("Optional diagram report unavailable (" + type(exc).__name__ + "); native diagrams retained", file=sys.stderr)
        return None

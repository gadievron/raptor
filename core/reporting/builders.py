"""Domain-neutral document construction and legacy spec compatibility."""
from __future__ import annotations

import json

from .document import Block, ReportContext, ReportDocument
from .spec import ReportSpec
from .summary import OperatorSummary, build_operator_summary


def build_document(context: ReportContext, *, title: str | None = None,
                   summary: OperatorSummary | None = None, blocks: list[Block] | None = None) -> ReportDocument:
    summary = summary or build_operator_summary(context)
    sections = [Block("paragraph", text=f"Outcome: {summary.state}." + (f" Captured findings: {summary.total}." if summary.findings_available else " Structured command result captured."))]
    if context.findings:
        sections.append(Block("table", title="Findings", columns=["Ref", "Tool", "Rule", "Location", "Status", "Scanner level", "Security severity", "Scanner security score", "Suppressed"], rows=[
            [f"F{i:05d}", f.get("tool"), f.get("rule_id"), f"{f.get('file') or 'unknown'}" + (f":{f['line']}" if f.get("line") else ""),
             f.get("status", "Unknown"), f.get("scanner_level"), f.get("severity"), f.get("security_score"), bool(f.get("suppressed"))]
            for i, f in enumerate(context.findings, 1)
        ]))
        details = []
        for i, f in enumerate(context.findings, 1):
            content = [Block("paragraph", text=f.get("message") or "No scanner message.")]
            scanner_metadata = [[label, f[key]] for key, label in (
                ("function", "Function"), ("rule_scope", "Rule namespace"),
                ("end_line", "End line"), ("start_column", "Start column"), ("end_column", "End column"),
            ) if f.get(key) is not None]
            if scanner_metadata:
                content.append(Block("table", title="Scanner location and namespace", columns=["Field", "Value"], rows=scanner_metadata))
            if f.get("snippet"):
                content.append(Block("code", text=f["snippet"]))
            if f.get("dataflow_path"):
                content.append(Block("code", title="Recorded data flow", text=json.dumps(f["dataflow_path"], ensure_ascii=True, indent=2), language="json"))
            details.append(Block("section", title=f"F{i:05d}: {f.get('rule_id', 'unknown')}", children=content, source_refs=[f["occurrence_ref"]]))
        sections.append(Block("section", title="Finding details", children=details))
    if context.stages:
        sections.append(Block("table", title="Stage Results", columns=["Stage", "State", "Reason", "Duration seconds"],
                              rows=[[s.stage_id, s.state, s.reason, s.duration_seconds] for s in context.stages]))
        for s in context.stages:
            if s.coverage:
                sections.append(Block("code", title=f"Coverage: {s.stage_id}", language="json", text=json.dumps(s.coverage, ensure_ascii=True, indent=2)))
    scan_metrics = context.extensions.get("raptor.scan_metrics")
    if isinstance(scan_metrics, dict):
        sections.append(Block("code", title="Recorded scan execution and coverage", language="json",
                              text=json.dumps(scan_metrics, ensure_ascii=True, indent=2, sort_keys=True)))
    sections.extend(blocks or [])
    if summary.actions:
        sections.append(Block("list", title="Next steps", items=summary.actions))
    if context.artifacts:
        sections.append(Block("list", title="Source artifacts", items=[str(a.get("path") or a.get("uri") or "unavailable") for a in context.artifacts]))
    return ReportDocument(title or f"RAPTOR {context.kind.title()} Report", context.kind, context.snapshot_id,
                          metadata={"Target": context.target, "Run": context.run_id, "Pass": context.pass_id, "Attempt": context.attempt_id,
                                    "Captured at": context.generated_at or "not recorded"},
                          summary=({"Captured findings": summary.total, **summary.counts} if summary.findings_available else {}), blocks=sections,
                          diagnostics=list(dict.fromkeys([*context.diagnostics, *summary.diagnostics,
                                                         *(note for stage in context.stages for note in stage.diagnostics)])),
                          extensions={"raptor.summary": summary.to_dict(), "raptor.artifacts": context.artifacts,
                                      "raptor.references": {f"F{i:05d}": f["occurrence_ref"] for i, f in enumerate(context.findings, 1)}})


def document_from_spec(spec: ReportSpec, context: ReportContext) -> ReportDocument:
    """Preserve old producer-built Markdown explicitly, without claiming portability."""
    blocks = []
    def section(s):
        if s.blocks is not None:
            return Block("section", title=s.title, children=s.blocks)
        return Block("legacy_markdown", title=s.title, text=s.content)
    if spec.table_columns:
        blocks.append(Block("table", columns=spec.table_columns, rows=[list(r) for r in spec.table_rows]))
    if spec.table_note:
        blocks.append(Block("paragraph", text=spec.table_note))
    if spec.detail_sections:
        blocks.append(Block("section", title=spec.detail_title, children=[section(s) for s in spec.detail_sections]))
    blocks.extend(section(s) for s in spec.sections)
    if context.findings:
        blocks.append(Block("table", title="Finding references", columns=["Ref", "Original ID", "Rule / type"],
                            rows=[[f"F{i:05d}", f.get("source_id"), f.get("rule_id")] for i, f in enumerate(context.findings, 1)]))
    if spec.output_files:
        blocks.append(Block("list", title="Output Files", items=spec.output_files))
    return ReportDocument(spec.title, context.kind, context.snapshot_id, metadata=spec.metadata, summary=spec.summary,
                          blocks=blocks, diagnostics=[*context.diagnostics, *spec.warnings],
                          extensions={"raptor.summary": build_operator_summary(context).to_dict(),
                                      "raptor.artifacts": context.artifacts,
                                      "raptor.legacy_sections": any(s.blocks is None for s in [*spec.detail_sections, *spec.sections])})

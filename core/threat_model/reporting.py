"""Portable assessment presentation over the canonical project threat model."""
from __future__ import annotations

import heapq
from dataclasses import asdict
from pathlib import Path
import sys

from core.reporting.document import Block, ReportContext, ReportDocument, digest
from core.reporting.options import options_from_args
from core.reporting.service import complete_reporting, unrefreshed_report_notice
from core.security.redaction import redact_secrets

from . import ThreatModel, _mermaid_id, _mermaid_label, _read_raptor_logo, _safe_for_render, lint_model


def _cell(value) -> str:
    return redact_secrets(_safe_for_render(value))


def _risk(threat: dict) -> int:
    try:
        return int(threat.get("risk_score") or 0)
    except (TypeError, ValueError):
        return 0


def build_threat_model_document(model: ThreatModel, *, lint: list[dict] | None = None,
                                drift: dict | None = None) -> ReportDocument:
    """Capture the assessment view without changing model or outcome semantics."""
    lint = lint if lint is not None else lint_model(model)
    top = heapq.nlargest(10, model.threats, key=_risk)
    blocks = []
    logo = _read_raptor_logo()
    if logo:
        blocks.append(Block("code", text=logo, language="text"))
    blocks.append(Block("table", title="Executive View", columns=["Measure", "Count"], rows=[
        ["Assets", len(model.assets)], ["Entry points", len(model.entry_points)],
        ["Trust boundaries", len(model.trust_boundaries) + len(model.trust_zones)],
        ["Data flows", len(model.data_flows)], ["Threats", len(model.threats)],
        ["Controls", len(model.controls)], ["Evidence records", len(model.evidence)],
        ["Open quality issues", sum(issue.get("severity") in ("error", "warning") for issue in lint)],
    ]))
    blocks.append(Block("table", title="Top Threats", columns=["ID", "Status", "Risk", "Severity", "Title"],
                        rows=[[_cell(t.get("id", "?")), _cell(t.get("status", "needs_evidence")),
                               _cell(t.get("risk_score", 0)), _cell(t.get("severity", "unknown")),
                               _cell(t.get("title", "Untitled threat"))] for t in top])
                  if top else Block("paragraph", title="Top Threats", text="No threats recorded yet."))
    blocks.append(Block("table", title="Evidence Loop", columns=["ID", "Oracle", "Status", "Summary", "Recorded reproducible", "Recorded provenance flag"],
                        rows=[[_cell(ev.get("id", "?")), _cell(ev.get("oracle", "?")),
                               _cell(ev.get("status", "?")), _cell(ev.get("summary", "no summary")),
                               _cell(ev.get("reproducible", "not recorded")),
                               _cell(ev["raw"].get("provenance_verified", "not recorded")) if isinstance(ev.get("raw"), dict) else "not recorded"]
                              for ev in model.evidence[:20]])
                  if model.evidence else Block("paragraph", title="Evidence Loop", text="No oracle evidence linked yet."))
    blocks.append(Block("table", title="Quality Gates", columns=["Severity", "Message"],
                        rows=[[_cell(str(issue.get("severity", "info")).title()), _cell(issue.get("message", ""))]
                              for issue in lint])
                  if lint else Block("paragraph", title="Quality Gates", text="No quality issues found."))
    if drift:
        children = []
        for key in ("new_entry_points", "missing_entry_points", "new_trust_boundaries",
                    "missing_trust_boundaries", "new_unchecked_flows"):
            values = drift.get(key) or []
            children.append(Block("section", title=f"{key}: {len(values)}", children=[
                Block("list", items=[_cell(value) for value in values[:8]]),
                *([Block("paragraph", text=f"{len(values) - 8} additional records omitted from this view.")] if len(values) > 8 else []),
            ]))
        blocks.append(Block("section", title="Drift", children=children))
    mermaid = ["flowchart LR"]
    equivalent = []
    for flow in model.data_flows[:25]:
        src = _mermaid_id(str(flow.get("source") or flow.get("id") or "source"))
        sink = _mermaid_id(str(flow.get("sink") or "sink"))
        source_label = _cell(flow.get("source") or "Source")
        sink_label = _cell(flow.get("sink") or "Sink")
        label = _cell(flow.get("id") or "")
        mermaid.append(f'  {src}["{_mermaid_label(source_label)}"] -->|"{_mermaid_label(label)}"| {sink}["{_mermaid_label(sink_label)}"]')
        equivalent.append(f"{source_label} → {sink_label} ({label})")
    if not model.data_flows:
        mermaid.append('  A["No data flows recorded"]')
        equivalent.append("No data flows recorded.")
    blocks.append(Block("diagram", title="Mermaid", text="\n".join(equivalent),
                        extensions={"mermaid": "\n".join(mermaid),
                                    "raptor.recorded_flows": len(model.data_flows),
                                    "raptor.displayed_flows": min(25, len(model.data_flows))}))
    notes = ["Threat statuses, risk scores and oracle labels are recorded model fields, not new validation verdicts. Report generation does not execute an oracle or update the model.",
             "Reproducibility and provenance flags are recorded model claims; no new reproduction or authentication is performed by report generation."]
    for label, total, shown in (("Threats", len(model.threats), 10), ("Evidence records", len(model.evidence), 20),
                                ("Diagram flows", len(model.data_flows), 25)):
        if total > shown:
            notes.append(f"{label}: showing {shown} of {total}; remaining records stay in the canonical threat-model JSON.")
    document = ReportDocument("Threat Model Report", "threat-model", "", metadata={
        "Project": _cell(model.project_name), "Target": _cell(model.target), "Updated": _cell(model.updated_at),
        "Source": _cell(model.source),
    }, blocks=blocks, diagnostics=notes)
    document.snapshot_id = digest(document.to_dict())
    return document


def complete_project_threat_model_report(args, model: ThreatModel, *, lint, drift, json_path: Path,
                                        markdown_path: Path, report_path: Path):
    """Export the selected project assessment without adopting run lineage."""
    options = getattr(args, "_report_options", None) or options_from_args(args)
    root = json_path.parent / "threat-model-reports"
    if not options.enabled:
        notice = unrefreshed_report_notice(root)
        if report_path.exists():
            notice = "Full report files disabled; prior threat-model report was not refreshed"
        if notice:
            print("Warning: " + notice, file=sys.stderr)
        return None
    if not (getattr(args, "report_format", None) or getattr(args, "report_output", None)):
        return None
    try:
        document = build_threat_model_document(model, lint=lint, drift=drift)
        artifacts = [{"path": str(path.resolve())} for path in (json_path, markdown_path, report_path)]
        if args.context_map:
            artifacts.append({"path": str(Path(args.context_map).resolve())})
        context = ReportContext(
            "threat-model", "unknown", target=_cell(model.target), state="completed", artifacts=artifacts,
            diagnostics=[*document.diagnostics, "This project assessment is a captured view; historical run metadata and lifecycle identity are not adopted."],
            extensions={"raptor.findings_available": False,
                        "raptor.metrics": {"Recorded threats": len(model.threats), "Recorded controls": len(model.controls),
                                           "Recorded evidence": len(model.evidence), "Quality issues": len(lint)},
                        "raptor.result_sections": [asdict(block) for block in document.blocks],
                        "raptor.threat_model_metadata": document.metadata},
        )
        document.diagnostics = context.diagnostics.copy()
        document.snapshot_id = context.snapshot_id
        if options.output is not None:
            root = options.output if options.output.is_dir() or not options.output.suffix else options.output.parent / ("." + options.output.stem + "-report")
        return complete_reporting(context, root, document=document, stem="threat-model-report", options=options, stream=sys.stderr)
    except (OSError, ValueError, TypeError) as exc:
        print("Optional threat-model export unavailable (" + type(exc).__name__ + "); native assessment retained", file=sys.stderr)
        return None

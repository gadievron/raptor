"""Portable audit presentation over an already synthesized domain report.

No artifact discovery or adjudication occurs here. The audit report remains the
authority for grouping, completeness, residue, and recorded evidence tiers.
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from core.reporting.adapters import native_findings
from core.reporting.document import Block, MAX_FINDINGS, ReportContext, ReportDocument, json_value
from core.reporting.results import result_blocks
from core.reporting.summary import build_operator_summary


def finding_block(finding, reference=None):
    from .report import _tier_title
    tier = _tier_title(finding.get("evidence_tier", "heuristic"))
    children = [Block("table", columns=["Attribute", "Value"], rows=[
        ["File", f"{finding.get('file', '?')}:{finding.get('line', '?')}"],
        ["Depth", finding.get("depth", "?")], ["Evidence", tier],
    ])]
    if reference:
        children[0].rows.insert(0, ["Report ref", reference[0]])
    if finding.get("provisional"):
        children.append(Block("paragraph", text="Provisional at time of writing — the run was interrupted before the post-loop pass could confirm or retract this promotion."))
    children.extend(result_blocks(finding, title="Recorded finding evidence"))
    return Block("section", title=f"{finding.get('id', 'FIND-???')}: {finding.get('title', 'Untitled')} ({tier})", children=children,
                 source_refs=[reference[1]] if reference else [])


def build_audit_document(report, out_dir: Path, *, target_path=None, model="", duration_minutes=0.0,
                         cost_usd=0.0, capabilities=None, suppressions_count=0):
    from .report import (_completeness_lines, _evidence_distribution, _group_findings_by_tree,
                         _tier_title, _TREE_CLASS_GROUP_LABELS, format_residue_lines)
    report = json_value(report)
    findings = report.get("findings", [])
    stats = report.get("stats", {})
    metadata = {"Target": str(target_path or report.get("target", "")), "Model": model}
    if duration_minutes > 0:
        metadata["Duration"] = f"{duration_minutes:.0f} minutes"
    if cost_usd > 0:
        metadata["Cost"] = f"${cost_usd:.2f}"
    reviewed = stats.get("reviewed", 0)
    total = reviewed + report.get("gaps_remaining", 0)
    if total > 0:
        metadata["Functions reviewed"] = f"{reviewed:,} of {total:,} ({reviewed * 100 / total:.1f}%)"
    completeness = report.get("completeness") or {}
    diagnostics = _completeness_lines(report) + format_residue_lines(report)
    if len(findings) > MAX_FINDINGS:
        diagnostics.append(f"Finding presentation truncated to {MAX_FINDINGS} of {len(findings)}; complete domain report retained in report-context.json.")
    artifacts = [{"path": str(out_dir / name)} for name in ("audit-report.json", "findings.json", "findings-graded.json", ".raptor-run.json")]
    if report.get("knowledge_processing") is not None:
        artifacts.append({"path": str(out_dir / "knowledge-results.json")})
    context = ReportContext("audit", out_dir.name, target=metadata["Target"], state="partial" if completeness.get("partial") else "unknown",
                            findings=native_findings(findings[:MAX_FINDINGS], producer="audit", run_id=out_dir.name),
                            diagnostics=diagnostics, artifacts=artifacts,
                            extensions={"raptor.audit": report, "raptor.metrics": stats,
                                        "raptor.audit_presentation": {"metadata": metadata, "capabilities": capabilities or {},
                                                                      "duration_minutes": duration_minutes, "cost_usd": cost_usd,
                                                                      "suppressions_count": suppressions_count},
                                        "raptor.accounting": {"recorded_findings": len(findings), "captured_findings": min(len(findings), MAX_FINDINGS)}})
    blocks = []
    if diagnostics:
        blocks.append(Block("section", title="Run completeness", children=[Block("paragraph", text=line) for line in _completeness_lines(report)]))
    not_attempted = report.get("not_attempted")
    if not_attempted:
        blocks.append(Block("paragraph", text=f"Not attempted ({not_attempted.get('reason', 'budget')}): {int(not_attempted.get('count', 0) or 0):,} functions (see not-attempted.json; gap-eligible next run)"))
        blocks.extend(result_blocks(not_attempted, title="Not attempted (gap-eligible next run; see not-attempted.json)"))
    edge = report.get("edge_obligations")
    if edge:
        edge_blocks = [Block("paragraph", text=f"Tier-1 (boundary) edges: {edge.get('tier1_total', 0)} obligated, {edge.get('tier1_unreviewed', 0)} unreviewed"),
                       Block("paragraph", text=f"Tier-2 (on-path) edges folded into caller reviews: {edge.get('tier2_total', 0)}")]
        degraded = (edge.get("stats") or {}).get("degraded") or []
        if "no-domain-model" in degraded:
            edge_blocks.append(Block("paragraph", text="Degraded — no domain model: contract review of aliasing/ownership bug classes needs the knowledge layer; run a study pass or seed concepts/domain-model.json and re-audit (context-staleness re-queues affected verdicts)."))
        if edge.get("blind_spot_count"):
            edge_blocks.append(Block("paragraph", text=f"Blind spots: {edge['blind_spot_count']} call site(s) on attack paths the static graph cannot follow. Manual review required; a percentage cannot be taken over edges that cannot be enumerated. See edge-obligations.json."))
        edge_blocks.extend(result_blocks(edge, title="Recorded boundary, on-path, and blind-spot evidence"))
        blocks.append(Block("section", title="Edge obligations (--edges)", children=edge_blocks))
    severity = Counter(str(f.get("severity", "medium")).lower() for f in findings)
    blocks.append(Block("paragraph", title="Summary", text=(f"{len(findings)} findings: " + ", ".join(f"{v} {k}" for k, v in sorted(severity.items())) + ".") if findings else "No findings."))
    residue = format_residue_lines(report)
    if residue:
        blocks.append(Block("section", title="Unverified residue", children=[Block("paragraph", text=s) for s in residue]))
    if capabilities:
        blocks.append(Block("table", title="Capabilities used", columns=["Tool", "Available"], rows=[[k, "Yes" if v else "No"] for k, v in sorted(capabilities.items())]))
    production, grouped = _group_findings_by_tree(findings[:MAX_FINDINGS])
    references = {id(f): (f"F{i:05d}", context.findings[i - 1]["occurrence_ref"]) for i, f in enumerate(findings[:MAX_FINDINGS], 1)}
    if findings:
        blocks.append(Block("section", title="Findings", children=[
            *(finding_block(f, references[id(f)]) for f in production),
            *(Block("section", title=f"{_TREE_CLASS_GROUP_LABELS[tree]} findings ({len(group)})", children=[finding_block(f, references[id(f)]) for f in group]) for tree, group in grouped),
        ]))
    dark = report.get("dark_findings", [])
    if dark:
        blocks.append(Block("section", title=f"Dark findings ({len(dark)}) — need concrete verification", children=[
            Block("paragraph", text="No mechanical channel can decide these classes. They are exported in findings-graded.json with needs_validation: true — run /validate to judge them. Dark hypotheses are not confirmed findings or refutations."),
            *result_blocks(dark, title="Recorded dark hypotheses"),
        ]))
    dist = _evidence_distribution(findings)
    blocks.append(Block("table", title="Evidence distribution", columns=["Tier", "Count"], rows=[[_tier_title(k), v] for k, v in sorted(dist.items())]) if dist else Block("paragraph", title="Evidence distribution", text="No evidence recorded."))
    if suppressions_count > 0:
        blocks.append(Block("paragraph", title="Suppressions", text=f"{suppressions_count} findings suppressed by binary oracle (function absent from binary). See suppressions.jsonl for details."))
    sweep = report.get("decomp_sweep")
    if sweep:
        conf = sweep.get("conformance") or {}
        rate = conf.get("parsed_rate")
        text = (f"{rate:.0%} of {int(conf.get('files_total', 0) or 0)} decomp-tree file(s) parsed" if isinstance(rate, (int, float)) else
                "parse rate unavailable (conformance metric present but no tool leg could measure — see decomp-tree-conformance.json)" if conf else
                "parse rate unavailable (no conformance metric recorded for the swept tree)")
        blocks.append(Block("section", title="Decomp-tree sweep", children=[
            Block("paragraph", text="Skipped — " + str(sweep.get("skip_reason") or "unknown reason") if sweep.get("skipped") else
                  f"Sweep coverage: {text}; {sweep.get('rules_run', 0)} rule file(s) run; {sweep.get('findings_total', 0)} match(es) — {sweep.get('mapped', 0)} mapped to functions ({sweep.get('journal_rows', 0)} journal row(s)), {sweep.get('unmapped', 0)} unmapped (recorded in decomp-sweep.json, never dropped)."),
            Block("paragraph", text=f"{int(conf.get('quarantine_total', 0) or 0)} tree file(s) quarantined as unparseable. {int(sweep.get('rules_errored', 0) or 0)} rule file(s) errored — their silence is not coverage. See decomp-tree-conformance.json and decomp-sweep.json."),
            *result_blocks(sweep, title="Recorded sweep evidence"),
        ]))
    gaps = report.get("analysis_gaps")
    if gaps:
        blocks.append(Block("section", title="Analysis Gaps", children=[Block("paragraph", text=f"{gaps['count']} file record(s) NOT analysed — a parser abandoned them. See analysis-gaps.jsonl for per-file records."), *result_blocks(gaps, title="Recorded parser gaps")]))
    evaluation = report.get("evaluation")
    if evaluation:
        blocks.append(Block("section", title="Evaluation", children=[
            Block("paragraph", text=f"Detection: {evaluation.get('recall', 0):.0%} Precision: {evaluation.get('precision', 0):.0%} F1: {evaluation.get('f1', 0):.2f}"),
            *result_blocks(evaluation, title="Recorded measurements by evidence source and failure mode"),
        ]))
    reads = report.get("unrecorded_reads", [])
    if reads:
        blocks.extend(result_blocks(reads, title=f"Unrecorded reads ({sum(len(u['functions']) for u in reads)} functions in {len(reads)} files)"))
    summary = build_operator_summary(context)
    return context, ReportDocument("Audit Report", "audit", context.snapshot_id, metadata=metadata, blocks=blocks,
                                   extensions={"raptor.summary": summary.to_dict(), "raptor.artifacts": artifacts,
                                               "raptor.references": {alias: ref for alias, ref in references.values()}})

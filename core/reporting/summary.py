"""Deterministic operator summaries, independent of optional report files."""
from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
import shutil

from core.security.log_sanitisation import sanitise_for_terminal
from core.security.markdown_render import md_inline, md_prose
from .document import ReportContext


@dataclass
class OperatorSummary:
    title: str
    target: str
    state: str
    total: int
    rows: list[dict]
    counts: dict[str, int]
    diagnostics: list[str] = field(default_factory=list)
    stages: list[dict] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    accounting: dict = field(default_factory=dict)
    snapshot_id: str = ""
    diagnostic_total: int = 0
    stage_total: int = 0
    scanner_levels: dict[str, int] = field(default_factory=dict)
    security_severities: dict[str, int] = field(default_factory=dict)
    tools: dict[str, int] = field(default_factory=dict)
    findings_available: bool = True
    metrics: dict = field(default_factory=dict)
    run_id: str = ""
    pass_id: str = ""
    attempt_id: str = ""
    captured_at: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def build_operator_summary(context: ReportContext, *, limit: int = 12, show_suppressed: bool = False) -> OperatorSummary:
    if not 1 <= limit <= 100:
        raise ValueError("Summary limit must be between 1 and 100")
    priority = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    indexed = list(enumerate(context.findings, 1))
    indexed.sort(key=lambda pair: (priority.get(str(pair[1].get("severity", "")).lower(), 5),
                                  str(pair[1].get("tool", "")), str(pair[1].get("file", "")),
                                  pair[1].get("line") or 0, pair[0]))
    eligible = [(i, f) for i, f in indexed if show_suppressed or not f.get("suppressed")]
    rows = []
    for i, f in eligible[:limit]:
        rows.append({"ref": f"F{i:05d}", "occurrence_ref": f["occurrence_ref"],
                     "tool": f.get("tool", ""), "rule": f.get("rule_id", ""),
                     "location": f"{f.get('file') or 'unknown'}" + (f":{f['line']}" if f.get("line") else ""),
                     "status": f.get("status", "Unknown"), "level": f.get("scanner_level") or f.get("severity") or "unknown"})
    counts = dict(Counter(f.get("status", "Unknown") for f in context.findings))
    diagnostics = list(context.diagnostics)
    known = {s.stage_id for s in context.stages}
    for stage in context.expected_stages:
        if stage not in known:
            diagnostics.append(f"Expected stage {stage} has no result; coverage unknown")
    for f in context.findings:
        diagnostics.extend(f.get("diagnostics", []))
    stages = []
    for s in context.stages:
        stages.append({"stage": s.stage_id, "state": s.state, "reason": s.reason})
        diagnostics.extend(s.diagnostics)
    suppressed = sum(bool(f.get("suppressed")) for f in context.findings)
    if suppressed:
        diagnostics.append(f"{suppressed} suppressed result(s) retained; {'shown' if show_suppressed else 'hidden from quick view'}")
    actions = []
    if context.kind in {"scan", "codeql"} and context.findings:
        actions.append("Use /validate on the SARIF artifacts for validation; scanner findings are Unconfirmed.")
    state = context.completion_state
    if state not in {"failed", "cancelled"} and (any(s.state in {"failed", "partial", "unknown", "cancelled"} for s in context.stages) or any(s not in known for s in context.expected_stages)):
        state = "partial"
    unique_notes = list(dict.fromkeys(diagnostics))
    try:
        snapshot_id = context.snapshot_id
    except (ValueError, TypeError):
        snapshot_id = ""
        unique_notes.append("Reporting snapshot could not be serialized; this quick view still describes the available findings")
    visible_notes = unique_notes[:30]
    if len(unique_notes) > len(visible_notes):
        visible_notes.append(f"{len(unique_notes) - len(visible_notes)} additional diagnostics retained in report context")
    return OperatorSummary(
        title=f"RAPTOR {context.kind.title()} Summary", target=context.target, state=state,
        total=len(context.findings), rows=rows, counts=counts, diagnostics=visible_notes,
        stages=stages[:30], actions=actions, accounting=context.extensions.get("raptor.accounting", {}),
        snapshot_id=snapshot_id, diagnostic_total=len(unique_notes), stage_total=len(stages),
        scanner_levels=dict(Counter(str(f.get("scanner_level")) if f.get("scanner_level") in ("error", "warning", "note", "none") else "unknown"
                                    for f in context.findings if f.get("scanner_level") is not None)),
        security_severities=dict(Counter(str(f.get("severity")).lower() if str(f.get("severity")).lower() in ("critical", "high", "medium", "moderate", "low", "info", "informational", "none") else "unknown"
                                         for f in context.findings if f.get("severity") is not None)),
        tools=dict(Counter(str(f.get("tool") or "unknown") for f in context.findings)),
        findings_available=context.extensions.get("raptor.findings_available") is not False,
        metrics={k: v for k, v in context.extensions.get("raptor.metrics", {}).items()
                 if v is None or isinstance(v, (str, int, float, bool))},
        run_id=context.run_id, pass_id=context.pass_id, attempt_id=context.attempt_id, captured_at=context.generated_at,
    )


def render_operator_summary(summary: OperatorSummary, *, markdown: bool = False, width: int | None = None) -> str:
    """Render the same bounded data for a terminal or Claude/chat handoff."""
    width = max(40, min(width or shutil.get_terminal_size((100, 24)).columns, 180))
    safe = md_inline if markdown else lambda x: sanitise_for_terminal(str(x), max_len=500)
    lines = [("## " if markdown else "") + safe(summary.title), "",
             f"Outcome: {safe(summary.state)}", f"Target: {safe(summary.target or 'not recorded')}"]
    if summary.findings_available:
        lines.append(f"Captured findings: {summary.total}; " + "; ".join(f"{safe(k)}: {v}" for k, v in sorted(summary.counts.items())[:20]))
    else:
        lines.append("Structured command result captured; this command does not supply a finding population.")
    if len(summary.counts) > 20:
        lines.append(f"{len(summary.counts) - 20} additional status categories retained in summary.json")
    if summary.pass_id or summary.attempt_id:
        lines.append(f"Run: {safe(summary.run_id)}; pass: {safe(summary.pass_id or 'not recorded')}; attempt: {safe(summary.attempt_id or 'not recorded')}")
    for label, counts in (("Scanner levels", summary.scanner_levels), ("Security severities", summary.security_severities), ("Findings by tool", summary.tools)):
        if counts:
            lines.append(label + ": " + "; ".join(f"{safe(k)}={v}" for k, v in sorted(counts.items())[:20]))
            if len(counts) > 20:
                lines.append(f"{len(counts) - 20} additional categories retained in summary.json")
    if summary.findings_available and not summary.total:
        lines.append("No findings in captured results; completeness and scope limits below still apply.")
    for key, value in list(summary.metrics.items())[:20]:
        lines.append(f"{safe(key)}: {safe(value)}")
    if len(summary.metrics) > 20:
        lines.append(f"{len(summary.metrics) - 20} additional metrics omitted from quick view")
    if summary.accounting:
        lines.append("Accounting: " + "; ".join(f"{safe(k)}={safe(v)}" for k, v in list(summary.accounting.items())[:20]))
        if len(summary.accounting) > 20:
            lines.append(f"{len(summary.accounting) - 20} additional accounting fields retained in summary.json")
    for s in summary.stages:
        lines.append(f"Tool/stage {safe(s['stage'])}: {safe(s['state'])}" + (f" ({safe(s['reason'])})" if s["reason"] else ""))
    if summary.stage_total > len(summary.stages):
        lines.append(f"{summary.stage_total - len(summary.stages)} additional stages retained in report context")
    if summary.rows:
        lines.extend(["", f"Showing {len(summary.rows)} of {summary.total} captured findings (severity, tool, location order)."])
        if markdown:
            lines.extend(["", "| Ref | Tool / rule | Location | Status | Scanner level / severity |", "|---|---|---|---|---|"])
            for r in summary.rows:
                lines.append("| " + " | ".join(safe(v) for v in (r["ref"], f"{r['tool']} / {r['rule']}", r["location"], r["status"], r["level"])) + " |")
        else:
            for r in summary.rows:
                # Cards keep status/location readable on narrow terminals.
                lines.extend([f"{safe(r['ref'])}  {safe(r['status'])}  [{safe(r['level'])}]",
                              "  " + safe(f"{r['tool']} / {r['rule']}")[:width - 2],
                              "  " + safe(r["location"])[:width - 2]])
    for note in summary.diagnostics:
        lines.append("Warning: " + safe(note))
    for action in summary.actions:
        lines.append("Next: " + (md_prose(action) if markdown else safe(action)))
    return "\n".join(lines) + "\n"

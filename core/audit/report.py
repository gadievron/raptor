"""Final summary report generation for /audit runs.

Reads the review journal (per-run ``review-journal.jsonl`` and the
project-level ``review-journal-index.json``), ``findings.json``, and
annotations to produce a human-readable summary and structured
report. ``coverage-audit.json`` was removed under the annotation →
journal migration; the journal is the authoritative LLM review
store.
"""

from __future__ import annotations

import contextlib
import json
import logging
import os
import tempfile
from pathlib import Path
from typing import Any

from core.coverage.journal import is_mechanical_echo as _is_mechanical_echo
from core.json import load_json
from core.security.prompt_output_sanitise import sanitise_string

# Byte budgets for the report's artifact reads: 1 MiB for run
# metadata, 8 MiB for small state files, 64 MiB for findings-class
# documents, 256 MiB for the checklist (largest measured artifact
# class — mirrors the coverage-store budget).
_MAX_RUN_META_BYTES = 1024 * 1024
_MAX_STATE_BYTES = 8 * 1024 * 1024
_MAX_FINDINGS_BYTES = 64 * 1024 * 1024
_MAX_CHECKLIST_BYTES = 256 * 1024 * 1024

logger = logging.getLogger(__name__)


def _line(value: Any, *, max_chars: int = 300) -> str:
    """Collapse a finding/journal-derived value to one sanitised line.

    Finding titles, severities, file paths, and function names originate
    from LLM review output (or from the scanned repo itself) and land in
    markdown headings / list lines of the audit report. Newlines are
    collapsed so a multi-line value cannot inject extra heading or list
    lines; ``sanitise_string`` strips autofetch markup, defangs
    line-leading markdown, and escapes ANSI/BIDI/control bytes. Same
    policy as ``core.project.report._md_heading``.
    """
    text = " ".join(str(value if value is not None else "").split()).strip()
    return sanitise_string(text, max_chars=max_chars)


def _cell(value: Any, *, max_chars: int = 300) -> str:
    """Sanitise a value for a one-line markdown table cell.

    Adds pipe-escaping on top of :func:`_line` so a cell can neither
    split table columns nor render as live markup — mirrors
    ``core.project.report._md_escape_inline``.
    """
    return _line(value, max_chars=max_chars).replace("|", "\\|")


def _tier_title(value: Any) -> str:
    """Render an evidence-tier enum value for human-readable output.

    JSON keeps the raw snake_case enum (``xref_backed``); markdown and
    prompt text render Title Case (``Xref Backed``) per the output
    style rule — never ALL-CAPS. ``smt_proved`` keeps its acronym.
    """
    raw = getattr(value, "value", value)
    title = str(raw or "").replace("_", " ").strip().title()
    return title.replace("Smt", "SMT")


def generate_report(
    out_dir: Path,
    *,
    target_path: Path | None = None,
) -> dict[str, Any]:
    """Generate the final audit report.

    Returns a dict with:
        summary: human-readable summary string
        stats: {reviewed, clean, suspicious, finding, dormant, dark,
            error, mechanical}
        findings_count: number of tool-confirmed findings
        coverage_delta: functions reviewed this run
        gaps_remaining: number of unreviewed functions
    """
    completeness = _assess_completeness(out_dir)
    segments = _load_segments(out_dir)

    audit_data = _load_review_state(out_dir)
    findings = _load_findings(out_dir)
    # JOIN findings with the journal for current-verdict authority.
    # findings.json is emit-only at /audit run completion; Reflexion
    # corrections land in the journal only. See amendment §4.
    #
    # Drop findings whose journal verdict is now benign
    # (clean/dormant) — those are Reflexion-refuted and shouldn't
    # count toward findings_count or appear in the summary list.
    # The retained findings carry ``_verdict_source="journal"`` when
    # the journal changed their status (e.g. finding → suspicious).
    findings = _apply_journal_verdict_overrides(findings, audit_data)
    gaps = _load_gaps(out_dir)

    stats = _compute_stats(audit_data)
    gaps_remaining = _count_remaining_gaps(gaps, audit_data)

    unrecorded = _find_unrecorded_reads(out_dir, audit_data, target_path)

    # Budget-truncated tail: functions the --budget cut dropped before
    # scheduling. They are absent from gaps.json (which holds the
    # scheduled list), so without this they would be silently missing
    # from every count — conflated with reviewed code. They count as
    # remaining gaps (never attempted, still gap-eligible next run).
    not_attempted = _load_not_attempted(out_dir)
    not_attempted_count = int(not_attempted.get("count", 0) or 0)
    gaps_remaining += not_attempted_count

    report = {
        "stats": stats,
        "findings_count": len(findings),
        "coverage_delta": stats["reviewed"],
        "gaps_remaining": gaps_remaining,
        "findings": findings,
        "unrecorded_reads": unrecorded,
        # Completeness is REPORTED, not assumed: the generator runs
        # against any partial run dir (interrupted / killed / mid-run)
        # and states what is missing; the verdict tables above always
        # reflect whatever the journal holds.
        "completeness": completeness,
    }
    if segments:
        report["segments"] = segments
    if not_attempted_count:
        report["not_attempted"] = {
            "reason": not_attempted.get("reason", "budget"),
            "count": not_attempted_count,
        }

    # Vendored/generated triage decisions (per-function records in
    # suppressions.jsonl) — the run summary states the counts so
    # skipped/glanced functions are never silently absent.
    vendored_triage = _load_vendored_triage(out_dir)
    if vendored_triage:
        report["vendored_triage"] = vendored_triage

    # Cross-function edge obligations (--edges runs): tier counts,
    # unreviewed tier-1 edges, and the blind-spot list — the
    # 2026-05-29 design's headline output. Absent file -> absent key.
    edge_block = _load_edge_obligations(out_dir)
    if edge_block:
        report["edge_obligations"] = edge_block

    # Dark outcomes ("tool-blind, needs concrete verification") from
    # the graded export — surfaced so the bucket reaches the operator
    # instead of being tallied invisibly as dormant.
    dark_findings = _load_dark_findings(out_dir)
    if dark_findings:
        report["dark_findings"] = dark_findings

    # Finding-survival metric: per-evidence-channel /validate outcomes
    # (pure read-side aggregation over the journal — empty until a
    # /validate feedback import has run).
    try:
        from .survival import aggregate_survival
        survival = aggregate_survival(out_dir)
    except Exception:  # reporting must not fail the run
        logger.debug("survival aggregation failed", exc_info=True)
        survival = {}
    if survival:
        report["survival"] = survival

    # Promotion-without-tool-evidence alarms: empty on every
    # legitimate run — any record is a mechanical-verdict invariant
    # violation and must be surfaced loudly.
    try:
        from .promotion_alarm import load_alarms
        promotion_alarms = load_alarms(out_dir)
    except Exception:  # reporting must not fail the run
        logger.debug("promotion alarm load failed", exc_info=True)
        promotion_alarms = []
    if promotion_alarms:
        report["promotion_alarms"] = promotion_alarms

    eval_path = out_dir / "evaluation.json"
    if eval_path.is_file():
        eval_data = load_json(eval_path, max_bytes=_MAX_STATE_BYTES)
        if eval_data is not None:
            report["evaluation"] = eval_data

    # Interrupted Joern pre-sweep window (server restart mid-query):
    # whether the window was re-queued and recovered or lost outright
    # must reach the operator — a lost window means the run's taint
    # evidence is incomplete, which reads as "no flows" everywhere
    # downstream unless stated.
    try:
        from .joern_backend import load_presweep_status
        presweep = load_presweep_status(out_dir)
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("pre-sweep status load failed", exc_info=True)
        presweep = None
    if presweep:
        report["joern_presweep"] = presweep

    # Phase aborts (persistent LLM auth refusal): a listed phase
    # produced NO trustworthy output — its empty results must not be
    # read as "phase ran and found nothing". Written at abort time by
    # the orchestrator (_record_phase_abort).
    phase_aborts = load_phase_aborts(out_dir)
    if phase_aborts:
        report["phase_aborts"] = phase_aborts

    report["summary"] = _format_summary(report)
    return report


def load_phase_aborts(out_dir: Path) -> list[dict[str, Any]]:
    """Load ``phase-aborts.json`` records from *out_dir* (empty list
    when absent or unreadable — reporting must not fail the run)."""
    path = Path(out_dir) / "phase-aborts.json"
    if not path.is_file():
        return []
    loaded = load_json(path, max_bytes=_MAX_STATE_BYTES)
    if not isinstance(loaded, list):
        return []
    return [r for r in loaded if isinstance(r, dict)]


def format_summary(report: dict[str, Any]) -> str:
    """Format a report dict as a human-readable summary."""
    return report.get("summary", _format_summary(report))


def _load_edge_obligations(out_dir: Path) -> dict[str, Any] | None:
    """Summarise edge-obligations.json + the journal's edge entries.

    Reviewed = journal entries carrying ``edge_callee`` (any verdict
    but ``error``) keyed against tier-1 obligations. Blind spots are
    surfaced in full count with a bounded sample — never silently
    truncated without the count saying so.
    """
    raw = load_json(
        out_dir / "edge-obligations.json", max_bytes=_MAX_FINDINGS_BYTES,
    )
    if not isinstance(raw, dict):
        return None
    tier1 = raw.get("tier1") or []
    tier2 = raw.get("tier2") or []
    blind = raw.get("blind_spots") or []

    reviewed_keys: set[str] = set()
    findings: list[dict[str, Any]] = []
    try:
        from core.audit.edge_review import edge_key
        from core.coverage.journal import load_entries
        for entry in load_entries(out_dir):
            callee_id = getattr(entry, "edge_callee", None)
            if not callee_id or entry.verdict == "error":
                continue
            reviewed_keys.add(entry.key)
            if entry.verdict == "finding":
                findings.append({
                    "caller": f"{entry.file}:{entry.function}",
                    "callee": callee_id,
                    "cwe": entry.cwe,
                })
        unreviewed = [
            r for r in tier1 if edge_key(r) not in reviewed_keys
        ]
    except Exception:  # noqa: BLE001 — journal read is best-effort
        logger.debug("edge journal summary failed", exc_info=True)
        unreviewed = list(tier1)

    block: dict[str, Any] = {
        "tier1_total": len(tier1),
        "tier1_unreviewed": len(unreviewed),
        "tier2_total": len(tier2),
        "blind_spot_count": len(blind),
        "blind_spots_sample": blind[:25],
        "stats": raw.get("stats") or {},
    }
    if findings:
        block["edge_findings"] = findings
    return block


def write_report(report: dict[str, Any], out_dir: Path) -> Path:
    """Write the report to audit-report.json."""
    path = out_dir / "audit-report.json"
    serializable = {k: v for k, v in report.items() if k != "summary"}
    tmp_fd, tmp_path = tempfile.mkstemp(
        dir=out_dir, prefix=".audit-report-", suffix=".json",
    )
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(serializable, f, indent=2)
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise
    return path


def write_markdown_report(
    report: dict[str, Any],
    out_dir: Path,
    *,
    target_path: Path | None = None,
    model: str = "",
    duration_minutes: float = 0.0,
    cost_usd: float = 0.0,
    capabilities: dict[str, bool] | None = None,
    suppressions_count: int = 0,
) -> Path:
    """Write the full audit-report.md per the /audit output contract."""
    stats = report.get("stats", {})
    findings = report.get("findings", [])

    lines = ["# Audit Report", ""]

    # Header metadata
    if target_path:
        lines.append(f"**Target:** {target_path}")
    if model:
        lines.append(f"**Model:** {model}")
    if duration_minutes > 0:
        lines.append(f"**Duration:** {duration_minutes:.0f} minutes")
    if cost_usd > 0:
        lines.append(f"**Cost:** ${cost_usd:.2f}")

    reviewed = stats.get("reviewed", 0)
    total_funcs = reviewed + report.get("gaps_remaining", 0)
    if total_funcs > 0:
        pct = reviewed * 100.0 / total_funcs
        lines.append(
            f"**Functions reviewed:** {reviewed:,} of {total_funcs:,} ({pct:.1f}%)"
        )
    not_attempted = report.get("not_attempted")
    if not_attempted:
        lines.append(
            f"**Not attempted ({_line(not_attempted.get('reason', 'budget'), max_chars=40)}):** "
            f"{int(not_attempted.get('count', 0) or 0):,} functions "
            "(see not-attempted.json; gap-eligible next run)"
        )
    lines.append("")

    # Run completeness — stated, not assumed (partial runs render the
    # verdict tables from whatever the journal holds).
    state_lines = _completeness_lines(report)
    if state_lines:
        lines.append("## Run completeness")
        lines.append("")
        lines.extend(state_lines)
        lines.append("")

    # Cross-function edge obligations — headline placement: the
    # blind-spot list (call sites the static graph cannot follow on
    # attack paths) is first-class output, equal in prominence to the
    # verdict tables, per the edge-obligations design.
    edge_block = report.get("edge_obligations")
    if edge_block:
        lines.append("## Edge obligations (--edges)")
        lines.append("")
        lines.append(
            f"- Tier-1 (boundary) edges: "
            f"{edge_block.get('tier1_total', 0)} obligated, "
            f"{edge_block.get('tier1_unreviewed', 0)} unreviewed")
        lines.append(
            f"- Tier-2 (on-path) edges folded into caller reviews: "
            f"{edge_block.get('tier2_total', 0)}")
        degraded = (edge_block.get("stats") or {}).get("degraded") or []
        if "no-domain-model" in degraded:
            lines.append(
                "- **Degraded — no domain model:** contract review of "
                "aliasing/ownership bug classes needs the knowledge "
                "layer; run a study pass or seed concepts/domain-model.json "
                "and re-audit (context-staleness re-queues affected "
                "verdicts).")
        others = [d for d in degraded if d != "no-domain-model"]
        if others:
            lines.append(
                "- Degraded: " + ", ".join(_line(d, max_chars=40)
                                           for d in others[:6]))
        lines.extend(f"- **Contract violation:** "
                f"{_line(str(f.get('caller', '')), max_chars=120)} -> "
                f"{_line(str(f.get('callee', '')), max_chars=120)}"
                + (f" ({_line(str(f.get('cwe')), max_chars=20)})"
                   if f.get("cwe") else "") for f in edge_block.get("edge_findings", [])[:10])
        blind_n = edge_block.get("blind_spot_count", 0)
        if blind_n:
            lines.append("")
            lines.append(
                f"### Blind spots: {blind_n} call site(s) on attack "
                "paths the static graph cannot follow")
            lines.append(
                "(function pointers / dynamic dispatch / unresolved or "
                "ambiguous callees — manual review required; a "
                "percentage cannot be taken over edges that cannot be "
                "enumerated)")
            for b in edge_block.get("blind_spots_sample", [])[:15]:
                caller = b.get("caller") or "(module scope)"
                lines.append(
                    f"- {_line(str(b.get('file', '')), max_chars=100)}"
                    f" :: {_line(str(caller), max_chars=60)} — "
                    f"{_line(str(b.get('kind', '')), max_chars=24)}"
                    f" `{_line(str(b.get('name', '')), max_chars=60)}`")
            shown = min(15, len(edge_block.get("blind_spots_sample", [])))
            if blind_n > shown:
                lines.append(
                    f"- (+{blind_n - shown} more — see "
                    "edge-obligations.json)")
        lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    if findings:
        severity_counts: dict[str, int] = {}
        for f in findings:
            sev = _line(str(f.get("severity", "medium")).lower(), max_chars=40)
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
        sev_parts = [f"{count} {sev}" for sev, count in sorted(severity_counts.items())]
        lines.append(f"{len(findings)} findings: {', '.join(sev_parts)}.")
    else:
        lines.append("No findings.")
    lines.append("")

    # Capabilities used
    if capabilities:
        lines.append("## Capabilities used")
        lines.append("")
        lines.append("| Tool | Available |")
        lines.append("|---|---|")
        for tool in sorted(capabilities):
            avail = "Yes" if capabilities[tool] else "No"
            lines.append(f"| {tool} | {avail} |")
        lines.append("")

    # Findings
    if findings:
        lines.append("## Findings")
        lines.append("")
        for f in findings:
            # LLM-derived free text (title) and labels (id, tier, file,
            # line, depth) — single-line sanitised so a crafted value
            # cannot break out of the heading or inject markup.
            fid = _line(f.get("id", "FIND-???"), max_chars=80)
            title = _line(f.get("title", "Untitled"))
            tier = _line(
                _tier_title(f.get("evidence_tier", "heuristic")),
                max_chars=40,
            )
            lines.append(f"### {fid}: {title} ({tier})")
            file_loc = _line(f.get("file", "?"))
            line_no = _line(f.get("line", "?"), max_chars=20)
            depth = _line(f.get("depth", "?"), max_chars=40)
            lines.append(
                f"**File:** {file_loc}:{line_no}  "
                f"**Depth:** {depth}  "
                f"**Evidence:** {tier}"
            )
            lines.append("")

    # Dark findings — tool-blind hypotheses that need concrete
    # verification. Not findings, not refuted: route to /validate.
    dark = report.get("dark_findings", [])
    if dark:
        lines.append(f"## Dark findings ({len(dark)}) — need concrete verification")
        lines.append("")
        lines.append(
            "No mechanical channel can decide these classes. They are "
            "exported in findings-graded.json with `needs_validation: "
            "true` — run `/validate` to judge them."
        )
        lines.append("")
        for f in dark[:20]:
            title = _line(f.get("title", "Untitled"))
            file_loc = _line(f.get("file", "?"))
            line_no = _line(f.get("line", "?"), max_chars=20)
            lines.append(f"- {title} ({file_loc}:{line_no})")
        if len(dark) > 20:
            lines.append(f"- ... and {len(dark) - 20} more")
        lines.append("")

    # Evidence distribution
    lines.append("## Evidence distribution")
    lines.append("")
    evidence_dist = _evidence_distribution(findings)
    if evidence_dist:
        lines.append("| Tier | Count |")
        lines.append("|---|---|")
        for tier, count in sorted(evidence_dist.items()):
            lines.append(
                f"| {_cell(_tier_title(tier), max_chars=40)} | {count} |"
            )
    else:
        lines.append("No evidence recorded.")
    lines.append("")

    # Suppressions
    if suppressions_count > 0:
        lines.append("## Suppressions")
        lines.append("")
        lines.append(
            f"{suppressions_count} findings suppressed by binary oracle "
            f"(function absent from binary)."
        )
        lines.append("See suppressions.jsonl for details.")
        lines.append("")

    # Measurement evaluation
    evaluation = report.get("evaluation")
    if evaluation:
        lines.append("## Evaluation")
        lines.append("")
        lines.append(
            f"**Detection:** {evaluation.get('recall', 0):.0%} "
            f"**Precision:** {evaluation.get('precision', 0):.0%} "
            f"**F1:** {evaluation.get('f1', 0):.2f}"
        )
        per_cap = evaluation.get("per_capability", {})
        if per_cap:
            lines.append("")
            lines.append("| Evidence source | TP | FP |")
            lines.append("|---|---|---|")
            for src, counts in sorted(per_cap.items()):
                lines.append(f"| {_cell(src, max_chars=60)} | {counts.get('tp', 0)} | {counts.get('fp', 0)} |")
        per_cell = evaluation.get("per_cell", {})
        if per_cell:
            lines.append("")
            lines.append("| Depth x Failure mode | TP | FN |")
            lines.append("|---|---|---|")
            for cell_key, counts in sorted(per_cell.items()):
                lines.append(f"| {_cell(cell_key, max_chars=60)} | {counts.get('tp', 0)} | {counts.get('fn', 0)} |")
        lines.append("")

    # Unrecorded reads
    unrecorded = report.get("unrecorded_reads", [])
    if unrecorded:
        total_funcs_unrec = sum(len(u["functions"]) for u in unrecorded)
        lines.append(
            f"## Unrecorded reads ({total_funcs_unrec} functions in "
            f"{len(unrecorded)} files)"
        )
        lines.append("")
        for u in unrecorded[:10]:
            # File / function names come from the scanned repo's
            # checklist — untrusted-source-derived; keep them to one
            # sanitised line each.
            fn_list = ", ".join(_line(fn, max_chars=80) for fn in u["functions"][:5])
            extra = len(u["functions"]) - 5
            suffix = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"- {_line(u['file'])}: {fn_list}{suffix}")
        lines.append("")

    content = "\n".join(lines)
    path = out_dir / "audit-report.md"
    # Pinned encoding: finding titles/bodies carry target-derived text
    # (often non-ASCII); the platform default (POSIX locale → ASCII)
    # made the report write crash at run end.
    path.write_text(content, encoding="utf-8")
    return path


def _evidence_distribution(
    findings: list[dict[str, Any]],
) -> dict[str, int]:
    """Count findings per evidence tier."""
    dist: dict[str, int] = {}
    for f in findings:
        # Raw snake_case enum key (matching EvidenceTier values) —
        # the markdown renderer Title-Cases at display time.
        tier = f.get("evidence_tier", "heuristic")
        dist[tier] = dist.get(tier, 0) + 1
    return dist


def _load_review_state(out_dir: Path) -> dict[str, Any]:
    """Load LLM review state from the review journal.

    Returns a ``coverage-audit.json``-shaped dict
    (``{"functions_analysed": [...]}``) so the downstream stats /
    remaining-gap helpers work unchanged. Each journal entry becomes
    one function record with ``file`` / ``function`` / ``status`` /
    ``hash`` fields — matches the pre-migration record schema.
    """
    try:
        from .journal import load_entries
    except Exception:  # noqa: BLE001
        return {"functions_analysed": []}
    try:
        # Latest per SITE — (file, function, line_start) — not per
        # coarse (file, function): same-named checklist items
        # (function + prototype, macro redefinitions) are distinct
        # review subjects, and the coarse collapse made a reviewed
        # prototype stand in for its unreviewed body in every
        # report-side count.
        best: dict[tuple, Any] = {}
        for e in load_entries(out_dir):
            k = (e.file, e.function, e.line_start or 0)
            prev = best.get(k)
            if prev is None or e.ts > prev.ts:
                best[k] = e
        entries = best
    except Exception:  # noqa: BLE001
        return {"functions_analysed": []}
    if not entries:
        return {"functions_analysed": []}

    functions: list[dict[str, Any]] = []
    files_examined: set = set()
    for entry in entries.values():
        functions.append({
            "file": entry.file,
            "function": entry.function,
            "line_start": entry.line_start or 0,
            "status": entry.verdict,
            "hash": entry.source_hash or None,
            # Post-loop mechanical entries (taint-spec / negative-space
            # checks journalled after the review loop) are not LLM
            # reviews — carry the marker so stats can state one
            # counting rule instead of silently inflating "reviewed".
            "mechanical": _is_mechanical_echo(entry),
        })
        if entry.file:
            files_examined.add(entry.file)
    return {
        "tool": "audit",
        "functions_analysed": functions,
        "files_examined": sorted(files_examined),
    }


_BENIGN_VERDICTS = frozenset({"clean", "dormant"})


def _apply_journal_verdict_overrides(
    findings: list[dict[str, Any]],
    audit_data: dict[str, Any],
) -> list[dict[str, Any]]:
    """JOIN semantics: findings.json is emit-only at /audit run end;
    the journal is authoritative for current verdict.

    Two behaviours:

    - **Status override**: when the journal's latest entry for a
      finding's ``(file, function)`` disagrees with the finding's
      status, the finding's ``status`` field is overwritten from the
      journal and ``_verdict_source="journal"`` is stamped for
      audit-trail visibility.
    - **Benign drop**: when the journal reports a benign verdict
      (``clean``, ``dormant``) — i.e. Reflexion refuted the finding
      after initial emission — the finding is dropped from the
      returned list entirely. Without this, ``findings_count`` +
      the report's Findings section still tally refuted issues,
      defeating the JOIN's whole purpose.

    Returns the filtered list (never mutates the input list's
    length in place).
    """
    by_key: dict[str, str] = {}
    for func in audit_data.get("functions_analysed", []):
        f = func.get("file", "")
        fn = func.get("function", "")
        status = func.get("status")
        if f and fn and status:
            by_key[f"{f}:{fn}"] = status

    out: list[dict[str, Any]] = []
    for finding in findings:
        key = f"{finding.get('file', '')}:{finding.get('function', '')}"
        journal_verdict = by_key.get(key)
        if journal_verdict and journal_verdict != finding.get("status"):
            finding["status"] = journal_verdict
            finding["_verdict_source"] = "journal"
        if finding.get("status") in _BENIGN_VERDICTS:
            # Reflexion refuted this finding — drop from active
            # findings so counts and summaries reflect current state.
            continue
        out.append(finding)
    return out


# Artifacts every finished orchestrator run writes. Absence of any of
# them means the run stopped before its export tail (or the write
# failed) — the report states this instead of silently rendering the
# sections empty.
_EXPECTED_ARTIFACTS = (
    ("checklist.json", "inventory (checklist.json)"),
    ("gaps.json", "gap schedule (gaps.json)"),
    ("findings-graded.json", "graded findings export (findings-graded.json)"),
    ("cost-breakdown.json", "cost ledger (cost-breakdown.json)"),
)

#: Run statuses `raptor-audit resume` can re-enter (mirrors
#: core.run.metadata.RESUMABLE_STATUSES without importing it here —
#: the report must render even when run metadata plumbing is absent).
_RESUMABLE_STATUSES = frozenset({
    "interrupted", "failed", "cancelled", "running",
})


def _study_starvation_label(out_dir: Path) -> str | None:
    """Label naming study starvation, or ``None`` when study is fine.

    Starvation = the consumer's persisted stats (``study-stats.json``,
    written at drain) show zero re-reviews while ``reading-list.json``
    still carries pending questions. Absent stats (older runs, no
    study-eligible files) stay silent — absence of evidence is not a
    gap claim.
    """
    try:
        stats_path = out_dir / "study-stats.json"
        if not stats_path.is_file():
            return None
        stats = load_json(stats_path, max_bytes=_MAX_STATE_BYTES)
        if not isinstance(stats, dict) or stats.get("re_reviews"):
            return None
        from core.concepts.reading_list import ReadingList
        pending = len(
            ReadingList.load(out_dir / "reading-list.json").pending(),
        )
        if pending <= 0:
            return None
        reason = stats.get("stopped_reason") or "unknown"
        return (
            f"study results (0 re-reviews; {pending} questions still "
            f"pending; consumer stopped: {reason})"
        )
    except Exception:
        logger.debug("study starvation assessment failed", exc_info=True)
        return None


def _assess_completeness(out_dir: Path) -> dict[str, Any]:
    """State how complete this run dir is — never assume.

    Returns ``{"run_status": str|None, "missing": [labels],
    "no_verdicts": bool, "partial": bool, "resumable": bool}``.
    ``partial`` is True when the lifecycle status is anything but
    ``completed`` (including unknown) or an expected export artifact
    is absent. The verdict tables elsewhere in the report are built
    from the journal regardless — completeness only *names* the gaps.
    """
    status: str | None = None
    meta_path = out_dir / ".raptor-run.json"
    if meta_path.is_file():
        meta = load_json(meta_path, max_bytes=_MAX_RUN_META_BYTES)
        if isinstance(meta, dict):
            status = meta.get("status")

    missing = [
        label for name, label in _EXPECTED_ARTIFACTS
        if not (out_dir / name).is_file()
    ]
    # Study starvation is a completeness gap, not a silent detail: a
    # run whose study consumer produced zero re-reviews while
    # questions are still pending reviewed everything hypothesis-blind
    # (empty invariants). Name it so the operator sees it.
    study_gap = _study_starvation_label(out_dir)
    if study_gap:
        missing.append(study_gap)
    no_verdicts = not (out_dir / "review-journal.jsonl").is_file()
    partial = bool(missing) or status != "completed"
    return {
        "run_status": status,
        "missing": missing,
        "no_verdicts": no_verdicts,
        "partial": partial,
        "resumable": status in _RESUMABLE_STATUSES,
    }


def _load_segments(out_dir: Path) -> dict[str, Any] | None:
    """Segment provenance for resumed runs, from ``extra.resumes``."""
    meta_path = out_dir / ".raptor-run.json"
    if not meta_path.is_file():
        return None
    meta = load_json(meta_path, max_bytes=_MAX_RUN_META_BYTES)
    try:
        resumes = ((meta or {}).get("extra") or {}).get("resumes")
    except AttributeError:
        return None
    if not isinstance(resumes, list) or not resumes:
        return None
    rows = [r for r in resumes if isinstance(r, dict)]
    return {
        "count": len(rows) + 1,
        "resumes": rows,
    }


def _load_dark_findings(out_dir: Path) -> list[dict[str, Any]]:
    """Load status=dark entries from findings-graded.json."""
    path = out_dir / "findings-graded.json"
    if not path.exists():
        return []
    data = load_json(path, max_bytes=_MAX_FINDINGS_BYTES)
    findings = data.get("findings", []) if isinstance(data, dict) else []
    return [
        f for f in findings
        if isinstance(f, dict) and f.get("status") == "dark"
    ]


def _load_vendored_triage(out_dir: Path) -> dict[str, int]:
    """Count vendored/generated triage decisions from the
    suppressions.jsonl audit trail (rule_id ``audit:vendored-triage``).
    Returns ``{}`` when the tier made no decisions."""
    path = out_dir / "suppressions.jsonl"
    if not path.exists():
        return {}
    skipped = glanced = 0
    try:
        with Path(path).open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("rule_id") != "audit:vendored-triage":
                    continue
                if rec.get("tier") == "skip":
                    skipped += 1
                elif rec.get("tier") == "glance":
                    glanced += 1
    except OSError:
        return {}
    if not (skipped or glanced):
        return {}
    return {"skipped": skipped, "glanced": glanced}


def _load_findings(out_dir: Path) -> list[dict[str, Any]]:
    path = out_dir / "findings.json"
    if not path.exists():
        return []
    data = load_json(path, max_bytes=_MAX_FINDINGS_BYTES)
    if isinstance(data, list):
        return data
    return data.get("findings", []) if isinstance(data, dict) else []


def _load_gaps(out_dir: Path) -> dict[str, Any]:
    path = out_dir / "gaps.json"
    if not path.exists():
        return {}
    data = load_json(path, max_bytes=_MAX_FINDINGS_BYTES)
    return data if data is not None else {}


def _load_not_attempted(out_dir: Path) -> dict[str, Any]:
    """Load not-attempted.json (budget-truncated tail), or {}."""
    path = out_dir / "not-attempted.json"
    if not path.exists():
        return {}
    data = load_json(path, max_bytes=_MAX_STATE_BYTES)
    return data if isinstance(data, dict) else {}


def _compute_stats(audit_data: dict[str, Any]) -> dict[str, int]:
    """Count statuses across all reviewed functions.

    One counting rule, shared with the console summary: ``reviewed``
    (and the per-status counts) cover LLM reviews only; post-loop
    mechanical journal entries land in ``mechanical``. Pre-fix the
    journal-derived report counted every entry as reviewed while the
    console counted only tallied LLM outcomes — one run printed
    14 reviewed / 8 suspicious in the report against 9 / 3 on the
    console for the same journal.
    """
    counts = {
        "reviewed": 0, "clean": 0, "suspicious": 0, "finding": 0,
        "dormant": 0, "dark": 0, "error": 0, "mechanical": 0,
    }

    if "files" in audit_data:
        for file_data in audit_data["files"].values():
            for func_data in file_data.get("functions", {}).values():
                counts["reviewed"] += 1
                status = func_data.get("status", "clean")
                if status in counts:
                    counts[status] += 1
    elif "functions_analysed" in audit_data:
        for func_data in audit_data["functions_analysed"]:
            if func_data.get("mechanical"):
                counts["mechanical"] += 1
                continue
            counts["reviewed"] += 1
            status = func_data.get("status", "clean")
            if status in counts:
                counts[status] += 1

    return counts


def _count_remaining_gaps(
    gaps_data: dict[str, Any],
    audit_data: dict[str, Any],
) -> int:
    """Count gaps not covered by this audit run.

    One counting rule, shared with ``_compute_stats``: post-loop
    mechanical journal echoes are not LLM reviews and must not count
    as covered gaps — pre-fix each pattern-scan echo shrank
    ``gaps_remaining`` by one while the reviewed count excluded it,
    so the two headline numbers disagreed about the same journal.
    """
    gaps = gaps_data.get("gaps") or []
    if not gaps:
        # Legacy gaps.json without the item list: arithmetic fallback.
        # Set-blind subtraction is UNSAFE when the list exists — the
        # journal contains reviews that are not gap items (batch
        # members, re-reviews, deepen passes), so ``reviewed`` can
        # exceed ``total_gaps`` while real gap items sit unreviewed;
        # a 46-hour run reported "0 gaps left" over ~2,300 untouched
        # priority-0 functions (two of which carried real
        # vulnerabilities a comparison harness later confirmed).
        total_gaps = gaps_data.get("count", 0)
        if "files" in audit_data:
            reviewed = sum(
                len(fd.get("functions", {}))
                for fd in audit_data["files"].values()
            )
        elif "functions_analysed" in audit_data:
            reviewed = sum(
                1 for func_data in audit_data["functions_analysed"]
                if not func_data.get("mechanical")
            )
        else:
            reviewed = 0
        return max(0, total_gaps - reviewed)

    # Set difference, per SITE: a gap counts as remaining unless a
    # non-mechanical journal record covers its (file, name) — and,
    # when both sides carry spans, its line_start. Same-named items
    # (function + prototype, macro redefinitions) must not cover each
    # other.
    sites: set = set()
    spanless: set = set()
    for rec in audit_data.get("functions_analysed", []):
        if rec.get("mechanical") or rec.get("status") == "error":
            continue
        key = (rec.get("file"), rec.get("function"))
        ls = rec.get("line_start") or 0
        if ls:
            sites.add((key[0], key[1], ls))
        else:
            spanless.add(key)
    if "files" in audit_data:  # pre-migration record shape
        for fp, fd in audit_data["files"].items():
            for fn in fd.get("functions", {}):
                spanless.add((fp, fn))
    remaining = 0
    for g in gaps:
        key = (g.get("file"), g.get("name"))
        ls = g.get("line_start") or 0
        if key in spanless or (ls and (key[0], key[1], ls) in sites):
            continue
        remaining += 1
    return remaining


def _find_unrecorded_reads(
    out_dir: Path,
    audit_data: dict[str, Any],
    target_path: Path | None,
) -> list[dict[str, Any]]:
    """Find functions in files the LLM read but didn't record.

    Cross-references the coverage plugin's .reads-manifest (files the
    Read tool touched) against journal-derived review state
    (``audit_data`` from ``_load_review_state`` — coverage-audit.json
    and the ``raptor-audit record`` CLI were removed by the journal
    migration).  Returns a list of {file, functions: [name, ...]}
    dicts for files with unrecorded functions, sorted by number of
    unrecorded functions descending.
    """
    manifest_path = out_dir / ".reads-manifest"
    checklist_path = out_dir / "checklist.json"
    if not manifest_path.exists() or not checklist_path.exists():
        return []

    try:
        with Path(manifest_path).open(encoding="utf-8", errors="replace") as f:
            read_paths = {line.strip() for line in f if line.strip()}
    except OSError:
        return []

    checklist = load_json(checklist_path, max_bytes=_MAX_CHECKLIST_BYTES)
    if checklist is None:
        return []

    recorded_funcs: set[str] = set()
    if "files" in audit_data:
        for file_path, file_data in audit_data["files"].items():
            for func_name in file_data.get("functions", {}):
                recorded_funcs.add(f"{file_path}:{func_name}")
    elif "functions_analysed" in audit_data:
        for entry in audit_data["functions_analysed"]:
            f = entry.get("file", "")
            fn = entry.get("function", "")
            if f and fn:
                recorded_funcs.add(f"{f}:{fn}")

    file_functions: dict[str, list[str]] = {}
    for file_entry in checklist.get("files", []):
        rel_path = file_entry.get("path", "")
        if not rel_path:
            continue
        funcs = [
            item["name"]
            for item in file_entry.get("items", [])
            if item.get("kind") in ("function", "method") and item.get("name")
        ]
        if funcs:
            file_functions[rel_path] = funcs

    target_resolved = str(Path(target_path).resolve()) if target_path else None

    result = []
    for abs_path in read_paths:
        rel_path = None
        if target_resolved and abs_path.startswith(target_resolved + os.sep):
            rel_path = abs_path[len(target_resolved) + 1:]
        elif target_resolved and abs_path == target_resolved:
            rel_path = abs_path[len(target_resolved):]
        if not rel_path:
            continue

        if rel_path not in file_functions:
            continue

        unrecorded = [
            fn for fn in file_functions[rel_path]
            if f"{rel_path}:{fn}" not in recorded_funcs
        ]
        if unrecorded:
            result.append({"file": rel_path, "functions": unrecorded})

    result.sort(key=lambda x: len(x["functions"]), reverse=True)
    return result


def _completeness_lines(report: dict[str, Any]) -> list[str]:
    """Shared partial-run / segment statements for summary + markdown."""
    lines: list[str] = []
    segments = report.get("segments")
    if segments:
        lines.append(
            f"Run segments: {int(segments.get('count', 0) or 0)} "
            "(resumed run — one report covers all segments)"
        )
    completeness = report.get("completeness") or {}
    if completeness.get("partial"):
        status = _line(completeness.get("run_status") or "unknown",
                       max_chars=40)
        lines.append(
            f"Partial run — lifecycle status: {status.title()}. "
            "Verdict counts below reflect the journal as written."
        )
        lines.extend(f"  Missing: {_line(label, max_chars=80)}" for label in completeness.get("missing", []))
        if completeness.get("no_verdicts"):
            lines.append(
                "  No review journal — the run stopped before any "
                "verdict was recorded."
            )
        if completeness.get("resumable"):
            lines.append(
                "  Resumable: raptor-audit resume <run-dir> re-enters "
                "this run ($0 verdict re-import, remaining budget)."
            )
    return lines


def _format_summary(report: dict[str, Any]) -> str:
    """Format a human-readable summary."""
    stats = report.get("stats", {})
    mech = stats.get("mechanical", 0)
    mech_s = f" (+{mech} mechanical post-loop)" if mech else ""
    lines = ["## Audit Summary", ""]
    state_lines = _completeness_lines(report)
    if state_lines:
        lines.extend(state_lines)
        lines.append("")
    lines += [
        f"Functions LLM-reviewed: {stats.get('reviewed', 0)}{mech_s}",
        f"  Clean: {stats.get('clean', 0)}",
        f"  Dormant: {stats.get('dormant', 0)}",
        f"  Dark: {stats.get('dark', 0)}",
        f"  Suspicious: {stats.get('suspicious', 0)}",
        f"  Finding: {stats.get('finding', 0)}",
        f"  Error: {stats.get('error', 0)}",
        "",
        f"Tool-confirmed findings: {report.get('findings_count', 0)}",
        f"Gaps remaining: {report.get('gaps_remaining', 0)}",
    ]

    dark_findings = report.get("dark_findings", [])
    if dark_findings:
        lines.append("")
        lines.append(
            f"### Dark findings ({len(dark_findings)}) — "
            f"need concrete verification"
        )
        lines.append(
            "Tool-blind classes (auth bypass, logic, IDOR, ...) no "
            "mechanical channel can decide. Exported with "
            "needs_validation: true — run /validate on them."
        )
        for f in dark_findings[:10]:
            lines.append(
                f"- {_line(f.get('title', 'Untitled'))} "
                f"({_line(f.get('file', '?'))}:"
                f"{_line(f.get('line', '?'), max_chars=20)})"
            )
        if len(dark_findings) > 10:
            lines.append(f"  ... and {len(dark_findings) - 10} more")
    not_attempted = report.get("not_attempted")
    if not_attempted:
        lines.append(
            f"Not attempted ({not_attempted.get('reason', 'budget')}): "
            f"{not_attempted.get('count', 0)} functions — see "
            "not-attempted.json; they stay gap-eligible next run"
        )
    vendored = report.get("vendored_triage")
    if vendored:
        lines.append(
            f"Vendored/generated triage: {vendored.get('skipped', 0)} "
            f"functions skipped, {vendored.get('glanced', 0)} routed to "
            "glance — per-function records in suppressions.jsonl"
        )

    findings = report.get("findings", [])
    if findings:
        lines.append("")
        lines.append("### Findings")
        for f in findings:
            # LLM-derived values — sanitise so a crafted title / path
            # cannot inject extra lines or live markup into the summary.
            severity = _line(str(f.get("severity", "medium")).title(), max_chars=40)
            lines.append(
                f"- [{severity}] {_line(f.get('title', 'Untitled'))} "
                f"({_line(f.get('file', '?'))}:{_line(f.get('line', '?'), max_chars=20)})"
            )

    survival = report.get("survival")
    if survival:
        from .survival import format_survival
        lines.append("")
        lines.append("### Finding survival (/validate feedback)")
        lines.extend(format_survival(survival)[1:])

    presweep = report.get("joern_presweep")
    if presweep:
        lines.append("")
        interrupted = presweep.get("interrupted", 0)
        requeued = presweep.get("requeued", 0)
        if presweep.get("recovered"):
            lines.append(
                f"Joern pre-sweep: interrupted by a server restart "
                f"({interrupted}x), re-queued and recovered after "
                f"{requeued} attempt(s) — "
                f"{presweep.get('flows_recovered', 0)} flow group(s) "
                f"recovered"
            )
        else:
            lines.append(
                f"### ⚠️ Joern pre-sweep window lost"
            )
            lines.append(
                f"Interrupted by a server restart and NOT recovered "
                f"after {requeued} re-queue attempt(s) — this run's "
                f"taint-flow evidence is incomplete (functions read as "
                f"'no flows' rather than 'not swept'). Re-run /audit "
                f"or /agentic to regenerate the sweep."
            )

    phase_aborts = report.get("phase_aborts")
    if phase_aborts:
        lines.append("")
        lines.append(
            f"### ⚠️ Phase aborts ({len(phase_aborts)})"
        )
        lines.append(
            "These phases ABORTED on persistent LLM auth refusal "
            "(expired/revoked credential — every call 401'd). Their "
            "output is missing, not empty: do not read the absence "
            "of results as \"phase ran clean\". Fix the credential "
            "and re-run. See phase-aborts.json."
        )
        for rec in phase_aborts[:10]:
            lines.append(
                f"  - {_line(rec.get('phase', '?'), max_chars=40)}: "
                f"{_line(rec.get('error', '?'), max_chars=200)}"
            )

    promotion_alarms = report.get("promotion_alarms")
    if promotion_alarms:
        lines.append("")
        lines.append(
            f"### ⚠️ Promotion alarms ({len(promotion_alarms)})"
        )
        lines.append(
            "Findings reached the journal/export without qualifying "
            "tool evidence — this class is empty on legitimate runs. "
            "Treat as possible prompt injection or a verdict-gate bug. "
            "See promotion-alarms.jsonl."
        )
        for rec in promotion_alarms[:10]:
            lines.append(
                f"  - {_line(rec.get('file', '?'))}:"
                f"{_line(rec.get('function', '?'), max_chars=60)} "
                f"[{_line(rec.get('stage', '?'), max_chars=20)}]"
            )
        if len(promotion_alarms) > 10:
            lines.append(f"  ... and {len(promotion_alarms) - 10} more")

    unrecorded = report.get("unrecorded_reads", [])
    if unrecorded:
        total_funcs = sum(len(u["functions"]) for u in unrecorded)
        lines.append("")
        lines.append(f"### Unrecorded reads ({total_funcs} functions in "
                     f"{len(unrecorded)} files)")
        lines.append("Files you read but have functions without a record call.")
        lines.append("Use `--related-to <primary_file>:<primary_function>` "
                     "to record ancillary reviews.")
        for u in unrecorded[:10]:
            fn_list = ", ".join(_line(fn, max_chars=80) for fn in u["functions"][:5])
            extra = len(u["functions"]) - 5
            suffix = f" (+{extra} more)" if extra > 0 else ""
            lines.append(f"  {_line(u['file'])}: {fn_list}{suffix}")
        if len(unrecorded) > 10:
            lines.append(f"  ... and {len(unrecorded) - 10} more files")

    return "\n".join(lines)

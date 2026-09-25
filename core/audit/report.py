"""Final summary report generation for /audit runs.

Reads the review journal (per-run ``review-journal.jsonl`` and the
project-level ``review-journal-index.json``), ``findings.json``, and
annotations to produce a human-readable summary and structured
report. ``coverage-audit.json`` was removed under the annotation →
journal migration; the journal is the authoritative LLM review
store.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from core.atomic_fs import write_text_atomically
from core.coverage.journal import is_mechanical_echo as _is_mechanical_echo
from core.coverage.record import READS_MANIFEST, read_manifest_lines
from core.json import load_json, save_json
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
    # Backticks are stripped, not escaped: several call sites wrap the
    # value in a code span, and an embedded backtick would terminate
    # the span and render the remainder as live markdown. Outside a
    # span a backtick in these values (paths, names, language ids) is
    # never meaningful, so stripping loses nothing.
    return sanitise_string(text.replace("`", ""), max_chars=max_chars)


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


# Tree-class grouping for finding lists: production findings render
# first, non-production trees follow under labeled subsections with
# counts. Insertion order here IS the render order.
_TREE_CLASS_GROUP_LABELS = {
    "vendored-compat": "Vendored / compat tree",
    "test-harness": "Test-harness tree",
}


def _finding_tree_class(finding: dict[str, Any]) -> str:
    """Tree class for report grouping: the finding's own ``tree_class``
    tag when it carries one, else the path-only classifier — pre-tag
    findings.json records must group the same way as freshly emitted
    ones."""
    tree_class = str(finding.get("tree_class") or "")
    if tree_class == "production" or tree_class in _TREE_CLASS_GROUP_LABELS:
        return tree_class
    try:
        from .tree_class import classify_tree_class
        return classify_tree_class(str(finding.get("file") or ""))
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("tree-class fallback failed", exc_info=True)
        return "production"


def _group_findings_by_tree(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[tuple[str, list[dict[str, Any]]]]]:
    """``(production, [(tree_class, findings), ...])`` — grouping only,
    never a filter: every input finding appears exactly once."""
    production: list[dict[str, Any]] = []
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in findings:
        tree_class = _finding_tree_class(finding)
        if tree_class in _TREE_CLASS_GROUP_LABELS:
            grouped.setdefault(tree_class, []).append(finding)
        else:
            production.append(finding)
    ordered = [
        (tc, grouped[tc]) for tc in _TREE_CLASS_GROUP_LABELS if tc in grouped
    ]
    return production, ordered


def generate_report(
    out_dir: Path,
    *,
    target_path: Path | None = None,
    final_status: str | None = None,
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
    if final_status:
        # The report is deliberately generated BEFORE the lifecycle
        # transition (a completed stamp must never exist without its
        # report — the resume --reopen recovery depends on that), so
        # the on-disk status still reads "running" here. The caller
        # passes the terminal status it is about to stamp; the
        # completeness block names the run's real end state instead
        # of a mid-finalisation snapshot.
        completeness["run_status"] = final_status
        if final_status == "completed":
            completeness["partial"] = bool(completeness.get("missing"))
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

    # Analysis gaps: files a parser abandoned (budget exceeded,
    # escaped parse error). Counted here so a crafted file that
    # defeats a parser is visible in the report, never a silent skip.
    from core.run.gaps import gap_summary
    analysis_gaps = gap_summary(out_dir)
    if analysis_gaps:
        report["analysis_gaps"] = {
            "count": sum(analysis_gaps.values()),
            "reasons": analysis_gaps,
        }

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
        # Completeness honesty: dark rows the /validate post-pass never
        # adjudicated (cap-deferred, or the post-pass never ran) are
        # stated with the exact follow-up command — they must not
        # dead-end silently.
        _annotate_dark_awaiting(
            completeness, out_dir, len(dark_findings), target_path,
        )

    # A /validate post-pass that never ran leaves every emitted
    # finding unvalidated — the skip reason must reach the report
    # summary, not just the on-disk record (unconditional: a run with
    # zero dark rows still owes this statement).
    _annotate_validate_postpass(completeness, out_dir, target_path)

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

    # CPG build outcome (failed → the Joern channel was lost for the
    # run; retried → it was rescued at derived-max limits): channel
    # loss must be named in the report, not just a mid-run log line —
    # zero joern receipts otherwise read as "tool found nothing".
    try:
        from .joern_backend import load_cpg_build_status
        cpg_build = load_cpg_build_status(out_dir)
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("CPG build status load failed", exc_info=True)
        cpg_build = None
    if cpg_build:
        report["joern_cpg_build"] = cpg_build

    # Mid-run channel-health trips (the joern gate): a tripped channel
    # skipped its remaining dispatches for the run — its zero-receipt
    # tiers mean "channel went down", not "tool found nothing", and
    # the operator must see that distinction stated.
    try:
        tier_diag = load_json(
            out_dir / "tier-diagnostics.json", max_bytes=_MAX_STATE_BYTES,
        )
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("tier diagnostics load failed", exc_info=True)
        tier_diag = None
    health = (tier_diag or {}).get("channel_health")
    if isinstance(health, dict):
        tripped_channels = {
            name: rec for name, rec in health.items()
            if isinstance(rec, dict)
            and (rec.get("tripped") or rec.get("gated_spends"))
        }
        if tripped_channels:
            report["channel_health"] = tripped_channels

    # Substrate skips: dispatches a tier refused because its
    # substrate provably cannot model the target (e.g. coccinelle on
    # a PHP tree). Zero receipts from such a tier mean "could not
    # look", not "looked and found nothing" — the report must say so.
    substrate_skips: dict[str, dict[str, Any]] = {}
    for tier_name, rec in (tier_diag or {}).items():
        if not isinstance(rec, dict):
            continue
        count = rec.get("skipped_substrate")
        if isinstance(count, int) and count > 0:
            substrate_skips[tier_name] = {
                "count": count,
                "languages": rec.get("substrate_skip_languages") or {},
            }
    if substrate_skips:
        report["substrate_skips"] = substrate_skips

    # CodeQL database provisioning outcome: languages left without a
    # database (skipped builds, timed-out or failed background builds)
    # must reach the operator with the flag or marker that would
    # provide one — the channel never skips silently.
    try:
        from .codeql_provision import load_provision_status
        provision = load_provision_status(out_dir)
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("codeql provision status load failed", exc_info=True)
        provision = None
    if provision and (
        provision.get("skipped")
        or provision.get("build_timed_out")
        or provision.get("build_aborted")
        or provision.get("build_failed")
    ):
        report["codeql_provision"] = provision

    # Phase aborts (persistent LLM auth refusal): a listed phase
    # produced NO trustworthy output — its empty results must not be
    # read as "phase ran and found nothing". Written at abort time by
    # the orchestrator (_record_phase_abort).
    phase_aborts = load_phase_aborts(out_dir)
    if phase_aborts:
        report["phase_aborts"] = phase_aborts

    # Decomp-tree sweep (binary targets): the tree-wide decompiler
    # Semgrep pass writes decomp-sweep.json — including its loud-skip
    # records, which must reach the operator — and the tree's
    # conformance metric is the honest denominator for the coverage
    # line (never "files emitted", which over-counts unparseable
    # pseudo-C the sweep could not actually read).
    decomp_sweep = _load_decomp_sweep(out_dir)
    if decomp_sweep:
        report["decomp_sweep"] = decomp_sweep

    report["summary"] = _format_summary(report)
    return report


def _load_decomp_sweep(out_dir: Path) -> dict[str, Any] | None:
    """Summary view of ``decomp-sweep.json`` (+ its conformance
    denominator) for the report — counts and skip reasons only; the
    per-finding records stay in the artifact.
    """
    path = Path(out_dir) / "decomp-sweep.json"
    if not path.is_file():
        return None
    try:
        data = load_json(path, max_bytes=_MAX_FINDINGS_BYTES)
    except Exception:  # noqa: BLE001 — reporting must not fail the run
        logger.debug("decomp-sweep record load failed", exc_info=True)
        return None
    if not isinstance(data, dict):
        return None
    if data.get("skipped"):
        return {"skipped": True,
                "skip_reason": str(data.get("skip_reason", ""))}
    out: dict[str, Any] = {
        "skipped": False,
        "rules_run": len(data.get("rules_run") or []),
        "rules_errored": len(data.get("rules_errored") or {}),
        "findings_total": int(data.get("findings_total", 0) or 0),
        "mapped": int(data.get("mapped", 0) or 0),
        "unmapped": int(data.get("unmapped", 0) or 0),
        "journal_rows": int(data.get("journal_rows", 0) or 0),
    }
    tree_root = data.get("tree_root")
    if tree_root:
        conf_path = Path(str(tree_root)) / "decomp-tree-conformance.json"
        try:
            if conf_path.is_file():
                conf = load_json(conf_path, max_bytes=_MAX_STATE_BYTES)
                if isinstance(conf, dict):
                    out["conformance"] = {
                        "parsed_rate": conf.get("parsed_rate"),
                        "files_total": int(
                            conf.get("files_total", 0) or 0),
                        "quarantine_total": int(
                            conf.get("quarantine_total", 0) or 0),
                    }
        except Exception:  # noqa: BLE001 — reporting must not fail the run
            logger.debug("decomp-tree conformance load failed",
                         exc_info=True)
    return out


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
    # Lazy fallback: dict.get's default argument would recompute the
    # summary on EVERY call even when the report already carries one.
    summary = report.get("summary")
    if summary is not None:
        return summary
    return _format_summary(report)


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
        # Latest entry per edge key BEFORE classifying (same discipline
        # as _load_review_state): the journal is append-only, so a
        # re-reviewed finding->clean edge would otherwise keep listing
        # the stale finding row from the superseded entry.
        latest: dict[str, Any] = {}
        for entry in load_entries(out_dir):
            callee_id = getattr(entry, "edge_callee", None)
            if not callee_id or entry.verdict == "error":
                continue
            prev = latest.get(entry.key)
            if prev is None or entry.ts > prev.ts:
                latest[entry.key] = entry
        reviewed_keys = set(latest)
        for entry in latest.values():
            if entry.verdict == "finding":
                findings.append({
                    "caller": f"{entry.file}:{entry.function}",
                    "callee": entry.edge_callee,
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
    save_json(path, serializable)
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

    # Findings — production tree first; vendored/compat and
    # test-harness findings follow under labeled subsections with
    # counts (grouped, never dropped: a harness overflow is still a
    # legitimate detection, just not what the operator reads first).
    if findings:
        lines.append("## Findings")
        lines.append("")
        production, grouped = _group_findings_by_tree(findings)
        for f in production:
            lines.extend(_finding_md_lines(f, heading="###"))
        for tree_class, group in grouped:
            label = _TREE_CLASS_GROUP_LABELS[tree_class]
            lines.append(f"### {label} findings ({len(group)})")
            lines.append("")
            for f in group:
                lines.extend(_finding_md_lines(f, heading="####"))

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

    # Decomp-tree sweep (binary targets): the coverage line cites the
    # conformance metric's parsed fraction as its denominator — a
    # missing metric renders "parse rate unavailable", never an
    # assumed 100% — and states the mapped/unmapped split (unmapped
    # matches are recorded in decomp-sweep.json, never dropped).
    ds = report.get("decomp_sweep")
    if ds:
        lines.append("## Decomp-tree sweep")
        lines.append("")
        if ds.get("skipped"):
            lines.append(
                "Skipped — "
                f"{_line(ds.get('skip_reason') or 'unknown reason', max_chars=500)}"
            )
        else:
            conf = ds.get("conformance") or {}
            rate = conf.get("parsed_rate")
            if isinstance(rate, (int, float)):
                cov = (
                    f"{rate:.0%} of "
                    f"{int(conf.get('files_total', 0) or 0)} decomp-tree "
                    "file(s) parsed"
                )
            elif conf:
                # Metric exists but no tool leg could measure
                # (parsed_rate null) — distinct from a missing metric.
                cov = (
                    "parse rate unavailable (conformance metric "
                    "present but no tool leg could measure — see "
                    "decomp-tree-conformance.json)"
                )
            else:
                cov = (
                    "parse rate unavailable (no conformance metric "
                    "recorded for the swept tree)"
                )
            lines.append(
                f"Sweep coverage: {cov}; "
                f"{ds.get('rules_run', 0)} rule file(s) run; "
                f"{ds.get('findings_total', 0)} match(es) — "
                f"{ds.get('mapped', 0)} mapped to functions "
                f"({ds.get('journal_rows', 0)} journal row(s)), "
                f"{ds.get('unmapped', 0)} unmapped (recorded in "
                "decomp-sweep.json, never dropped)."
            )
            quarantined = int(conf.get("quarantine_total", 0) or 0)
            if quarantined:
                lines.append(
                    f"{quarantined} tree file(s) quarantined as "
                    "unparseable — see decomp-tree-conformance.json."
                )
            errored = int(ds.get("rules_errored", 0) or 0)
            if errored:
                lines.append(
                    f"{errored} rule file(s) errored (recorded in "
                    "decomp-sweep.json) — their silence is not "
                    "coverage."
                )
        lines.append("")

    # Analysis gaps
    analysis_gaps = report.get("analysis_gaps")
    if analysis_gaps:
        lines.append("## Analysis Gaps")
        lines.append("")
        lines.append(
            f"{analysis_gaps['count']} file record(s) NOT analysed — "
            "a parser abandoned them:"
        )
        lines.append("")
        for reason, count in sorted(analysis_gaps["reasons"].items()):
            lines.append(f"- {_cell(reason, max_chars=80)}: {count}")
        lines.append("")
        lines.append("See analysis-gaps.jsonl for the per-file records.")
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
    # Atomic write, pinned utf-8 (the atomic writer's default): the
    # platform default encoding (POSIX locale → ASCII) once crashed
    # the report write at run end, and a bare write_text at the
    # predictable name follows a symlink planted in the reused,
    # sandbox-writable run dir.
    write_text_atomically(path, content)
    return path


def _finding_md_lines(
    f: dict[str, Any], *, heading: str = "###",
) -> list[str]:
    """One finding's markdown block — THE single per-finding render
    seam: the production list and every tree-class subsection all
    render through here. Any per-finding marker (e.g. a provisional
    flag) must render inside this helper, or it silently misses one
    of those paths.

    LLM-derived free text (title) and labels (id, tier, file, line,
    depth) — single-line sanitised so a crafted value cannot break
    out of the heading or inject markup."""
    fid = _line(f.get("id", "FIND-???"), max_chars=80)
    title = _line(f.get("title", "Untitled"))
    tier = _line(
        _tier_title(f.get("evidence_tier", "heuristic")),
        max_chars=40,
    )
    file_loc = _line(f.get("file", "?"))
    line_no = _line(f.get("line", "?"), max_chars=20)
    depth = _line(f.get("depth", "?"), max_chars=40)
    block = [
        f"{heading} {fid}: {title} ({tier})",
        (
            f"**File:** {file_loc}:{line_no}  "
            f"**Depth:** {depth}  "
            f"**Evidence:** {tier}"
        ),
    ]
    if f.get("provisional"):
        # Cadence-tick promotion whose confirming post-loop pass
        # never ran — completed runs strip the mark at finalization,
        # so its presence means the run was interrupted first.
        block.append(
            "*Provisional at time of writing — the run was "
            "interrupted before the post-loop pass could "
            "confirm or retract this promotion.*"
        )
    block.append("")
    return block


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
            # Span end travels with the record so the verdict-override
            # join can bind a finding's line to its containing site.
            "line_end": getattr(entry, "line_end", None),
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


def _as_line(value: Any) -> int:
    """``value`` as a non-negative int line number; 0 when unusable."""
    try:
        n = int(value or 0)
    except (TypeError, ValueError):
        return 0
    return n if n > 0 else 0


def _site_covers(site: dict[str, Any], line: int) -> bool:
    """True when the journal site's span contains ``line``.

    A positioned site without a usable ``line_end`` matches only an
    exact ``line_start`` hit — the span's extent is unknown, so
    containment cannot be claimed.
    """
    start = _as_line(site.get("line_start"))
    if not start:
        return False
    end = _as_line(site.get("line_end"))
    if end >= start:
        return start <= line <= end
    return line == start


def _match_journal_site(
    finding: dict[str, Any],
    sites: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Pick the journal record for the SITE the finding belongs to.

    Journal review records are kept latest-per-site — (file,
    function, line_start) — because same-named checklist items
    (function + prototype, macro redefinitions) are distinct review
    subjects. Findings carry the vulnerable line, so a lined finding
    binds only to the site whose span contains that line: a benign
    verdict on the OTHER same-named site must never override — let
    alone drop — this one.

    Fallbacks stay in the never-suppress-without-evidence direction:

    - Finding has a line and positioned sites exist, but none covers
      the line → no match; the finding passes through untouched.
    - Finding has no line, or every same-name row is span-unknown
      (``line_start`` 0/absent) → coarse name-level join, preferring
      a non-benign row over a benign one instead of last-wins, so an
      unlocatable benign twin never retires a live verdict by mere
      row order.
    """
    if not sites:
        return None
    line = _as_line(finding.get("line"))
    positioned = [s for s in sites if _as_line(s.get("line_start"))]
    if line and positioned:
        covering = [s for s in positioned if _site_covers(s, line)]
        if not covering:
            return None
        # Nested spans: the innermost (largest line_start) is the
        # most specific review subject for this line.
        return max(covering, key=lambda s: _as_line(s.get("line_start")))
    non_benign = [
        s for s in sites if s.get("status") not in _BENIGN_VERDICTS
    ]
    pool = non_benign or sites
    return pool[-1]


def _apply_journal_verdict_overrides(
    findings: list[dict[str, Any]],
    audit_data: dict[str, Any],
) -> list[dict[str, Any]]:
    """JOIN semantics: findings.json is emit-only at /audit run end;
    the journal is authoritative for current verdict.

    Two behaviours:

    - **Status override**: when the journal's latest entry for a
      finding's site disagrees with the finding's status, the
      finding's ``status`` field is overwritten from the journal and
      ``_verdict_source="journal"`` is stamped for audit-trail
      visibility. Site resolution is per (file, function,
      line-span) via :func:`_match_journal_site` — the coarse
      (file, function) join collapsed same-named sites, letting a
      clean prototype/macro-twin verdict drop the other site's
      finding.
    - **Benign drop**: when the journal reports a benign verdict
      (``clean``, ``dormant``) — i.e. Reflexion refuted the finding
      after initial emission — the finding is dropped from the
      returned list entirely. Without this, ``findings_count`` +
      the report's Findings section still tally refuted issues,
      defeating the JOIN's whole purpose.

    Mechanical echo rows carry no verdict authority here — they are
    pattern-scan echoes journalled for cross-layer visibility, not
    LLM reviews (the same exclusion the reviewed-stats counting
    applies).

    Returns the filtered list (never mutates the input list's
    length in place).
    """
    by_name: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for func in audit_data.get("functions_analysed", []):
        f = func.get("file", "")
        fn = func.get("function", "")
        status = func.get("status")
        if f and fn and status and not func.get("mechanical"):
            by_name.setdefault((f, fn), []).append(func)

    out: list[dict[str, Any]] = []
    for finding in findings:
        sites = by_name.get(
            (finding.get("file", ""), finding.get("function", "")), [],
        )
        site = _match_journal_site(finding, sites)
        journal_verdict = site.get("status") if site else None
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


def _annotate_dark_awaiting(
    completeness: dict[str, Any],
    out_dir: Path,
    dark_total: int,
    target_path: Path | None,
) -> None:
    """State how many dark findings are still awaiting /validate.

    Reads ``validate-postpass.json`` (written by ``core.audit.validate``
    with the post-pass selection record). When the record is absent —
    the post-pass never ran, or predates the record — every dark row
    counts as awaiting. Sets ``dark_awaiting`` + ``dark_followup`` on
    the completeness block; a zero-awaiting run sets neither.
    """
    awaiting = dark_total
    record = None
    record_path = out_dir / "validate-postpass.json"
    if record_path.is_file():
        record = load_json(record_path, max_bytes=_MAX_RUN_META_BYTES)
    if isinstance(record, dict):
        # The record lives in a directory the dispatched CC child and
        # the target can write mid-run, and the follow-up renders as
        # an operator-facing EXACT re-run command. The old prefix
        # gate (accept anything starting "/validate ") let a run-dir
        # writer splice arbitrary operator instructions into the
        # remainder — so the recorded value is never consumed at all:
        # the command is rebuilt locally below from the run's own
        # metadata, which is exactly what the writer derives it from.
        try:
            recorded = int(record.get("dark_awaiting", dark_total))
            selected = int(record.get("dark_selected", 0))
        except (TypeError, ValueError):
            recorded, selected = dark_total, 0
        # The record is a selection-time snapshot; the run can both
        # RESOLVE dark rows after it (dark verification runs later)
        # and ADD new ones (post-loop demotions). Count late-added
        # rows as awaiting, and never claim more awaiting rows than
        # the graded export still carries.
        awaiting = min(max(recorded, dark_total - selected), dark_total)
    if awaiting <= 0:
        return
    # Local rebuild in ALL cases: the run's own metadata carries the
    # target (the main report path — libexec/raptor-audit's finalise —
    # does not pass target_path), and the findings path is fixed.
    target = str(target_path) if target_path else _run_meta_target(out_dir)
    # --include-dark: the validate import routes dark rows to the
    # witness backlog by default — this follow-up exists precisely to
    # adjudicate them, so it carries the explicit opt-in.
    followup = (
        f"/validate {target or '<target>'} "
        f"--findings {out_dir / 'findings-graded.json'} "
        f"--include-dark"
    )
    completeness["dark_awaiting"] = awaiting
    completeness["dark_followup"] = followup


def _annotate_validate_postpass(
    completeness: dict[str, Any],
    out_dir: Path,
    target_path: Path | None,
) -> None:
    """Surface a skipped /validate post-pass on the completeness block.

    Reads ``validate-postpass.json``. When the post-pass never ran,
    ``validate_postpass_skipped`` carries the recorded reason and
    ``validate_postpass_followup`` the exact re-run command — without
    this the reason lives only in the record file and the summary
    reads as if the findings had been validated. The record lives in
    a directory the dispatched CC child can write, so the reason is
    sanitised at render time and the follow-up command is always
    rebuilt locally (same policy as the dark followup) — the record's
    own ``followup_command`` is never consumed.
    """
    record_path = out_dir / "validate-postpass.json"
    if not record_path.is_file():
        return
    record = load_json(record_path, max_bytes=_MAX_RUN_META_BYTES)
    if not isinstance(record, dict) or record.get("ran") is not False:
        return
    reason = record.get("skipped_reason")
    if not isinstance(reason, str) or not reason.strip():
        reason = "unknown (no reason recorded)"
    completeness["validate_postpass_skipped"] = reason
    # Local rebuild in ALL cases — same policy (and rationale) as the
    # dark follow-up: the recorded command sits in a child/target-
    # writable file and renders as an operator-facing exact re-run
    # line, and the local derivation is what the writer used anyway.
    target = str(target_path) if target_path else _run_meta_target(out_dir)
    # --include-dark: the skipped post-pass would have carried its
    # selected dark rows into candidacy; the equivalent re-run must
    # opt in the same way (the import chokepoint otherwise routes
    # them to the witness backlog).
    followup = (
        f"/validate {target or '<target>'} "
        f"--findings {out_dir / 'findings-graded.json'} "
        f"--include-dark"
    )
    completeness["validate_postpass_followup"] = followup


def _run_meta_target(out_dir: Path) -> str:
    """Target path recorded in the run metadata, or ""."""
    meta_path = out_dir / ".raptor-run.json"
    if not meta_path.is_file():
        return ""
    meta = load_json(meta_path, max_bytes=_MAX_RUN_META_BYTES)
    if isinstance(meta, dict):
        return str(meta.get("target_path") or "")
    return ""


def _load_vendored_triage(out_dir: Path) -> dict[str, int]:
    """Count vendored/generated triage decisions from the
    suppressions.jsonl audit trail (rule_id ``audit:vendored-triage``).
    Returns ``{}`` when the tier made no decisions."""
    path = out_dir / "suppressions.jsonl"
    if not path.exists():
        return {}
    skipped = glanced = 0
    try:
        with Path(path).open(encoding="utf-8") as f:  # raw-open: RAPTOR-written report artifact in the run dir
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
    manifest_path = out_dir / READS_MANIFEST
    checklist_path = out_dir / "checklist.json"
    if not manifest_path.exists() or not checklist_path.exists():
        return []

    # Chokepoint reader, never a bespoke parser: the manifest sits in
    # the sandbox write grant, and a raw ``.open()`` here followed a
    # planted symlink, blocked forever on a planted FIFO (wedging
    # report finalize), and buffered an unbounded plant — exactly the
    # attacks the shared reader refuses (lstat S_ISREG + 64 MiB cap).
    read_paths = read_manifest_lines(manifest_path)
    if not read_paths:
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
    # Dark rows the /validate post-pass never adjudicated — stated
    # unconditionally (a completed run can still owe these), with the
    # exact follow-up command.
    dark_awaiting = int(completeness.get("dark_awaiting", 0) or 0)
    if dark_awaiting:
        lines.append(
            f"{dark_awaiting} dark finding(s) awaiting validation "
            "(tool-blind — never entered the /validate post-pass)."
        )
        followup = completeness.get("dark_followup")
        if followup:
            lines.append(f"  Follow up: {_line(followup, max_chars=400)}")
    # A skipped /validate post-pass means NO emitted finding was
    # validated — stated with the recorded reason and the exact
    # re-run command, never left to the on-disk record alone.
    skipped = completeness.get("validate_postpass_skipped")
    if skipped:
        lines.append(
            "/validate post-pass skipped — findings were not "
            f"validated: {_line(skipped, max_chars=300)}"
        )
        vp_followup = completeness.get("validate_postpass_followup")
        if vp_followup:
            lines.append(
                f"  Re-run: {_line(vp_followup, max_chars=400)}"
            )
    return lines


def _summary_finding_line(f: dict[str, Any]) -> str:
    """One finding's summary list line. LLM-derived values — sanitise
    so a crafted title / path cannot inject extra lines or live markup
    into the summary."""
    severity = _line(str(f.get("severity", "medium")).title(), max_chars=40)
    return (
        f"- [{severity}] {_line(f.get('title', 'Untitled'))} "
        f"({_line(f.get('file', '?'))}:"
        f"{_line(f.get('line', '?'), max_chars=20)})"
    )


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
        # Production tree first; non-production trees grouped after,
        # labeled with counts (see _group_findings_by_tree).
        production, grouped = _group_findings_by_tree(findings)
        lines.extend(_summary_finding_line(f) for f in production)
        for tree_class, group in grouped:
            lines.append(
                f"{_TREE_CLASS_GROUP_LABELS[tree_class]} ({len(group)}):"
            )
            lines.extend(
                "  " + _summary_finding_line(f) for f in group
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
        elif interrupted:
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
        else:
            # Errored (never interrupted): the record exists exactly
            # because the taint query failed — restart wording here
            # would misattribute the loss.
            n_errors = len(presweep.get("errors") or [])
            lines.append(
                "### ⚠️ Joern pre-sweep errored"
            )
            lines.append(
                f"The taint query errored ({n_errors} error(s)) — "
                f"this run's taint-flow evidence is incomplete "
                f"(functions read as 'no flows' rather than "
                f"'not swept'). Re-run /audit or /agentic to "
                f"regenerate the sweep."
            )

    cpg_build = report.get("joern_cpg_build")
    if cpg_build:
        lines.append("")
        first_heap = cpg_build.get("first_heap_mb")
        first_wall = cpg_build.get("first_timeout_s")
        retry_heap = cpg_build.get("retry_heap_mb")
        retry_wall = cpg_build.get("retry_timeout_s")
        attempts = (
            f"first attempt heap="
            f"{first_heap if first_heap else 'default'} MB / "
            f"timeout={first_wall}s"
        )
        if cpg_build.get("retried"):
            attempts += (
                f"; derived-max retry heap={retry_heap} MB / "
                f"timeout={retry_wall}s"
            )
        if cpg_build.get("failed"):
            lines.append("### ⚠️ Joern channel lost — CPG build failed")
            what = (
                "The CPG built but failed to import into the server"
                if cpg_build.get("phase") == "import"
                else "The CPG build failed"
            )
            lines.append(
                f"{what} ({attempts}), so this run carries NO Joern "
                f"receipts — hypotheses read as 'not looked at', "
                f"never as refuted. Remedies: raise "
                f"joern_heap_ceiling_mb / joern_cpg_timeout_s in "
                f"tuning.json, or narrow --scope."
            )
        else:
            # Rescued by the derived-max retry — worth one line so
            # the doubled wall is attributable.
            lines.append(
                f"Joern CPG build succeeded on the derived-max retry "
                f"({attempts})."
            )

    channel_health = report.get("channel_health")
    if channel_health:
        for raw_name, rec in sorted(channel_health.items()):
            # trip_reason originates from channel error strings
            # (Joern/tool stderr that can echo target-derived bytes)
            # persisted in tier-diagnostics.json — sanitise like every
            # sibling block; the channel name rides the same records.
            name = _line(raw_name, max_chars=40)
            lines.append("")
            if rec.get("tripped"):
                lines.append(
                    f"### ⚠️ {name} channel unhealthy (mid-run trip)"
                )
                reason = _line(
                    rec.get("trip_reason")
                    or "consecutive dispatch failures",
                    max_chars=200,
                )
                lines.append(
                    f"The {name} channel tripped its health gate "
                    f"({reason}) and its remaining dispatches were "
                    f"skipped — hypotheses after the trip carry no "
                    f"{name} receipts. Skipped is not refuted: treat "
                    f"the missing receipts as unanswered questions. "
                    f"{rec.get('total_successes', 0)} dispatch(es) "
                    f"completed before the trip, "
                    f"{rec.get('total_errors', 0)} failed."
                )
            else:
                lines.append(f"### ⚠️ {name} channel down")
            for phase in rec.get("gated_spends", []):
                lines.append(
                    f"  - {_line(phase, max_chars=40)} skipped at $0 — "
                    f"its LLM spend only pays into the {name} channel, "
                    f"which was down for this run"
                )

    provision = report.get("codeql_provision")
    if provision:
        lines.append("")
        lines.append("### ⚠️ CodeQL database(s) missing")
        for skip in provision.get("skipped", [])[:10]:
            lines.append(
                f"  - {_line(skip.get('language', '?'), max_chars=20)}: "
                f"{_line(skip.get('reason', '?'), max_chars=160)} — "
                f"{_line(skip.get('remedy', '?'), max_chars=160)}"
            )
        if provision.get("build_timed_out"):
            lines.append(
                "  - background database build did not finish inside "
                "this run's wait budget (it completes into the shared "
                "cache — the next run reuses it)"
            )
        if provision.get("build_aborted"):
            lines.append(
                "  - background database build wait was interrupted "
                "by a shutdown request — not a wait-budget timeout"
            )
        if provision.get("build_failed"):
            lines.append(
                "  - background database build failed (see the run "
                "log); pass --codeql-db <path> to supply one"
            )
        lines.append(
            "  CodeQL steps for the affected language(s) were skipped, "
            "not refuted."
        )

    substrate_skips = report.get("substrate_skips")
    if substrate_skips:
        lines.append("")
        lines.append("### ⚠️ Substrate skips (tier could not look)")
        for tier_name, rec in sorted(substrate_skips.items()):
            langs = {
                k: v for k, v in (rec.get("languages") or {}).items()
                if isinstance(v, int)
            }
            dominant = max(langs, key=langs.__getitem__) if langs else ""
            lang_note = (
                f" — dominant unmodeled language "
                f"`{_line(dominant, max_chars=20)}`"
                if dominant and dominant != "unknown" else ""
            )
            lines.append(
                f"  - {_line(tier_name, max_chars=30)}: "
                f"{rec.get('count', 0)} check(s) skipped because the "
                f"target is outside this tier's substrate{lang_note}; "
                f"the tier contributed no verdicts to those checks."
            )
        lines.append(
            "  Skipped is not refuted: these hypotheses were never "
            "examined by the skipping tier."
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

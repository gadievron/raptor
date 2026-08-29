"""Opt-in listwise ranking of findings before per-finding analysis.

Rank-then-spend: on large targets the post-dedup finding queue is
longer than the analysis budget (``--max-cost`` / ``--max-findings``),
and without ordering the cap truncates an arbitrary suffix of the
queue. This stage reorders the queue by expected follow-up value so
the cap cuts the least promising tail instead.

Ordering only — a finding is never dropped, classified, or suppressed
here. A wrong ranking misprioritises; the verdict machinery downstream
stays authoritative. On any failure the original order is returned and
the pipeline proceeds unranked.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# How much of each finding the ranker sees. Kept small on purpose:
# batches of ~10 renderings share one prompt, and triage-grade signal
# (tool, rule, CWE, location, message) fits comfortably in this cap.
# Finding text originates in the scanned (untrusted) repo, so every
# field is length-capped and flattened to one line here; the ranking
# module adds nonce-fenced envelopes and control-char escaping.
_MAX_MESSAGE_CHARS = 400
_MAX_FIELD_CHARS = 120

# Fraction of the operator's --max-cost the ranking pass may spend.
# Analysis is the main event; ranking is a cheap opening move.
_RANK_BUDGET_FRACTION = 0.10

_TRIAGE_QUERY = (
    "Rank these static-analysis findings by expected value for "
    "follow-up vulnerability analysis. Prefer likely true positives, "
    "practical exploitability, attacker-controlled input reaching a "
    "dangerous sink, clear dataflow evidence, and meaningful security "
    "impact. Rank lower: likely false positives, test-only or "
    "unreachable code, informational notes, and findings with too "
    "little context to judge."
)


def _field(value: Any, cap: int = _MAX_FIELD_CHARS) -> str:
    """Flatten an untrusted finding field to one capped line."""
    text = str(value) if value not in (None, "") else "?"
    text = text.replace("\r", " ").replace("\n", " ")
    return text[:cap] or "?"


def _render_finding(finding: Any) -> str:
    """Compact triage rendering of one prep-report finding dict."""
    if not isinstance(finding, dict):
        return _field(finding, cap=_MAX_MESSAGE_CHARS)
    get = finding.get
    location = "{}:{}".format(
        _field(get("file_path") or get("file")),
        _field(get("start_line") or get("line"), cap=12),
    )
    message = _field(
        get("message") or get("description") or get("title"),
        cap=_MAX_MESSAGE_CHARS,
    )
    lines = [
        f"tool: {_field(get('tool'))}",
        f"rule: {_field(get('rule_id') or get('check_id'))}",
        f"severity: {_field(get('severity'))}",
        f"cwe: {_field(get('cwe_id'))}",
        f"location: {location}",
        f"function: {_field(get('function') or get('function_name'))}",
        f"dataflow: {'yes' if get('has_dataflow') else 'no'}",
        f"message: {message}",
    ]
    # Checklist-derived priority (understand-bridge entry points,
    # firmware high-value targets, reachability demotions) — the
    # ranker should see the same signal the analysis prompt renders.
    meta = get("metadata") if isinstance(get("metadata"), dict) else {}
    priority = get("priority") or meta.get("priority")
    if priority:
        reason = get("priority_reason") or meta.get("priority_reason")
        line = f"priority: {_field(priority, cap=16)}"
        if reason:
            line += f" ({_field(reason, cap=80)})"
        lines.append(line)
    return "\n".join(lines)


def rank_findings_for_analysis(
    findings: list[Any],
    llm_config: Any,
    query: str = _TRIAGE_QUERY,
) -> tuple[list[Any], float, str]:
    """Reorder ``findings`` most-promising-first.

    Returns ``(ordered_findings, cost_usd, model_name)``. Best-effort:
    any failure (no usable model, ranking error) returns the input
    order with zero cost. Requires an external-LLM config — under
    CC-only dispatch there is no client to rank with, so the stage
    logs and passes through.
    """
    if len(findings) < 3:
        return findings, 0.0, ""
    if not (llm_config and getattr(llm_config, "primary_model", None)):
        logger.info(
            "ranking stage skipped: no external LLM configured "
            "(CC-only dispatch)",
        )
        print("  Ranking skipped — needs an external analysis model")
        return findings, 0.0, ""

    try:
        import copy

        from core.llm.client import LLMClient
        from core.llm.ranking import rank_items

        # Ranking gets a slice of the operator's budget, never the
        # whole cap — the LLMClient budget gate is instance-local, so
        # an uncapped rank client could spend the full --max-cost
        # before analysis starts.
        rank_config = llm_config
        cap = float(getattr(llm_config, "max_cost_per_scan", 0) or 0)
        if cap > 0:
            rank_config = copy.copy(llm_config)
            rank_config.max_cost_per_scan = cap * _RANK_BUDGET_FRACTION
        client = LLMClient(rank_config)
        result = rank_items(
            findings, query, client=client, render=_render_finding,
        )
        stats = result.stats
        model = None
        get_model = getattr(llm_config, "get_model_for_task", None)
        if callable(get_model):
            model = get_model("ranking")
        model_name = getattr(
            model or llm_config.primary_model, "model_name", "",
        ) or ""
        logger.info(
            "ranking stage: %d findings, %d LLM calls, %d trials, "
            "%d iterations, %d dropped batches, converged=%s, "
            "cost=$%.4f",
            len(findings), stats.llm_calls, stats.trials,
            stats.iterations, stats.dropped_batches, stats.converged,
            stats.cost,
        )
        if stats.ranked_batches == 0:
            # Every batch failed (budget, malformed responses):
            # rank_items already fell back to input order — say so
            # instead of claiming a ranking happened.
            print("  Ranking produced no signal — keeping input order")
            return findings, stats.cost, model_name
        print(
            f"  Ranked {len(findings)} findings for analysis order "
            f"({stats.llm_calls} calls, ${stats.cost:.2f})",
        )
        return [r.item for r in result.ranked], stats.cost, model_name
    except Exception as e:  # noqa: BLE001 — ranking must never break
        # the pipeline; unranked order is always a valid fallback.
        logger.warning("ranking stage failed (%s); keeping input order", e)
        return findings, 0.0, ""

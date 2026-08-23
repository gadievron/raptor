"""Opt-in listwise LLM refinement of the audit gap queue.

Refines review ORDER strictly *within* each mechanical priority tier
of the gap list (``core.audit.gaps`` / ``core.audit.priority``). The
tier policy stays authoritative: entry points stay ahead of
uncovered functions, dead code stays last, and no gap is ever added
or removed — the LLM can only reorder inside a tier. That bound
matters because the queue may be budget-truncated downstream
(``truncate_gaps_to_budget``): within-tier ranking means a
manipulated or simply wrong ranking cannot push a gap below a tier
the mechanical policy protected.

Signal level: gaps are ranked from their *metadata* (path, function
name, line span, strategy tags) — the ranker never reads function
bodies here, so this is a cheap ordering hint, not analysis. The
heavy per-function work stays in the audit loop itself.

Consumers construct their own client or let this module build the
default (``LLMClient()`` uses the session transport, so this works
on claude-code-only installs). Orchestrator-mode audits that carry a
budget-governed run client should pass it via ``client=`` so spend
lands on the run ledger (see ``_run_llm_client`` doctrine in
core/audit/orchestrator.py).
"""

from __future__ import annotations

import logging
from itertools import groupby
from typing import Any

logger = logging.getLogger(__name__)

# Only the head of the queue is worth LLM attention: the audit loop
# reads the queue front-to-back and deep tails are rarely reached
# within a run budget.
DEFAULT_RANK_HEAD = 150

_GAP_QUERY = (
    "Rank these unreviewed functions by how likely a focused security "
    "review of the function will uncover a real, reachable "
    "vulnerability. Prefer functions that parse or transform external "
    "input, cross trust boundaries, do manual memory or length "
    "arithmetic, implement authentication, crypto, path, or permission "
    "logic, or sit close to dangerous sinks. Rank lower: trivial "
    "accessors, generated code, formatting or logging helpers, and "
    "test-only code."
)

_MAX_FIELD_CHARS = 160


def _field(value: Any, cap: int = _MAX_FIELD_CHARS) -> str:
    """Flatten an untrusted gap field to one capped line."""
    text = str(value) if value not in (None, "") else "?"
    text = text.replace("\r", " ").replace("\n", " ")
    return text[:cap] or "?"


def _render_gap(gap: Any) -> str:
    """Metadata-only rendering of one gap dict for the ranker."""
    if not isinstance(gap, dict):
        return _field(gap)
    get = gap.get
    strategies = get("strategies") or []
    if isinstance(strategies, list):
        strategies = ", ".join(str(s) for s in strategies[:8])
    span = f"{get('line_start') or '?'}-{get('line_end') or '?'}"
    return "\n".join([
        f"function: {_field(get('name'))}",
        f"file: {_field(get('file'))}",
        f"lines: {_field(span, cap=24)}",
        f"strategies: {_field(strategies)}",
        f"stale_annotation: {'yes' if get('is_stale') else 'no'}",
    ])


def _restamp_scores(ranked_items: list[dict[str, Any]]) -> None:
    """Reassign the segment's own priority_score multiset (sorted
    descending) along the LLM order, in place. No-op when the segment
    carries no scores (plain compute_gaps output)."""
    scores = [
        g.get("priority_score") for g in ranked_items
        if isinstance(g, dict) and g.get("priority_score") is not None
    ]
    if not scores:
        return
    ordered = sorted((float(s) for s in scores), reverse=True)
    it = iter(ordered)
    for gap in ranked_items:
        if isinstance(gap, dict) and gap.get("priority_score") is not None:
            gap["priority_score"] = next(it)


def rank_gap_queue(
    gaps: list[dict[str, Any]],
    *,
    client: Any = None,
    model: str | None = None,
    head: int | None = None,
    query: str = _GAP_QUERY,
    seed: int | None = None,
    max_workers: int | None = None,
    stamp_scores: bool = False,
) -> tuple[list[dict[str, Any]], str]:
    """Re-rank the gap queue within priority tiers, head-capped.

    Walks contiguous runs of equal ``priority`` (both ``compute_gaps``
    and ``score_functions`` emit tier-contiguous lists) and ranks
    inside each run until ``head`` items have been ranked; everything
    beyond keeps its mechanical order. Returns ``(gaps, note)`` where
    ``note`` is a one-line human summary. Best-effort throughout: any
    failure returns the input order unchanged.

    ``stamp_scores``: reassign each ranked segment's existing
    ``priority_score`` values (its own multiset, sorted descending)
    along the LLM order. Consumers whose downstream scheduling keys
    on ``priority_score`` rather than list order (the audit
    orchestrator's topological tiebreaks, subsystem grouping) need
    this or the re-rank only decides budget-cut membership. Scores
    never leave the segment, so tiers cannot cross.
    """
    if head is None:
        head = DEFAULT_RANK_HEAD
    if len(gaps) < 3 or head <= 0:
        return gaps, "gap ranking skipped (nothing to rank)"

    try:
        from core.llm.ranking import rank_items

        if client is None:
            from core.llm.client import LLMClient
            client = LLMClient(pinned_model=model) if model else LLMClient()

        out: list[dict[str, Any]] = []
        budget = head
        ranked_n = 0
        tiers_ranked = 0
        calls = 0
        cost = 0.0
        for _tier, run_iter in groupby(
            gaps, key=lambda g: g.get("priority") if isinstance(g, dict)
            else None,
        ):
            run = list(run_iter)
            if budget < 3 or len(run) < 3:
                out.extend(run)
                continue
            head_slice, rest = run[:budget], run[budget:]
            result = rank_items(
                head_slice, query, client=client, render=_render_gap,
                seed=seed, max_workers=max_workers,
            )
            calls += result.stats.llm_calls
            cost += result.stats.cost
            if result.stats.ranked_batches == 0:
                # No successful batch: keep the mechanical order for
                # this tier rather than pretending a ranking happened.
                # The head budget is NOT charged — a transient outage
                # on one tier shouldn't downgrade every later tier
                # (per-tier waste is bounded by rank_items' failed-
                # trial abort).
                out.extend(run)
                continue
            budget -= len(head_slice)
            ranked_items = [r.item for r in result.ranked]
            if stamp_scores:
                _restamp_scores(ranked_items)
            out.extend(ranked_items)
            out.extend(rest)
            ranked_n += len(head_slice)
            tiers_ranked += 1

        if ranked_n == 0:
            return gaps, (
                "gap ranking produced no signal — mechanical order "
                f"kept ({calls} LLM calls, ${cost:.2f})"
            )
        note = (
            f"ranked {ranked_n}/{len(gaps)} gaps within {tiers_ranked} "
            f"priority tier(s) ({calls} LLM calls, ${cost:.2f})"
        )
        return out, note
    except Exception as e:  # noqa: BLE001 — ordering refinement must
        # never break the gaps pipeline; mechanical order is always a
        # valid fallback.
        logger.warning("gap ranking failed (%s); mechanical order kept", e)
        return gaps, f"gap ranking failed ({e}); mechanical order kept"

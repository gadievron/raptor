"""CLI for ``libexec/raptor-llm-scorecard`` — research surface and
sidecar maintenance over the model scorecard.

Subcommands:
    list      — markdown table of all cells with derived columns
    compare   — side-by-side two models on shared decision_classes
    samples   — show disagreement-sample reasoning for a cell
    pin       — set policy_override on a cell
    unpin     — release a pin (set policy_override back to "auto")
    reset     — delete cells (single, --model, --older-than, --all)

Run ``raptor-llm-scorecard <subcommand> -h`` for per-subcommand
flags.  All output is markdown so operators can paste it straight
into a notebook / issue / etc.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path
from typing import Any

from core.llm.scorecard._render import scrub_cell

from .paths import default_scorecard_path
from .scorecard import (
    ALL_EVENT_TYPES,
    DEFAULT_MISS_RATE_CEILING,
    DEFAULT_SAMPLE_SIZE_FLOOR,
    EventType,
    ModelScorecard,
    Policy,
    SCHEMA_VERSION,
    DecisionClassStats,
    _wilson_upper_bound,
)


# Shared resolver (RAPTOR_SCORECARD_PATH override → RAPTOR_DIR-anchored
# → relative fallback): the CLI must read the SAME ledger analysis runs
# write, regardless of the invoking cwd. Resolved lazily at
# parser-build time, NOT frozen at import — an env override set after
# import (in-process callers, some test orders) must still win, like
# every other call site of the resolver.


# ---------------------------------------------------------------------------
# Policy + Wilson display helpers
# ---------------------------------------------------------------------------


def _policy_for_stats(
    stats: DecisionClassStats,
    *,
    sample_size_floor: int = DEFAULT_SAMPLE_SIZE_FLOOR,
    miss_rate_ceiling: float = DEFAULT_MISS_RATE_CEILING,
) -> str:
    """Re-derive the policy decision from a ``DecisionClassStats``
    snapshot. We don't read the live ``ModelScorecard.should_short_circuit``
    here because that's per-call and we want a self-contained
    interpretation of the on-disk data.

    The gate parameters default to the SUBSTRATE constants (never
    re-hardcoded literals) so this column diverges from the live gate
    only where the operator tuned a per-run knob the CLI cannot see —
    a run configured with ``scorecard_freshness_half_life_days`` or a
    custom ceiling. The default-view note in ``cmd_list`` names that
    residual; ``--freshness`` mirrors the freshness half."""
    if stats.policy_override == "force_short_circuit":
        return Policy.SHORT_CIRCUIT
    if stats.policy_override == "force_fall_through":
        return Policy.FALL_THROUGH
    correct = stats.events[EventType.CHEAP_SHORT_CIRCUIT].correct
    incorrect = stats.events[EventType.CHEAP_SHORT_CIRCUIT].incorrect
    n = correct + incorrect
    if n < sample_size_floor:
        return Policy.LEARNING
    upper = _wilson_upper_bound(correct, incorrect)
    if upper <= miss_rate_ceiling:
        return Policy.SHORT_CIRCUIT
    return Policy.FALL_THROUGH


def _format_policy(policy: str, _n: int, sample_size_floor: int = 10) -> str:
    """Operator-friendly policy label."""
    if policy == Policy.SHORT_CIRCUIT:
        return "short-circuit"
    if policy == Policy.FALL_THROUGH:
        return "fall-through"
    return f"learning (n<{sample_size_floor})"


def _drift_marker(baseline: str, current: str) -> str:
    """Prefix the policy column with a drift indicator when the freshness-weighted
    verdict differs from the unweighted baseline. Surfaces silent regressions
    (or improvements) in the `list` view when `--freshness` is used.

      * ``↓`` — was trusted (short-circuit), recent data says otherwise (the
        actionable signal — the model regressed in the recent window).
      * ``↑`` — was distrusted, recent data trusts (the recovery signal).
      * ``*`` — any other verdict change (fall-through ↔ learning).
      * ``""`` — no drift.
    """
    if baseline == current:
        return ""
    if baseline == Policy.SHORT_CIRCUIT and current != Policy.SHORT_CIRCUIT:
        return "↓ "
    if current == Policy.SHORT_CIRCUIT and baseline != Policy.SHORT_CIRCUIT:
        return "↑ "
    return "* "


def _wilson_ub_pct(
    stats: DecisionClassStats,
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
) -> float | None:
    """Wilson 95% upper bound on the chosen event slot's
    incorrect-rate as a percentage. None when n=0 (no observations).

    For ``CHEAP_SHORT_CIRCUIT`` (default) this is the miss-rate
    bound the auto-policy gate consults. For other event types
    (``MULTI_MODEL_CONSENSUS``, ``JUDGE_REVIEW``, ``TOOL_EVIDENCE``,
    ``OPERATOR_FEEDBACK``, ``REASONING_DIVERGENCE``) it's the
    research-question equivalent: of all recordings on that slot,
    how often did this model land on the ``incorrect`` side?
    """
    correct = stats.events[event_type].correct
    incorrect = stats.events[event_type].incorrect
    if correct + incorrect == 0:
        return None
    return _wilson_upper_bound(correct, incorrect) * 100


def _format_wilson(
    stats: DecisionClassStats,
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
) -> str:
    pct = _wilson_ub_pct(stats, event_type)
    if pct is None:
        return "-"
    return f"{pct:5.1f}"


def _calls_saved(stats: DecisionClassStats) -> int:
    """Number of full-tier calls avoided by this cell — the count of
    confident-FP outcomes that were correct. Each such outcome
    represents a full ANALYSE we didn't have to run.

    Cheap-tier-specific. For other event types use
    :func:`_event_correct_count`.
    """
    return stats.events[EventType.CHEAP_SHORT_CIRCUIT].correct


def _event_correct_count(stats: DecisionClassStats, event_type: str) -> int:
    """Number of ``correct`` outcomes recorded against the chosen
    event slot. Generic equivalent of :func:`_calls_saved`."""
    return stats.events[event_type].correct


def _humanise_age(iso_ts: str, *, now: _dt.datetime | None = None) -> str:
    """Render an ISO timestamp as a human-friendly relative age
    (``2h ago``, ``3d ago``). Empty string for missing/invalid ts."""
    if not iso_ts:
        return ""
    try:
        ts = _dt.datetime.fromisoformat(iso_ts)
    except ValueError:
        # An unparseable timestamp only comes from a forged/corrupt
        # sidecar row (the writer always emits ISO) — escape + bound
        # before it can reach a terminal render verbatim.
        return _scrub_cell(iso_ts)
    if now is None:
        now = _dt.datetime.now(_dt.timezone.utc)
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=_dt.timezone.utc)
    delta = now - ts
    secs = delta.total_seconds()
    if secs < 60:
        return f"{int(secs)}s ago"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


# ---------------------------------------------------------------------------
# Filter / sort helpers
# ---------------------------------------------------------------------------


def _parse_since(s: str) -> _dt.timedelta:
    """Parse strings like ``7d``, ``24h``, ``30m``, ``90d``."""
    m = re.fullmatch(r"(\d+)([smhd])", s)
    if not m:
        msg = f"--since expects N[smhd] (e.g. 7d, 12h), got {s!r}"
        raise argparse.ArgumentTypeError(msg)
    n, unit = int(m.group(1)), m.group(2)
    return {
        "s": _dt.timedelta(seconds=n),
        "m": _dt.timedelta(minutes=n),
        "h": _dt.timedelta(hours=n),
        "d": _dt.timedelta(days=n),
    }[unit]


def _filter_stats(
    stats: list[DecisionClassStats], *,
    consumer: str | None = None,
    since: _dt.timedelta | None = None,
    only_untrusted: bool = False,
    only_learning: bool = False,
    sample_size_floor: int = DEFAULT_SAMPLE_SIZE_FLOOR,
) -> list[DecisionClassStats]:
    """Apply CLI filter flags. Filters compose (AND)."""
    out = list(stats)
    if consumer is not None:
        prefix = consumer if consumer.endswith(":") else f"{consumer}:"
        out = [s for s in out if s.decision_class.startswith(prefix)]
    if since is not None:
        cutoff = _dt.datetime.now(_dt.timezone.utc) - since
        kept = []
        for s in out:
            try:
                ts = _dt.datetime.fromisoformat(s.last_seen_at)
            except ValueError:
                continue
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=_dt.timezone.utc)
            if ts >= cutoff:
                kept.append(s)
        out = kept
    if only_untrusted:
        out = [
            s for s in out
            if _policy_for_stats(s, sample_size_floor=sample_size_floor)
            == Policy.FALL_THROUGH
        ]
    if only_learning:
        out = [
            s for s in out
            if _policy_for_stats(s, sample_size_floor=sample_size_floor)
            == Policy.LEARNING
        ]
    return out


def _sort_stats(
    stats: list[DecisionClassStats], *, sort_key: str,
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
) -> list[DecisionClassStats]:
    """Apply CLI sort. Default is decision_class then model."""
    if sort_key == "savings":
        return sorted(
            stats,
            key=lambda s: _event_correct_count(s, event_type),
            reverse=True,
        )
    if sort_key == "miss-rate":
        return sorted(
            stats,
            key=lambda s: (
                _wilson_ub_pct(s, event_type)
                if _wilson_ub_pct(s, event_type) is not None
                else -1
            ),
            reverse=True,
        )
    if sort_key == "cost":
        return sorted(stats, key=lambda s: s.cost_usd, reverse=True)
    return sorted(stats, key=lambda s: (s.decision_class, s.model))


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _stats_to_json(s: DecisionClassStats) -> dict[str, Any]:
    """JSON-shape dict for a single cell — used by every command's --json
    output. Keeps the shape stable so scripts / dashboards / CI gates can
    depend on it (vs scraping the markdown table)."""
    ev = s.events[EventType.CHEAP_SHORT_CIRCUIT]
    return {
        "decision_class": s.decision_class,
        "model": s.model,
        "model_version": s.model_version,
        "policy": _policy_for_stats(s),
        "policy_override": s.policy_override,
        "n": ev.correct + ev.incorrect,
        "max_miss_pct": _wilson_ub_pct(s, EventType.CHEAP_SHORT_CIRCUIT),
        "cheap_correct": ev.correct,
        "cheap_incorrect": ev.incorrect,
        "calls": s.calls,
        "cost_usd": s.cost_usd,
        "tokens": s.tokens,
        "input_tokens": s.input_tokens,
        "output_tokens": s.output_tokens,
        "latency_ms_sum": s.latency_ms_sum,
        "latency_ms_max": s.latency_ms_max,
        "first_seen_at": s.first_seen_at,
        "last_seen_at": s.last_seen_at,
    }


def _scrub_cell(value: object) -> str:
    """Escape + bound a sidecar-derived cell value (decision_class,
    model, event_type) before terminal rendering — the sidecar is
    same-user writable and readable without HMAC verification under
    the key-unusable clamp, so these strings are attacker-choosable.
    Routes through the shared ``scrub_cell`` (md_inline projection):
    control bytes escaped AND in-slot markdown structure (pipes,
    backticks) entity-escaped, so a forged cell cannot mint table
    columns in the pasted report."""
    return scrub_cell(value)


def _dumps_json_lane(data: Any) -> str:
    """Serialise a ``--json`` lane payload for the terminal.

    ensure_ascii: JSON escapes C0 but passes C1 controls
    (U+0080-U+009F, incl. single-byte CSI/OSC) through raw when
    ensure_ascii is off — ``dumps_display`` is exactly that, and these
    dicts carry the same sidecar-derived strings the table lanes scrub
    (decision_class, model, model_version, timestamps). ASCII-encode
    so the structured lane cannot carry live terminal controls either;
    output stays valid JSON for consumers that parse it."""
    return json.dumps(data, indent=2, ensure_ascii=True, default=str)


def _render_table(
    stats: list[DecisionClassStats],
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
    *,
    drift_map: dict[Any, str] | None = None,
) -> str:
    """Markdown table of cell summary lines. Columns are chosen for
    "what is this model good at?" research questions.

    ``event_type`` selects which event-slot the n / wilson / correct
    columns reflect. Default ``CHEAP_SHORT_CIRCUIT`` preserves the
    historic auto-policy view. The ``policy`` column always reflects
    the cheap-tier auto-policy gate regardless — that's the only
    event slot a policy is derived from.
    """
    if not stats:
        return "_(no scorecard data)_"
    is_cheap = event_type == EventType.CHEAP_SHORT_CIRCUIT
    correct_col = "calls_saved" if is_cheap else "correct"
    rows = []
    for s in stats:
        ev = s.events[event_type]
        n = ev.correct + ev.incorrect
        policy = _policy_for_stats(s)
        # Drift marker is prepended to the policy column when the freshness-
        # weighted verdict differs from the unweighted baseline — surfaces
        # silent regressions/recoveries directly in the list view.
        marker = ""
        if drift_map is not None:
            baseline = drift_map.get((s.decision_class, s.model), policy)
            marker = _drift_marker(baseline, policy)
        rows.append((
            _scrub_cell(s.decision_class),
            _scrub_cell(s.model),
            n,
            _format_wilson(s, event_type),
            marker + _format_policy(policy, s.events[
                EventType.CHEAP_SHORT_CIRCUIT].correct + s.events[
                EventType.CHEAP_SHORT_CIRCUIT].incorrect),
            _event_correct_count(s, event_type),
            _humanise_age(s.last_seen_at),
            s.calls,
            f"${s.cost_usd:.4f}" if s.cost_usd else "$0",
        ))
    headers = (
        "decision_class", "model", "n", "max_miss%",
        "policy", correct_col, "last_seen", "calls", "$$",
    )
    widths = [
        max(len(headers[i]), max((len(str(r[i])) for r in rows), default=0))
        for i in range(len(headers))
    ]
    lines = []
    lines.append(" | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)))
    lines.append("-+-".join("-" * w for w in widths))
    lines.extend(" | ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows)
    return "\n".join(lines)


def _render_compare(
    a_stats: list[DecisionClassStats],
    b_stats: list[DecisionClassStats],
    *, model_a: str, model_b: str,
) -> str:
    """Side-by-side view of two models on decision_classes they
    share. Decision classes seen by only one model are omitted —
    the operator's question is "how do these compare?", not
    "what's each one's coverage?"."""
    by_dc_a = {s.decision_class: s for s in a_stats if s.model == model_a}
    by_dc_b = {s.decision_class: s for s in b_stats if s.model == model_b}
    shared = sorted(set(by_dc_a) & set(by_dc_b))
    if not shared:
        return (
            f"_(no decision_classes seen by both {model_a} and "
            f"{model_b})_"
        )
    def _cost(s: DecisionClassStats) -> str:
        return f"${s.cost_usd:.4f}" if s.cost_usd else "$0"

    rows = []
    for dc in shared:
        a, b = by_dc_a[dc], by_dc_b[dc]
        a_ev = a.events[EventType.CHEAP_SHORT_CIRCUIT]
        b_ev = b.events[EventType.CHEAP_SHORT_CIRCUIT]
        rows.append((
            _scrub_cell(dc),
            f"{a_ev.correct + a_ev.incorrect}",
            _format_wilson(a),
            _format_policy(_policy_for_stats(a),
                           a_ev.correct + a_ev.incorrect),
            str(a.calls), _cost(a),
            f"{b_ev.correct + b_ev.incorrect}",
            _format_wilson(b),
            _format_policy(_policy_for_stats(b),
                           b_ev.correct + b_ev.incorrect),
            str(b.calls), _cost(b),
        ))
    headers = (
        "decision_class",
        f"{model_a} n", f"{model_a} max_miss%", f"{model_a} policy",
        f"{model_a} calls", f"{model_a} $$",
        f"{model_b} n", f"{model_b} max_miss%", f"{model_b} policy",
        f"{model_b} calls", f"{model_b} $$",
    )
    widths = [
        max(len(headers[i]), max((len(str(r[i])) for r in rows), default=0))
        for i in range(len(headers))
    ]
    lines = []
    lines.append(" | ".join(h.ljust(w) for h, w in zip(headers, widths, strict=True)))
    lines.append("-+-".join("-" * w for w in widths))
    lines.extend(" | ".join(str(c).ljust(w) for c, w in zip(r, widths, strict=True)) for r in rows)
    return "\n".join(lines)


def _render_samples(stat: DecisionClassStats) -> str:
    """Show disagreement-sample reasoning for a single cell.
    Used for the "why did this model get it wrong?" research
    question — operator reads through the LLM's reasoning when
    cheap and full disagreed."""
    if not stat.disagreement_samples:
        return (
            f"_(no disagreement samples for {_scrub_cell(stat.decision_class)} on "
            f"{_scrub_cell(stat.model)})_"
        )
    lines = [
        f"# {_scrub_cell(stat.decision_class)} on {_scrub_cell(stat.model)}",
        f"_{len(stat.disagreement_samples)} sample(s); "
        f"trust math: cheap claimed FP and was actually wrong_",
        "",
    ]
    # Persisted reasoning text originates from LLM output that can
    # quote analysed-repo tool output — escape control/ANSI bytes so a
    # planted escape sequence can't rewrite the operator's terminal.
    from core.security.log_sanitisation import escape_nonprintable

    def _esc(s: str) -> str:
        return escape_nonprintable(s, preserve_newlines=True)

    for i, sample in enumerate(stat.disagreement_samples, 1):
        lines.append(f"## Sample {i} — {_esc(str(sample.get('ts', '?')))} ({_esc(str(sample.get('event_type', '?')))})")
        cheap_r = _esc(sample.get("this_reasoning", ""))
        full_r = _esc(sample.get("other_reasoning", ""))
        note = _esc(sample.get("note", ""))
        if cheap_r:
            lines.append("**Cheap (clear_fp):**")
            lines.append(cheap_r)
            lines.append("")
        if full_r:
            lines.append("**Full (overruled):**")
            lines.append(full_r)
            lines.append("")
        if note:
            # Operator-feedback shape: a single ``note`` field rather
            # than the cheap-vs-full disagreement pair.
            lines.append("**Operator note:**")
            lines.append(note)
            lines.append("")
        # Producer-specific fields (self-consistency verdict pair,
        # dataflow method, cross-family trigger, validate-feedback join
        # keys, ...): render any remaining string-valued field so no
        # producer's samples come out empty-bodied.
        handled = {"ts", "event_type", "this_reasoning",
                   "other_reasoning", "note"}
        for key in sorted(sample):
            if key in handled:
                continue
            value = sample.get(key)
            if isinstance(value, str) and value:
                lines.append(f"**{_esc(key)}:**")
                lines.append(_esc(value))
                lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    hl = getattr(args, "freshness_half_life_days", None)
    stats = sc.get_stats(freshness_half_life_days=hl)
    # Drift map: when freshness is on, compute the unweighted baseline policy
    # per (dc, model) so the render can flag cells whose verdict changed under
    # freshness — the silent-regression / silent-recovery signal.
    drift_map: dict[Any, str] | None = None
    if hl:
        baseline = sc.get_stats()
        drift_map = {
            (s.decision_class, s.model): _policy_for_stats(s)
            for s in baseline
        }
    # ``--since`` is declared ``type=str`` (handlers are also driven
    # programmatically with pre-parsed namespaces), so argparse never
    # converts it — surface a typo as a usage error, not a traceback.
    try:
        since = _parse_since(args.since) if args.since else None
    except argparse.ArgumentTypeError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2
    stats = _filter_stats(
        stats,
        consumer=args.consumer,
        since=since,
        only_untrusted=args.untrusted,
        only_learning=args.learning,
    )
    sort_key = "default"
    if args.by_savings:
        sort_key = "savings"
    elif args.by_miss_rate:
        sort_key = "miss-rate"
    elif getattr(args, "by_cost", False):
        sort_key = "cost"
    event_type = getattr(args, "event_type", EventType.CHEAP_SHORT_CIRCUIT)
    stats = _sort_stats(stats, sort_key=sort_key, event_type=event_type)
    if getattr(args, "json", False):
        cells = []
        for s in stats:
            d = _stats_to_json(s)
            if drift_map:
                baseline = drift_map.get((s.decision_class, s.model))
                if baseline and baseline != d["policy"]:
                    d["freshness_drift"] = {"baseline_policy": baseline}
            cells.append(d)
        out: dict[str, Any] = {"cells": cells}
        if hl:
            out["freshness_half_life_days"] = hl
            out["freshness_impact"] = sc.measure_freshness_impact(hl)
        print(_dumps_json_lane(out))
        return 0
    print(_render_table(stats, event_type=event_type, drift_map=drift_map))
    if not hl:
        # Divergence breadcrumb: the live gate applies the run
        # config's scorecard_freshness_half_life_days, which this
        # process cannot see — an operator auditing the routing
        # decision must know the default view is the unweighted lens.
        print(
            "\nnote: policy column is unweighted with default gate "
            "parameters; a run configured with freshness weighting "
            "applies a different lens — mirror it with --freshness "
            "DAYS."
        )
    if hl:
        # When the freshness view is on, summarise its impact inline: how many
        # currently-trusted cells would change verdict under this half-life —
        # the cold-start signal to weigh before enabling freshness by default.
        imp = sc.measure_freshness_impact(hl)
        extra = f", +{imp['flipped_in']} newly trusted" if imp["flipped_in"] else ""
        print(
            f"\nfreshness @{hl:g}d: {imp['flipped_out']} of "
            f"{imp['short_circuit_baseline']} trusted cells fall out of "
            f"short-circuit{extra}"
        )
    return 0


def cmd_summary(args: argparse.Namespace) -> int:
    """One-shot dashboard: totals, policy breakdown, spend, most-used model,
    cheapest-reliable, recent activity. The "open this every morning" view."""
    sc = ModelScorecard(args.path)
    hl = getattr(args, "freshness_half_life_days", None)
    stats = sc.get_stats(freshness_half_life_days=hl)
    if not stats:
        print("scorecard is empty — no LLM calls recorded yet.")
        return 0

    models = set()
    short_circuit = learning = fall_through = 0
    total_cost = 0.0
    cost_per_model: dict[str, float] = {}
    calls_per_model: dict[str, int] = {}
    usage_cell_by_model: dict[str, DecisionClassStats] = {}
    # Keyed by (decision_class, model) — for cheapest-trusted picking.
    sc_models_by_dc: dict[tuple[str, str], str] = {}

    for s in stats:
        models.add(s.model)
        if s.decision_class == "_usage":
            usage_cell_by_model[s.model] = s
        # Underscore-prefixed cells (_usage roll-ups, _structured
        # schema tallies) are bookkeeping, not policy cells — counting
        # them in the breakdown inflated "learning" by one per model
        # per bookkeeping axis.
        if not s.decision_class.startswith("_"):
            p = _policy_for_stats(s)
            if p == Policy.SHORT_CIRCUIT:
                short_circuit += 1
                sc_models_by_dc[(s.decision_class, s.model)] = s.model
            elif p == Policy.LEARNING:
                learning += 1
            elif p == Policy.FALL_THROUGH:
                fall_through += 1
        # ``_usage`` is the per-model roll-up of every real call and its
        # spend. Other underscore-prefixed cells (e.g. ``_structured``)
        # re-count a per-call subset of those same calls on a separate
        # metric axis — summing them alongside ``_usage`` double-counts
        # calls and spend.
        is_subset_cell = (
            s.decision_class.startswith("_")
            and s.decision_class != "_usage"
        )
        if not is_subset_cell:
            total_cost += s.cost_usd
            cost_per_model[s.model] = cost_per_model.get(s.model, 0.0) + s.cost_usd
            calls_per_model[s.model] = calls_per_model.get(s.model, 0) + s.calls

    # Cheapest short-circuit (lowest $/call from each cell's _usage row).
    cheapest: tuple | None = None
    sc_aliases = {m for (_, m) in sc_models_by_dc}
    for m in sc_aliases:
        u = usage_cell_by_model.get(m)
        if u and u.calls > 0:
            cpc = u.cost_usd / u.calls
            if cheapest is None or cpc < cheapest[1]:
                cheapest = (m, cpc)

    # Recent activity — cells touched in the last 7 days.
    threshold = _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=7)
    recent = 0
    for s in stats:
        try:
            t = _dt.datetime.fromisoformat(s.last_seen_at)
            if t.tzinfo is None:
                t = t.replace(tzinfo=_dt.timezone.utc)
            if t > threshold:
                recent += 1
        except (ValueError, TypeError):
            pass

    most_used = max(calls_per_model.items(), key=lambda x: x[1], default=(None, 0))

    if getattr(args, "json", False):
        out = {
            "cells_total": len(stats),
            "models_total": len(models),
            "policy_breakdown": {
                "short_circuit": short_circuit, "learning": learning, "fall_through": fall_through,
            },
            "total_spend_usd": total_cost,
            "spend_by_model": dict(cost_per_model),
            "calls_by_model": dict(calls_per_model),
            "most_used": (
                {"model": most_used[0], "calls": most_used[1]}
                if most_used[0] else None
            ),
            "cheapest_short_circuit": (
                {"model": cheapest[0], "cost_per_call": cheapest[1]}
                if cheapest else None
            ),
            "recent_cells_7d": recent,
        }
        print(_dumps_json_lane(out))
        return 0

    print(f"scorecard summary ({args.path}):")
    print(f"  cells: {len(stats)} across {len(models)} model(s)")
    print(f"  policy: {short_circuit} trusted · {learning} learning · {fall_through} fall-through")
    # Model names are sidecar-derived (same forgeable provenance as the
    # table cells) — scrub before the terminal, like every other lane.
    cost_lines = [f"{_scrub_cell(m)} ${c:.4f}" for m, c in sorted(
        cost_per_model.items(), key=lambda x: -x[1]) if c > 0]
    cost_break = " (" + ", ".join(cost_lines) + ")" if cost_lines else ""
    print(f"  total spend: ${total_cost:.4f}{cost_break}")
    if most_used[0] and most_used[1] > 0:
        print(f"  most-used: {_scrub_cell(most_used[0])} ({most_used[1]} calls)")
    if cheapest:
        print(f"  cheapest trusted: {_scrub_cell(cheapest[0])} @ ${cheapest[1]:.4f}/call")
    print(f"  recent activity: {recent} cells last seen in last 7d")
    return 0


def cmd_recommend(args: argparse.Namespace) -> int:
    """Pick the model an operator should route a `decision_class` to: cheapest
    trusted-by-the-data, with the runners-up listed. Combines per-(model, dc)
    reliability (max_miss% from the cheap-tier slot) with the model's overall
    cost-per-call from its `_usage` cell. The actionable payoff of the whole
    scorecard system."""
    sc = ModelScorecard(args.path)
    target_dc = args.decision_class
    stats = sc.get_stats(
        freshness_half_life_days=getattr(args, "freshness_half_life_days", None))
    candidates = []
    usage_by_model = {}
    for s in stats:
        if s.decision_class == "_usage":
            usage_by_model[s.model] = s
        elif s.decision_class == target_dc:
            candidates.append(s)
    if not candidates:
        print(
            f"no scorecard data for decision_class {target_dc!r} — nothing to "
            f"recommend. Use `list --prefix {target_dc.split(':')[0]}` to "
            f"survey what's available.",
            file=sys.stderr,
        )
        return 0

    # (model, max_miss_pct_or_None, cost_per_call_or_None, policy, n)
    rows = []
    for c in candidates:
        ub = _wilson_ub_pct(c, EventType.CHEAP_SHORT_CIRCUIT)
        u = usage_by_model.get(c.model)
        cpc = (u.cost_usd / u.calls) if u and u.calls else None
        ev = c.events[EventType.CHEAP_SHORT_CIRCUIT]
        rows.append((c.model, ub, cpc, _policy_for_stats(c), ev.correct + ev.incorrect))

    sc_rows = sorted(
        (r for r in rows if r[3] == Policy.SHORT_CIRCUIT),
        key=lambda r: r[2] if r[2] is not None else float("inf"),
    )
    learning = [r for r in rows if r[3] == Policy.LEARNING]
    fall_through = sorted(
        (r for r in rows if r[3] == Policy.FALL_THROUGH),
        key=lambda r: r[1] if r[1] is not None else float("inf"),
    )

    hl = getattr(args, "freshness_half_life_days", None)

    if getattr(args, "json", False):
        def _r(row):
            m, ub, cpc, _pol, n = row
            return {"model": m, "max_miss_pct": ub, "cost_per_call": cpc, "n": n}
        out = {
            "decision_class": target_dc,
            "freshness_half_life_days": hl,
            "short_circuit": [_r(r) for r in sc_rows],
            "learning": [r[0] for r in learning],
            "fall_through": [_r(r) for r in fall_through],
            "recommendation": (
                {"model": sc_rows[0][0], "reason": "cheapest short-circuit"}
                if sc_rows else None
            ),
        }
        if not sc_rows and fall_through:
            out["least_bad"] = {"model": fall_through[0][0]}
        print(_dumps_json_lane(out))
        return 0

    # Freshness banner — when an operator passes --freshness, surface that the
    # ranking reflects weighted (recent-dominant) data so a different answer
    # than unweighted has a visible breadcrumb.
    suffix = f" (freshness half-life {hl:g}d)" if hl else ""
    print(f"recommendation for {target_dc}{suffix}:")

    def _fmt_ub(x) -> str:
        return f"{x:.1f}% max_miss" if x is not None else "max_miss=n/a"

    def _fmt_cpc(x) -> str:
        return f"${x:.4f}/call" if x is not None else "no cost data"

    # Model names are sidecar-derived (same forgeable provenance as the
    # table cells) — scrub before the terminal, like every other lane.
    if sc_rows:
        m, ub, cpc, _, n = sc_rows[0]
        cpc_note = " — cheapest trusted" if cpc is not None else " — trusted (no cost data to rank by)"
        print(f"  use: {_scrub_cell(m)}  ({_fmt_ub(ub)} · n={n} · {_fmt_cpc(cpc)}){cpc_note}")
        for m2, ub2, cpc2, _, _n2 in sc_rows[1:]:
            print(f"  also trusted: {_scrub_cell(m2)} ({_fmt_ub(ub2)} · {_fmt_cpc(cpc2)})")
    else:
        print("  no trusted model — none meet the miss-rate ceiling")
        if fall_through:
            m, ub, cpc, _, n = fall_through[0]
            print(f"  least-bad option: {_scrub_cell(m)} ({_fmt_ub(ub)} · n={n} · {_fmt_cpc(cpc)})")
    if learning:
        names = ", ".join(_scrub_cell(r[0]) for r in learning)
        print(f"  still learning (insufficient data): {names}")
    return 0


def cmd_chain_closure(args: argparse.Namespace) -> int:
    """Rank models by chain-closure success rate for a given
    exploit_chain_closure decision_class.

    Distinct from ``recommend``: that command optimises the
    cheap-vs-expensive short-circuit trust question (CHEAP_SHORT_CIRCUIT
    events), which isn't the right question for /exploit fires. Here we
    look at EXPLOIT_CHAIN_CLOSURE events directly — how often did the
    model actually weaponise the bug — and rank highest success rate
    first, with cost per fire as a tiebreak.

    Usage:
      scorecard chain-closure                 # aggregate across CWEs
      scorecard chain-closure --cwe cwe-121   # per-CWE ranking
    """
    sc = ModelScorecard(args.path)
    stats = sc.get_stats(
        freshness_half_life_days=getattr(
            args, "freshness_half_life_days", None,
        ),
    )
    # Target decision_class: aggregate or per-CWE.
    target_dc = "exploit_chain_closure"
    if getattr(args, "cwe", None):
        target_dc = f"exploit_chain_closure:{args.cwe.lower()}"

    candidates = []
    usage_by_model = {}
    for s in stats:
        if s.decision_class == "_usage":
            usage_by_model[s.model] = s
        elif s.decision_class == target_dc:
            candidates.append(s)

    if not candidates:
        # Honest remedy: the exploit-engine producer for this event
        # type has not landed, so there is no flag or run that
        # populates it yet — sending the operator to one is a wall.
        msg = (
            f"no chain-closure data for {target_dc!r} — nothing to rank. "
            f"The exploit-engine producer for exploit_chain_closure "
            f"events is not wired in this tree yet; this view populates "
            f"once it lands."
        )
        if getattr(args, "json", False):
            print(_dumps_json_lane({
                "decision_class": target_dc,
                "candidates": [],
                "message": msg,
            }))
        else:
            print(msg, file=sys.stderr)
        return 0

    # For each candidate: n = successes + failures on this cell;
    # success_rate = success / n; cost_per_fire from _usage.
    rows = []
    for c in candidates:
        ev = c.events[EventType.EXPLOIT_CHAIN_CLOSURE]
        n = ev.correct + ev.incorrect
        rate = (ev.correct / n) if n else None
        u = usage_by_model.get(c.model)
        cpc = (u.cost_usd / u.calls) if u and u.calls else None
        rows.append({
            "model": c.model,
            "n": n,
            "successes": ev.correct,
            "success_rate": rate,
            "cost_per_call": cpc,
        })
    # Sort: highest success_rate first; ties broken by cheaper
    # cost_per_call, then by larger n (more evidence).
    #
    # F5 fix: pre-fix used ``-(r["success_rate"] or -1.0)`` which
    # collapsed rate=0.0 to -(-1.0)=1.0 — identical to rate=None
    # (also 1.0) — so a 0/10 all-failures model with a low cost
    # could sort ABOVE a rate=None cell (n=0, cost=inf), and the
    # top row would then be handed to the "recommendation" field.
    # Post-fix: rate=None sorts to the tail explicitly via a
    # sentinel; rate=0.0 keeps its ordinal (worst rate wins the
    # top of "least bad" tail).
    def _sort_key(r):
        rate = r["success_rate"]
        rate_key = -rate if rate is not None else float("inf")
        cost_key = (
            r["cost_per_call"] if r["cost_per_call"] is not None
            else float("inf")
        )
        return (rate_key, cost_key, -r["n"])

    rows.sort(key=_sort_key)

    # A recommendation is only meaningful when the top row has real
    # positive success rate. Recommending a rate=0.0 model would be
    # misleading — no wins observed. Return None in that case
    # rather than pointing operators at a proven-failing model.
    def _recommendation() -> str | None:
        if not rows:
            return None
        top = rows[0]
        if top["n"] and (top["success_rate"] or 0.0) > 0.0:
            return top["model"]
        return None

    if getattr(args, "json", False):
        print(_dumps_json_lane({
            "decision_class": target_dc,
            "candidates": rows,
            "recommendation": _recommendation(),
        }))
        return 0

    print(f"chain-closure ranking for {target_dc}:")
    print(
        f"  {'model':<28} {'n':>4} {'succ':>4} "
        f"{'rate':>7} {'cost/fire':>10}",
    )
    for r in rows:
        rate_s = f"{r['success_rate']*100:5.1f}%" if r['success_rate'] is not None else "  n/a"
        cpc_s = f"${r['cost_per_call']:.3f}" if r['cost_per_call'] is not None else "  n/a"
        # Model names are sidecar-derived (forgeable) — scrub for the
        # terminal, like the list/compare table cells.
        print(
            f"  {_scrub_cell(r['model']):<28} {r['n']:>4} {r['successes']:>4} "
            f"{rate_s:>7} {cpc_s:>10}",
        )
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    all_stats = sc.get_stats()
    if getattr(args, "json", False):
        by_dc_a = {s.decision_class: s for s in all_stats if s.model == args.model_a}
        by_dc_b = {s.decision_class: s for s in all_stats if s.model == args.model_b}
        out = {
            "model_a": args.model_a, "model_b": args.model_b,
            "shared": [
                {
                    "decision_class": dc,
                    "model_a": _stats_to_json(by_dc_a[dc]),
                    "model_b": _stats_to_json(by_dc_b[dc]),
                }
                for dc in sorted(set(by_dc_a) & set(by_dc_b))
            ],
        }
        print(_dumps_json_lane(out))
        return 0
    print(_render_compare(
        all_stats, all_stats,
        model_a=args.model_a, model_b=args.model_b,
    ))
    return 0


def cmd_samples(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    all_stats = sc.get_stats()
    matching = [
        s for s in all_stats if s.decision_class == args.decision_class
    ]
    if args.model:
        matching = [s for s in matching if s.model == args.model]
    if not matching:
        print(
            f"_(no scorecard data for {args.decision_class}"
            + (f" on {args.model}" if args.model else "")
            + ")_",
            file=sys.stderr,
        )
        return 1
    for stat in matching:
        print(_render_samples(stat))
        print()
    return 0


# Friendly CLI policy words -> the internal policy_override storage values
# (kept verbose for an explicit on-disk format + unchanged verdict comparisons).
# The CLI words match the `policy` column `list` prints, so the vocab is
# consistent end to end.
_PIN_VALUE_MAP = {
    "short-circuit": "force_short_circuit",
    "fall-through": "force_fall_through",
    "auto": "auto",
}


def cmd_pin(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    override = _PIN_VALUE_MAP.get(args.as_, args.as_)
    sc.set_policy_override(args.decision_class, args.model, override)
    print(
        f"Pinned {args.decision_class} on {args.model} as "
        f"{args.as_}.",
        file=sys.stderr,
    )
    return 0


def cmd_unpin(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    sc.set_policy_override(args.decision_class, args.model, "auto")
    print(
        f"Unpinned {args.decision_class} on {args.model} (back to "
        f"auto).",
        file=sys.stderr,
    )
    return 0


def cmd_reset(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    try:
        n = sc.reset(
            decision_class=args.decision_class,
            model=args.model,
            older_than_days=args.older_than_days,
            all_=args.all,
        )
    except ValueError as e:
        # A bare ``reset`` (no filter, no --all) is refused by the
        # substrate; surface the reason instead of a traceback.
        print(f"✗ {e}", file=sys.stderr)
        return 2
    print(f"Deleted {n} cell(s).", file=sys.stderr)
    return 0


def cmd_tool_evidence(args: argparse.Namespace) -> int:
    """Walk an /agentic ``orchestrated_report.json`` + a /validate
    ``validation_report.json``, joining on ``finding_id``, and record
    one ``TOOL_EVIDENCE`` event per finding the validator concluded
    on. Skips findings the validator marked inconclusive.

    Operator-driven back-propagation: run after a /validate completes
    to update the scorecard with downstream-validation truth signal.
    """
    from core.json import load_json

    from .tool_evidence import record_tool_evidence_outcomes

    def _read_report(path: Path):
        data = load_json(path, strict=True, max_bytes=64 * 1024 * 1024)
        if data is None:
            # strict load_json returns None for a missing file.
            msg = f"{path}: file not found"
            raise OSError(msg)
        return data

    try:
        analysis = _read_report(Path(args.analysis))
    except (OSError, ValueError) as e:
        print(f"✗ Cannot read analysis report {args.analysis!r}: {e}",
              file=sys.stderr)
        return 2
    try:
        validation = _read_report(Path(args.validation))
    except (OSError, ValueError) as e:
        print(f"✗ Cannot read validation report {args.validation!r}: {e}",
              file=sys.stderr)
        return 2

    if not isinstance(analysis, dict):
        print(
            f"✗ Analysis report is not a JSON object: "
            f"{type(analysis).__name__}",
            file=sys.stderr,
        )
        return 2
    if not isinstance(validation, dict):
        print(
            f"✗ Validation report is not a JSON object: "
            f"{type(validation).__name__}",
            file=sys.stderr,
        )
        return 2

    # Build {finding_id: validation_verdict} from the validation report.
    # Tolerate multiple possible shapes — both a flat ``findings`` list
    # and a nested ``results`` array.
    val_by_id: dict = {}
    val_findings = (
        validation.get("findings")
        or validation.get("results")
        or []
    )
    for vf in val_findings:
        if not isinstance(vf, dict):
            # A hand-edited or corrupted report can carry non-dict
            # list entries; same guard as the auto-back-prop walk.
            continue
        fid = vf.get("finding_id")
        if not fid:
            continue
        verdict = vf.get("is_exploitable")
        if not isinstance(verdict, bool):
            # Inconclusive (None) or malformed (stringy "true"/"yes")
            # — skip; same typed rule as the auto-back-prop join in
            # tool_evidence.py.
            continue
        val_by_id[fid] = verdict

    # Walk analysis records; emit one evidence record per finding the
    # validator concluded on. Skip records missing the model — without
    # an attributable model, a recorded event lands on a "?"-keyed
    # cell that no producer ever revisits and that would silently
    # accumulate noise.
    records = []
    skipped_no_model = 0
    analysis_records = analysis.get("results") or []
    for r in analysis_records:
        if not isinstance(r, dict):
            continue
        fid = r.get("finding_id")
        if not fid or fid not in val_by_id:
            continue
        model = r.get("analysed_by")
        if not model:
            skipped_no_model += 1
            continue
        analysis_verdict = r.get("is_exploitable")
        if not isinstance(analysis_verdict, bool):
            # The analysis model abstained (errored / refused /
            # schema-failed response nulls the field): it cast no
            # verdict, so grading it against the validator would mint
            # a reliability event for a vote never cast. bool()
            # coercion here previously turned that abstention into a
            # "not exploitable" vote — same typed rule as the
            # auto-back-prop join in tool_evidence.py.
            continue
        records.append({
            "model": model,
            "rule_id": r.get("rule_id") or "unknown",
            "analysis_verdict": analysis_verdict,
            "validation_verdict": val_by_id[fid],
            "finding_id": fid,
            "analysis_reasoning": r.get("reasoning") or "",
        })

    sc = ModelScorecard(args.path)
    n = record_tool_evidence_outcomes(
        sc, records=records,
        decision_class_prefix=args.prefix,
    )
    print(
        f"Recorded {n} tool_evidence event(s) "
        f"from {len(records)} joined finding(s).",
        file=sys.stderr,
    )
    if skipped_no_model:
        print(
            f"  notice: {skipped_no_model} analysis record(s) skipped "
            "(no analysed_by field — can't attribute to a model)",
            file=sys.stderr,
        )
    print(
        "  reminder: re-running this command on the same reports "
        "double-records. Track external state (commit hash, run id) "
        "if invoking from automation.",
        file=sys.stderr,
    )
    return 0


def cmd_adopt(args: argparse.Namespace) -> int:
    """Re-bless an unverified sidecar with this install's integrity
    token (see ``core.llm.scorecard.integrity``). The verification
    layer discards-and-quarantines content it cannot verify — this
    is the deliberate operator path for keeping genuine pre-MAC
    history. Inspect the JSON before adopting: adoption asserts
    trust in every cell and pin it contains."""
    sc = ModelScorecard(args.path)
    try:
        adopted = sc.adopt_unverified(source=args.file)
    except (ValueError, OSError) as e:
        print(f"adopt failed: {e}", file=sys.stderr)
        return 1
    if not adopted:
        print(
            "nothing to adopt — no quarantine file "
            f"({args.path}.<timestamp>.unverified) and no sidecar "
            "content",
        )
        return 1
    print(f"adopted scorecard content into {args.path} (stamped).")
    return 0


def cmd_mark(args: argparse.Namespace) -> int:
    """Record an explicit operator-feedback event on a (model,
    decision_class) cell. Operator override of automated signals —
    the operator inspected an output and is asserting whether the
    model got it right or wrong. Increments the
    ``operator_feedback`` event counter; the cell's auto-policy
    surface still runs over the cheap-short-circuit math (per the
    SHORT_CIRCUIT gate's design). The operator can read this
    surface back through ``list``, ``compare``, or ``samples`` to
    track whether their own feedback aligns with the model's
    track record.
    """
    from .scorecard import EventType, ModelScorecard
    sc = ModelScorecard(args.path)
    # Soft notice when the targeted cell didn't pre-exist — catches
    # decision_class / --model typos that would otherwise silently
    # create a fresh cell that no producer ever touches again. Doesn't
    # block (the operator may legitimately be marking a brand-new
    # finding before any cheap-tier history has accumulated).
    pre_existing = sc.get_stat(args.decision_class, args.model) is not None
    sample = None
    if args.note:
        # Single-line operator note attached to the disagreement-
        # samples log on incorrect outcomes. Length-bounded at the
        # sink (``_append_sample`` slices every string leaf to
        # ``_MAX_REASONING_CHARS``) and gated by retain_samples.
        sample = {"note": args.note}
    sc.record_event(
        decision_class=args.decision_class,
        model=args.model,
        event_type=EventType.OPERATOR_FEEDBACK,
        outcome=args.outcome,
        sample=sample,
    )
    print(
        f"Recorded operator_feedback {args.outcome!r} on "
        f"{args.decision_class} for {args.model}.",
        file=sys.stderr,
    )
    if not pre_existing:
        print(
            f"  notice: {args.decision_class!r} on {args.model!r} had "
            "no prior events — created a new cell. Double-check the "
            "decision_class + --model spelling if this looks like a typo.",
            file=sys.stderr,
        )
    return 0


# ---------------------------------------------------------------------------
# argparse wiring
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="raptor-llm-scorecard",
        description=(
            "Inspect and maintain the model scorecard "
            "(out/llm_scorecard.json by default). "
            f"Substrate schema version {SCHEMA_VERSION}."
        ),
    )
    p.add_argument(
        "--path", type=Path, default=default_scorecard_path(),
        help=f"sidecar path (default: {default_scorecard_path()}),"
             " resolved at invocation",
    )
    p.add_argument(
        "--json", action="store_true",
        help=(
            "emit machine-parseable JSON instead of the markdown table — "
            "applies to list / compare / recommend / summary. Lets scripts, "
            "dashboards, and CI gates consume scorecard data directly."
        ),
    )
    # Not required: a bare invocation defaults to `list` (see main()). Keeps
    # `/scorecard` fast and useful instead of erroring on a missing subcommand.
    sub = p.add_subparsers(dest="subcommand", required=False)

    # list
    p_list = sub.add_parser(
        "list",
        help="markdown table of all cells with derived columns",
    )
    p_list.add_argument(
        "--by-savings", action="store_true",
        help=(
            "sort by full-tier calls saved (descending). For "
            "non-cheap event slots (--event-type), sorts by the "
            "``correct`` count in that slot — the flag name keeps "
            "its cheap-tier semantics for backwards compatibility."
        ),
    )
    p_list.add_argument(
        "--by-miss-rate", action="store_true",
        help=(
            "sort by worst-case miss-rate (descending) — the conservative "
            "95%%-confidence upper bound shown in the max_miss%% column. For "
            "non-cheap event slots, sorts by that slot's worst-case "
            "incorrect-rate."
        ),
    )
    p_list.add_argument(
        "--by-cost", action="store_true",
        help="sort by total spend on this cell (descending) — the $$ column.",
    )
    p_list.add_argument(
        "--untrusted", action="store_true",
        help="show only cells whose policy is fall-through",
    )
    p_list.add_argument(
        "--learning", action="store_true",
        help="show only cells still in learning mode (n<floor)",
    )
    p_list.add_argument(
        "--prefix", type=str, default=None, dest="consumer", metavar="PREFIX",
        help=(
            "filter by decision_class prefix "
            "(e.g. 'codeql' matches codeql:py/sql-injection etc.)"
        ),
    )
    p_list.add_argument(
        "--since", type=str, default=None,
        help="only cells last seen within this window (e.g. 7d, 12h)",
    )
    p_list.add_argument(
        "--event-type", type=str, default=EventType.CHEAP_SHORT_CIRCUIT,
        choices=list(ALL_EVENT_TYPES),
        help=(
            "reframe n / max_miss%% / correct columns around the "
            "chosen event slot. Default 'cheap_short_circuit' "
            "preserves the auto-policy view; pass "
            "'reasoning_divergence' / 'multi_model_consensus' / "
            "'judge_review' / 'tool_evidence' / 'operator_feedback' "
            "to read the research-question slots. The 'policy' "
            "column is always cheap-derived."
        ),
    )
    p_list.add_argument(
        "--freshness", dest="freshness_half_life_days",
        type=float, default=None, metavar="DAYS",
        help=(
            "weight recent behaviour more heavily, halving an observation's "
            "weight every DAYS days (exponential half-life), so the policy / "
            "max_miss%% / calls columns reflect recent over stale history — "
            "the same weighting the live gate applies when "
            "scorecard_freshness_half_life_days is configured. Default: "
            "unweighted (all-time)."
        ),
    )
    p_list.set_defaults(handler=cmd_list)

    # summary — the daily-driver dashboard
    p_sum = sub.add_parser(
        "summary",
        help=(
            "one-shot dashboard: cell totals, policy breakdown, total spend, "
            "most-used model, cheapest trusted, recent activity"
        ),
    )
    p_sum.add_argument(
        "--freshness", dest="freshness_half_life_days",
        type=float, default=None, metavar="DAYS",
        help=(
            "weight recent behaviour (half-life in days) so the policy "
            "breakdown mirrors a freshness-configured live gate; same "
            "as `list --freshness`. Default: unweighted (all-time)."
        ),
    )
    p_sum.set_defaults(handler=cmd_summary)

    # recommend — the actionable payoff
    p_rec = sub.add_parser(
        "recommend",
        help=(
            "pick the model to route a given decision_class to — cheapest "
            "trusted (max_miss%% ≤ ceiling), with runners-up listed. The "
            "operator-facing payoff of the whole scorecard."
        ),
    )
    p_rec.add_argument(
        "decision_class", type=str,
        help="decision_class to recommend for (e.g. codeql:py/sql-injection)",
    )
    p_rec.add_argument(
        "--freshness", dest="freshness_half_life_days",
        type=float, default=None, metavar="DAYS",
        help="weight recent behaviour (half-life in days); same as `list --freshness`",
    )
    p_rec.set_defaults(handler=cmd_recommend)

    # chain-closure — rank models by /exploit chain-closure success
    p_cc = sub.add_parser(
        "chain-closure",
        help=(
            "rank models by /exploit chain-closure success rate. "
            "Aggregate across CWEs by default; scope to one with "
            "--cwe. Reads EXPLOIT_CHAIN_CLOSURE events populated by "
            "/exploit --scorecard."
        ),
    )
    p_cc.add_argument(
        "--cwe", type=str, default=None,
        help="scope to a specific CWE, e.g. --cwe cwe-121",
    )
    p_cc.add_argument(
        "--freshness", dest="freshness_half_life_days",
        type=float, default=None, metavar="DAYS",
        help="weight recent behaviour (half-life in days)",
    )
    p_cc.set_defaults(handler=cmd_chain_closure)

    # compare
    p_cmp = sub.add_parser(
        "compare",
        help="side-by-side comparison of two models on shared decision_classes",
    )
    p_cmp.add_argument("model_a", type=str)
    p_cmp.add_argument("model_b", type=str)
    p_cmp.set_defaults(handler=cmd_compare)

    # samples
    p_smp = sub.add_parser(
        "samples",
        help="show disagreement-sample reasoning for a decision_class",
    )
    p_smp.add_argument("decision_class", type=str)
    p_smp.add_argument(
        "--model", type=str, default=None,
        help="restrict to a specific model (default: all models with data)",
    )
    p_smp.set_defaults(handler=cmd_samples)

    # pin
    p_pin = sub.add_parser(
        "pin",
        help="set policy_override on a cell",
    )
    p_pin.add_argument("decision_class", type=str)
    p_pin.add_argument(
        "--model", type=str, required=True,
        help="model whose cell to pin",
    )
    p_pin.add_argument(
        "--as", type=str, dest="as_", required=True,
        choices=("short-circuit", "fall-through", "auto"),
        help=("policy to pin: short-circuit (always trust this cell) / "
              "fall-through (never trust) / auto (back to data-driven)"),
    )
    p_pin.set_defaults(handler=cmd_pin)

    # unpin
    p_un = sub.add_parser(
        "unpin",
        help="release a pin (set policy_override back to 'auto')",
    )
    p_un.add_argument("decision_class", type=str)
    p_un.add_argument("--model", type=str, required=True)
    p_un.set_defaults(handler=cmd_unpin)

    # reset
    p_rst = sub.add_parser(
        "reset",
        help="delete cells (single, --model, --older-than, --all)",
    )
    p_rst.add_argument(
        "decision_class", nargs="?", default=None,
        help="single decision_class to delete (optional)",
    )
    p_rst.add_argument("--model", type=str, default=None)
    p_rst.add_argument(
        "--older-than-days", type=int, default=None,
        help="delete cells whose last_seen is older than N days",
    )
    p_rst.add_argument(
        "--all", action="store_true",
        help="delete every cell",
    )
    p_rst.set_defaults(handler=cmd_reset)

    # mark — operator-feedback producer.
    p_mark = sub.add_parser(
        "mark",
        help=(
            "record an explicit operator-feedback event on a cell "
            "(operator inspected a model's output and is asserting "
            "whether it got it right). Bumps the operator_feedback "
            "counter; visible via list/compare/samples."
        ),
    )
    p_mark.add_argument(
        "decision_class",
        help="decision class — usually 'codeql:<rule_id>' or "
             "'agentic:<rule_id>'",
    )
    p_mark.add_argument(
        "outcome", choices=("correct", "incorrect"),
        help="operator's verdict on the model's output for this cell",
    )
    p_mark.add_argument(
        "--model", required=True,
        help="model_name the verdict is being recorded against",
    )
    p_mark.add_argument(
        "--note",
        help=(
            "short operator note attached to the disagreement-samples "
            "log (only retained on outcome=incorrect, per the "
            "scorecard's existing retain_samples policy). Avoid "
            "including any code under analysis."
        ),
    )
    p_mark.set_defaults(handler=cmd_mark)

    # tool-evidence — automated back-propagation from /validate.
    p_te = sub.add_parser(
        "tool-evidence",
        help=(
            "back-propagate /validate outcomes onto the scorecard. "
            "Joins an /agentic orchestrated_report.json with a "
            "/validate validation_report.json by finding_id and "
            "records one TOOL_EVIDENCE event per finding the "
            "validator concluded on (skips inconclusive)."
        ),
    )
    p_te.add_argument(
        "--analysis", required=True, type=Path,
        help="path to /agentic's orchestrated_report.json",
    )
    p_te.add_argument(
        "--validation", required=True, type=Path,
        help="path to /validate's validation_report.json",
    )
    p_te.add_argument(
        "--prefix", default="agentic",
        help=(
            "decision_class prefix (default: 'agentic'). Use "
            "'codeql' when validating /codeql findings so cells "
            "land under codeql:<rule_id> matching the prefilter "
            "producer's existing convention."
        ),
    )
    p_te.set_defaults(handler=cmd_tool_evidence)

    # adopt
    p_adopt = sub.add_parser(
        "adopt",
        help=(
            "re-bless an unverified sidecar (pre-MAC history or a "
            "quarantined <sidecar>.unverified file) by stamping it "
            "with this install's integrity token. Deliberate "
            "operator action: the machinery never re-stamps "
            "unverified content on its own — inspect the file "
            "before adopting."
        ),
    )
    p_adopt.add_argument(
        "--file", type=Path, default=None,
        help=(
            "explicit source JSON to adopt (default: the newest "
            "quarantine file <sidecar>.<timestamp>.unverified when "
            "present, else the sidecar itself)"
        ),
    )
    p_adopt.set_defaults(handler=cmd_adopt)

    return p


def main(argv: list[str] | None = None) -> int:
    import sys as _sys
    argv = list(_sys.argv[1:] if argv is None else argv)
    parser = _build_parser()
    args = parser.parse_args(argv)
    if getattr(args, "handler", None) is None:
        # No subcommand given -> default to `list` (top-level optionals like
        # --path stay before the appended subcommand, which argparse accepts).
        # Print a discoverability footer so the operator still learns the other
        # subcommands now that a bare invocation no longer errors into usage.
        args = parser.parse_args([*argv, "list"])
        rc = args.handler(args)
        # Suppress the discoverability footer when --json is on so the
        # emitted output stays valid JSON for downstream parsers.
        if not getattr(args, "json", False):
            print("\n(more subcommands: run `raptor-llm-scorecard -h`)")
        return rc
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())

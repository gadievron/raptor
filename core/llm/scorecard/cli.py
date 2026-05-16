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
import re
import sys
from pathlib import Path
from typing import List, Optional

from .scorecard import (
    ALL_EVENT_TYPES,
    EventType,
    ModelScorecard,
    Policy,
    SCHEMA_VERSION,
    DecisionClassStats,
    _wilson_upper_bound,
)


DEFAULT_PATH = Path("out/llm_scorecard.json")


# ---------------------------------------------------------------------------
# Policy + Wilson display helpers
# ---------------------------------------------------------------------------


def _policy_for_stats(
    stats: DecisionClassStats,
    *,
    sample_size_floor: int = 10,
    miss_rate_ceiling: float = 0.05,
) -> str:
    """Re-derive the policy decision from a ``DecisionClassStats``
    snapshot. We don't read the live ``ModelScorecard.should_short_circuit``
    here because that's per-call and we want a self-contained
    interpretation of the on-disk data."""
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


def _format_policy(policy: str, n: int, sample_size_floor: int = 10) -> str:
    """Operator-friendly policy label."""
    if policy == Policy.SHORT_CIRCUIT:
        return "short-circuit"
    if policy == Policy.FALL_THROUGH:
        return "fall-through"
    return f"learning (n<{sample_size_floor})"


def _wilson_ub_pct(
    stats: DecisionClassStats,
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
) -> Optional[float]:
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


def _humanise_age(iso_ts: str, *, now: Optional[_dt.datetime] = None) -> str:
    """Render an ISO timestamp as a human-friendly relative age
    (``2h ago``, ``3d ago``). Empty string for missing/invalid ts."""
    if not iso_ts:
        return ""
    try:
        ts = _dt.datetime.fromisoformat(iso_ts)
    except ValueError:
        return iso_ts                              # pass through if unparseable
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
        raise argparse.ArgumentTypeError(
            f"--since expects N[smhd] (e.g. 7d, 12h), got {s!r}"
        )
    n, unit = int(m.group(1)), m.group(2)
    return {
        "s": _dt.timedelta(seconds=n),
        "m": _dt.timedelta(minutes=n),
        "h": _dt.timedelta(hours=n),
        "d": _dt.timedelta(days=n),
    }[unit]


def _filter_stats(
    stats: List[DecisionClassStats], *,
    consumer: Optional[str] = None,
    since: Optional[_dt.timedelta] = None,
    only_untrusted: bool = False,
    only_learning: bool = False,
    sample_size_floor: int = 10,
) -> List[DecisionClassStats]:
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
    stats: List[DecisionClassStats], *, sort_key: str,
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
) -> List[DecisionClassStats]:
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
    return sorted(stats, key=lambda s: (s.decision_class, s.model))


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------


def _render_table(
    stats: List[DecisionClassStats],
    event_type: str = EventType.CHEAP_SHORT_CIRCUIT,
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
        rows.append((
            s.decision_class,
            s.model,
            n,
            _format_wilson(s, event_type),
            _format_policy(policy, s.events[
                EventType.CHEAP_SHORT_CIRCUIT].correct + s.events[
                EventType.CHEAP_SHORT_CIRCUIT].incorrect),
            _event_correct_count(s, event_type),
            _humanise_age(s.last_seen_at),
        ))
    headers = (
        "decision_class", "model", "n", "wilson_ub%",
        "policy", correct_col, "last_seen",
    )
    widths = [
        max(len(headers[i]), max((len(str(r[i])) for r in rows), default=0))
        for i in range(len(headers))
    ]
    lines = []
    lines.append(" | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    lines.append("-+-".join("-" * w for w in widths))
    for r in rows:
        lines.append(" | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(lines)


def _render_compare(
    a_stats: List[DecisionClassStats],
    b_stats: List[DecisionClassStats],
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
    rows = []
    for dc in shared:
        a, b = by_dc_a[dc], by_dc_b[dc]
        a_ev = a.events[EventType.CHEAP_SHORT_CIRCUIT]
        b_ev = b.events[EventType.CHEAP_SHORT_CIRCUIT]
        rows.append((
            dc,
            f"{a_ev.correct + a_ev.incorrect}",
            _format_wilson(a),
            _format_policy(_policy_for_stats(a),
                           a_ev.correct + a_ev.incorrect),
            f"{b_ev.correct + b_ev.incorrect}",
            _format_wilson(b),
            _format_policy(_policy_for_stats(b),
                           b_ev.correct + b_ev.incorrect),
        ))
    headers = (
        "decision_class",
        f"{model_a} n", f"{model_a} wilson%", f"{model_a} policy",
        f"{model_b} n", f"{model_b} wilson%", f"{model_b} policy",
    )
    widths = [
        max(len(headers[i]), max((len(str(r[i])) for r in rows), default=0))
        for i in range(len(headers))
    ]
    lines = []
    lines.append(" | ".join(h.ljust(w) for h, w in zip(headers, widths)))
    lines.append("-+-".join("-" * w for w in widths))
    for r in rows:
        lines.append(" | ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(lines)


def _render_samples(stat: DecisionClassStats) -> str:
    """Show disagreement-sample reasoning for a single cell.
    Used for the "why did this model get it wrong?" research
    question — operator reads through the LLM's reasoning when
    cheap and full disagreed."""
    if not stat.disagreement_samples:
        return (
            f"_(no disagreement samples for {stat.decision_class} on "
            f"{stat.model})_"
        )
    lines = [
        f"# {stat.decision_class} on {stat.model}",
        f"_{len(stat.disagreement_samples)} sample(s); "
        f"trust math: cheap claimed FP and was actually wrong_",
        "",
    ]
    for i, sample in enumerate(stat.disagreement_samples, 1):
        lines.append(f"## Sample {i} — {sample.get('ts', '?')} ({sample.get('event_type', '?')})")
        cheap_r = sample.get("this_reasoning", "")
        full_r = sample.get("other_reasoning", "")
        note = sample.get("note", "")
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
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------


def cmd_list(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    stats = sc.get_stats()
    since = _parse_since(args.since) if args.since else None
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
    event_type = getattr(args, "event_type", EventType.CHEAP_SHORT_CIRCUIT)
    stats = _sort_stats(stats, sort_key=sort_key, event_type=event_type)
    print(_render_table(stats, event_type=event_type))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    all_stats = sc.get_stats()
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


def cmd_pin(args: argparse.Namespace) -> int:
    sc = ModelScorecard(args.path)
    sc.set_policy_override(args.decision_class, args.model, args.as_)
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
    n = sc.reset(
        decision_class=args.decision_class,
        model=args.model,
        older_than_days=args.older_than_days,
        all_=args.all,
    )
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
    import json as _json
    from .tool_evidence import record_tool_evidence_outcomes

    try:
        analysis = _json.loads(Path(args.analysis).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: cannot read analysis report {args.analysis!r}: {e}",
              file=sys.stderr)
        return 2
    try:
        validation = _json.loads(Path(args.validation).read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        print(f"error: cannot read validation report {args.validation!r}: {e}",
              file=sys.stderr)
        return 2

    # Build {finding_id: validation_verdict} from the validation report.
    # Tolerate multiple possible shapes — both a flat ``findings`` list
    # and a nested ``results`` array.
    val_by_id: dict = {}
    val_findings = validation.get("findings") or validation.get("results") or []
    for vf in val_findings:
        fid = vf.get("finding_id")
        if not fid:
            continue
        verdict = vf.get("is_exploitable")
        if verdict is None:
            # inconclusive — skip
            continue
        val_by_id[fid] = bool(verdict)

    # Walk analysis records; emit one evidence record per finding the
    # validator concluded on. Skip records missing the model — without
    # an attributable model, a recorded event lands on a "?"-keyed
    # cell that no producer ever revisits and that would silently
    # accumulate noise.
    records = []
    skipped_no_model = 0
    analysis_records = analysis.get("results") or []
    for r in analysis_records:
        fid = r.get("finding_id")
        if not fid or fid not in val_by_id:
            continue
        model = r.get("analysed_by")
        if not model:
            skipped_no_model += 1
            continue
        records.append({
            "model": model,
            "rule_id": r.get("rule_id") or "unknown",
            "analysis_verdict": bool(r.get("is_exploitable", False)),
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
        # samples log on incorrect outcomes. Bounded by
        # ``record_event``'s caps + retain_samples gate.
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
        "--path", type=Path, default=DEFAULT_PATH,
        help=f"sidecar path (default: {DEFAULT_PATH})",
    )
    sub = p.add_subparsers(dest="subcommand", required=True)

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
            "sort by Wilson upper-95%% miss-rate (descending). For "
            "non-cheap event slots, sorts by the wilson upper bound "
            "on that slot's incorrect-rate."
        ),
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
        "--consumer", type=str, default=None,
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
            "reframe n / wilson_ub%% / correct columns around the "
            "chosen event slot. Default 'cheap_short_circuit' "
            "preserves the auto-policy view; pass "
            "'reasoning_divergence' / 'multi_model_consensus' / "
            "'judge_review' / 'tool_evidence' / 'operator_feedback' "
            "to read the research-question slots. The 'policy' "
            "column is always cheap-derived."
        ),
    )
    p_list.set_defaults(handler=cmd_list)

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
        choices=("force_short_circuit", "force_fall_through", "auto"),
        help="override value to set",
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

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    sys.exit(main())

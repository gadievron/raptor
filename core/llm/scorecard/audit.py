"""Scorecard audit — Phase 1a of the calibrated-aggregation arc.

Walks a scorecard sidecar (default ``out/llm_scorecard.json``) and reports
per-(model, decision_class, event_type) sample-count distributions. The
output answers one question: does the existing data support Dawid–Skene
aggregation, or will the estimator reduce to its prior?

This module is read-only and has no behaviour-changing side effects on
``/agentic`` or ``/codeql``. It exists to gate Phase 1b (Beta priors
parameterisation) — the chosen prior strength depends on the median cell
sample count, which the audit measures.

Verdict thresholds (configurable):

* ``green``  — ≥ 50 %% of ``(model, decision_class)`` cells reach
  ``N=30`` observations for the ``multi_model_consensus`` event type.
  D–S will see signal across most partitions.
* ``amber``  — 10–50 %% reach N=30. D–S will be informative on the
  data-rich partitions and prior-dominated on the rest.
* ``red``    — < 10 %% reach N=30. D–S reduces to prior almost
  everywhere; revisit prior design before proceeding to Phase 2.

See ``docs/design-aggregation-dominators-wp.md`` Phase 1 for context.
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from core.llm.scorecard.scorecard import (
    ALL_EVENT_TYPES,
    EventType,
    ModelScorecard,
)


DEFAULT_PATH = Path("out/llm_scorecard.json")

# Sample-count thresholds reported in the cell-count histogram. N=10 is
# the existing scorecard's ``sample_size_floor`` (where ``learning`` ends
# and Wilson gating begins). N=30 is the conventional "moderately large"
# threshold below which normal-approximation CIs are too optimistic. N=100
# is a quality bar for per-class confusion-matrix estimation in D–S.
THRESHOLDS: Sequence[int] = (10, 30, 100)

# Phase 2 primarily consumes panel data; this is the event type whose
# coverage decides the green / amber / red verdict.
PRIMARY_EVENT_TYPE = EventType.MULTI_MODEL_CONSENSUS

# Verdict ratio cut-offs for cells reaching N=30 on the primary event type.
GREEN_RATIO = 0.50
AMBER_RATIO = 0.10


@dataclass
class EventTypeSummary:
    """Per-event-type stats across all cells."""
    event_type: str
    total_cells: int = 0
    cells_with_any_data: int = 0
    cells_at_thresholds: Dict[int, int] = field(default_factory=dict)
    total_observations: int = 0


@dataclass
class DecisionClassSummary:
    """Per-decision-class stats — how many distinct models contribute and
    what the median observation count is. D–S needs at least 2 models per
    class to break vote ties; more is better."""
    decision_class: str
    distinct_models: int = 0
    median_obs_primary: float = 0.0
    total_obs_primary: int = 0


@dataclass
class AuditReport:
    scorecard_path: str
    schema_version: Optional[int]
    total_models: int
    total_decision_classes: int
    total_cells: int
    event_type_summaries: List[EventTypeSummary]
    decision_class_summaries: List[DecisionClassSummary]
    primary_event_type: str
    verdict: str  # "green" | "amber" | "red" | "no-data"
    verdict_reason: str


def _empty_event_summary(event_type: str) -> EventTypeSummary:
    return EventTypeSummary(
        event_type=event_type,
        cells_at_thresholds={t: 0 for t in THRESHOLDS},
    )


def _load_raw(path: Path) -> Optional[dict]:
    """Read the sidecar JSON directly (without going through
    ``ModelScorecard``) so we can surface ``schema_version`` and survive
    a malformed file. Returns ``None`` when the file is missing."""
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise SystemExit(f"scorecard-audit: cannot read {path}: {exc}")


def audit(path: Path = DEFAULT_PATH) -> AuditReport:
    """Compute the audit report for the scorecard at ``path``.

    Pure function modulo file IO — given identical input, output is
    identical. No locking, no mutation.
    """
    raw = _load_raw(path)
    if raw is None:
        return AuditReport(
            scorecard_path=str(path),
            schema_version=None,
            total_models=0,
            total_decision_classes=0,
            total_cells=0,
            event_type_summaries=[_empty_event_summary(et)
                                  for et in ALL_EVENT_TYPES],
            decision_class_summaries=[],
            primary_event_type=PRIMARY_EVENT_TYPE,
            verdict="no-data",
            verdict_reason=f"scorecard file not found at {path}",
        )

    schema_version = raw.get("version")

    # Use ``ModelScorecard.get_stats()`` for the per-cell view — it handles
    # the v2 age-bucket flattening and the migration path. The audit cares
    # about cumulative observation counts, not per-bucket freshness, so
    # default (unweighted) flattening is the right choice here.
    sc = ModelScorecard(path)
    stats_list = sc.get_stats()

    event_summaries: Dict[str, EventTypeSummary] = {
        et: _empty_event_summary(et) for et in ALL_EVENT_TYPES
    }
    # Per decision-class: track distinct models and per-cell primary-event
    # observation counts for median computation.
    dc_models: Dict[str, set] = defaultdict(set)
    dc_obs_primary: Dict[str, List[int]] = defaultdict(list)

    distinct_models = set()
    distinct_decision_classes = set()

    for stats in stats_list:
        distinct_models.add(stats.model)
        distinct_decision_classes.add(stats.decision_class)
        dc_models[stats.decision_class].add(stats.model)

        for event_type, counts in stats.events.items():
            summary = event_summaries.get(event_type)
            if summary is None:
                # Unknown event type — likely a forward-compat field added
                # since this audit was written. Surface it under its own
                # bucket so it isn't silently dropped.
                summary = _empty_event_summary(event_type)
                event_summaries[event_type] = summary
            summary.total_cells += 1
            n = counts.correct + counts.incorrect
            summary.total_observations += n
            if n > 0:
                summary.cells_with_any_data += 1
            for threshold in THRESHOLDS:
                if n >= threshold:
                    summary.cells_at_thresholds[threshold] = (
                        summary.cells_at_thresholds.get(threshold, 0) + 1
                    )

            if event_type == PRIMARY_EVENT_TYPE:
                dc_obs_primary[stats.decision_class].append(n)

    dc_summaries: List[DecisionClassSummary] = []
    for dc, obs_list in sorted(dc_obs_primary.items()):
        obs_list_sorted = sorted(obs_list)
        median = (
            obs_list_sorted[len(obs_list_sorted) // 2]
            if obs_list_sorted else 0.0
        )
        dc_summaries.append(DecisionClassSummary(
            decision_class=dc,
            distinct_models=len(dc_models[dc]),
            median_obs_primary=float(median),
            total_obs_primary=sum(obs_list_sorted),
        ))

    primary = event_summaries[PRIMARY_EVENT_TYPE]
    cells_at_30 = primary.cells_at_thresholds.get(30, 0)
    # ``total_cells`` counts cells that have the event-type key — which is
    # every cell in the scorecard (``_empty_events()`` seeds all known
    # types). The audit's ratio must be against cells that actually carry
    # observations for the primary event type, otherwise a scorecard
    # populated only via ``cheap_short_circuit`` would look like red rather
    # than no-data.
    cells_with_data = primary.cells_with_any_data
    if cells_with_data == 0:
        verdict = "no-data"
        reason = (
            f"no cells carry any {PRIMARY_EVENT_TYPE} events; the panel "
            "log (or its scorecard producer) has not run yet"
        )
    else:
        ratio = cells_at_30 / cells_with_data
        if ratio >= GREEN_RATIO:
            verdict = "green"
            reason = (
                f"{cells_at_30}/{cells_with_data} cells "
                f"({ratio:.1%}) reach N=30 on {PRIMARY_EVENT_TYPE}"
            )
        elif ratio >= AMBER_RATIO:
            verdict = "amber"
            reason = (
                f"{cells_at_30}/{cells_with_data} cells "
                f"({ratio:.1%}) reach N=30 on {PRIMARY_EVENT_TYPE} — "
                "D–S will be informative on data-rich partitions, "
                "prior-dominated on the rest"
            )
        else:
            verdict = "red"
            reason = (
                f"{cells_at_30}/{cells_with_data} cells "
                f"({ratio:.1%}) reach N=30 on {PRIMARY_EVENT_TYPE} — "
                "D–S will reduce to prior almost everywhere; revisit "
                "prior design before Phase 2"
            )

    return AuditReport(
        scorecard_path=str(path),
        schema_version=schema_version,
        total_models=len(distinct_models),
        total_decision_classes=len(distinct_decision_classes),
        total_cells=sum(s.total_cells for s in event_summaries.values()
                        if s.event_type == PRIMARY_EVENT_TYPE),
        event_type_summaries=sorted(
            event_summaries.values(), key=lambda s: s.event_type
        ),
        decision_class_summaries=dc_summaries,
        primary_event_type=PRIMARY_EVENT_TYPE,
        verdict=verdict,
        verdict_reason=reason,
    )


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_markdown(report: AuditReport) -> str:
    """Operator-facing markdown report. Tables paste cleanly into issues
    and notebooks."""
    lines: List[str] = []
    lines.append(f"# Scorecard audit — `{report.scorecard_path}`")
    lines.append("")
    lines.append(f"Schema version: `{report.schema_version}`")
    lines.append(f"Distinct models: **{report.total_models}**")
    lines.append(
        f"Distinct decision classes: **{report.total_decision_classes}**"
    )
    lines.append(
        f"Total `(model, decision_class)` cells "
        f"(by {report.primary_event_type} coverage): **{report.total_cells}**"
    )
    lines.append("")
    lines.append(f"## Verdict — **{report.verdict.upper()}**")
    lines.append("")
    lines.append(report.verdict_reason)
    lines.append("")
    lines.append("## Per-event-type coverage")
    lines.append("")
    lines.append(
        "| event_type | cells | cells w/ data | "
        + " | ".join(f"≥N={t}" for t in THRESHOLDS)
        + " | total obs |"
    )
    lines.append(
        "|---|---:|---:|"
        + "|".join("---:" for _ in THRESHOLDS)
        + "|---:|"
    )
    for summary in report.event_type_summaries:
        row = (
            f"| `{summary.event_type}` "
            f"| {summary.total_cells} "
            f"| {summary.cells_with_any_data} "
        )
        for t in THRESHOLDS:
            row += f"| {summary.cells_at_thresholds.get(t, 0)} "
        row += f"| {summary.total_observations} |"
        lines.append(row)
    lines.append("")
    lines.append(
        f"## Per-decision-class coverage ({report.primary_event_type})"
    )
    lines.append("")
    if not report.decision_class_summaries:
        lines.append("_No decision classes carry any data._")
    else:
        lines.append(
            "| decision_class | distinct models | median obs/cell | total obs |"
        )
        lines.append("|---|---:|---:|---:|")
        for s in report.decision_class_summaries:
            lines.append(
                f"| `{s.decision_class}` "
                f"| {s.distinct_models} "
                f"| {s.median_obs_primary:.1f} "
                f"| {s.total_obs_primary} |"
            )
    lines.append("")
    return "\n".join(lines)


def render_json(report: AuditReport) -> str:
    payload = asdict(report)
    return json.dumps(payload, indent=2, sort_keys=True)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="scorecard-audit",
        description=(
            "Audit a scorecard sidecar for data sufficiency. Gates "
            "Phase 1b (Beta priors) of the calibrated-aggregation arc."
        ),
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=DEFAULT_PATH,
        help=(
            f"Path to the scorecard JSON (default: {DEFAULT_PATH}). "
            "Pass a project-local path to audit a project sidecar."
        ),
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of markdown. Phase 1b reads this shape.",
    )
    args = parser.parse_args(argv)

    report = audit(args.path)
    if args.json:
        sys.stdout.write(render_json(report))
        sys.stdout.write("\n")
    else:
        sys.stdout.write(render_markdown(report))

    # Exit code mirrors the verdict so the audit is usable in CI gates:
    #   0 = green, 1 = amber, 2 = red, 3 = no-data.
    return {"green": 0, "amber": 1, "red": 2, "no-data": 3}[report.verdict]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

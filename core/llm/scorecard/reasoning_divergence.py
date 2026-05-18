"""Producer wiring for ``EventType.REASONING_DIVERGENCE``.

Sister of ``core.llm.scorecard.consensus`` for the ``agreed-verdict``
case. ``consensus`` only fires on disputed findings (split panels);
this producer covers the gap: panels that agreed on the verdict but
their reasoning text diverged. Translation: "everyone said
exploitable, but for noticeably different reasons — the outlier is
the most likely to be right for the wrong reason".

For each ``"high"`` / ``"high-negative"`` finding in the correlation
result:

  * Compute reasoning divergence via :mod:`core.llm.semantic_entropy`.
  * If the metric is ``None`` (panel too small / reasoning too short)
    → skip the finding.
  * If ``mean_pairwise_distance < threshold`` → skip (panel is tight,
    no anomaly to report). The threshold is configurable; default
    ``0.80`` derived from the test-fixture distribution between
    aligned (~0.67) and divergent (~0.91) panels. Operators should
    re-calibrate from real data once a few runs have accumulated.
  * Otherwise: outlier model (farthest reasoning from the rest of
    the panel) → ``incorrect``; the remaining panel members →
    ``correct``.

Disputed findings are skipped — they belong to ``consensus`` and
double-counting them here would inject correlated noise into the
two cells.

Sister producers in the same family:

  * ``core.llm.scorecard.prefilter`` — ``CHEAP_SHORT_CIRCUIT``.
  * ``core.llm.scorecard.consensus`` — ``MULTI_MODEL_CONSENSUS``
    (disputed-finding sibling of this producer).
  * ``core.llm.scorecard.judge`` — ``JUDGE_REVIEW``.
  * ``core.llm.scorecard.tool_evidence`` — ``TOOL_EVIDENCE``.

These all use the same ``record_event`` substrate API + same
decision_class shape (``<consumer>:<rule_id>``).

Observability-only in v1: no policy gate consumes
``REASONING_DIVERGENCE`` yet. The cell counters accumulate so
operators can query them via ``scorecard cli`` and we can decide
whether to promote any of the deferred policies — see
``project_semantic_entropy`` memory for the three deferred options.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from core.llm.semantic_entropy import divergence

from . import _MAX_REASONING_CHARS
from .scorecard import EventType, ModelScorecard

logger = logging.getLogger(__name__)

# Default Jaccard mean-pairwise threshold above which the panel is
# considered divergent. Sits between aligned (~0.67) and divergent
# (~0.91) on the test fixtures. Tunable per call; should be replaced
# with a calibrated value once operators have real data.
DEFAULT_DIVERGENCE_THRESHOLD = 0.80


def record_reasoning_divergence(
    scorecard: Optional[ModelScorecard],
    *,
    correlation: Dict[str, Any],
    results_by_id: Dict[str, Dict],
    per_finding_results: Optional[Dict[str, Any]] = None,
    decision_class_prefix: str = "agentic",
    divergence_threshold: float = DEFAULT_DIVERGENCE_THRESHOLD,
) -> int:
    """Walk a correlation result; record one
    ``REASONING_DIVERGENCE`` event per (model, finding) pair on
    agreed findings whose reasoning dispersion exceeds the threshold.

    Returns the number of events written.

    No-op when ``scorecard`` is ``None`` (operator opted out via
    ``scorecard_enabled=False`` or the consumer didn't have a
    scorecard available). No-op when ``correlation`` is empty
    (single-model run). No-op when ``per_finding_results`` is
    ``None``: without per-model reasoning we have nothing to
    measure — consensus can still record outcomes because verdicts
    are in the matrix, but divergence needs the text.

    ``per_finding_results``: mapping ``{finding_id: [per-model
    result dict, ...]}`` from the orchestrator's per-model dispatch.
    Each per-model dict must carry ``analysed_by`` (or ``model``)
    and ``reasoning``. Decoupled from ``results_by_id`` for the same
    reason as in ``record_consensus_outcomes``: we don't want to
    mutate records the orchestrator later serialises into
    ``orchestrated_report.json``.

    Failure path: any per-event ``record_event`` exception is logged
    at debug level and swallowed; one bad event must not abort the
    whole batch and must never block the calling orchestrator's flow.
    """
    if scorecard is None or not correlation or not per_finding_results:
        return 0
    confidence = correlation.get("confidence_signals") or {}
    if not confidence:
        return 0

    n_recorded = 0
    for fid, signal in confidence.items():
        if signal not in ("high", "high-negative"):
            # Disputed findings → handled by ``record_consensus_outcomes``.
            # Anything else (``single_model``, ``mixed``, ...) → not the
            # agreed-verdict case this producer covers.
            continue

        per_model_records = per_finding_results.get(fid) or []
        reasonings: Dict[str, str] = {}
        for r in per_model_records:
            model_name = str(
                r.get("analysed_by") or r.get("model") or ""
            )
            text = r.get("reasoning") or ""
            if model_name and text:
                reasonings[model_name] = str(text)

        metric = divergence(reasonings)
        if metric is None:
            # Panel too small or reasoning too short to measure.
            continue
        mean_pw = float(metric["mean_pairwise_distance"])
        if mean_pw < divergence_threshold:
            # Panel is tight enough; no anomaly to report.
            continue

        outlier = str(metric["outlier_model"])
        result = results_by_id.get(fid) or {}
        rule_id = str(result.get("rule_id") or "unknown")
        decision_class = f"{decision_class_prefix}:{rule_id}"

        for model in reasonings:
            is_outlier = (model == outlier)
            outcome = "incorrect" if is_outlier else "correct"
            sample = None
            if is_outlier:
                # Capture the outlier's own reasoning so the operator
                # can quickly see WHY this model's text drifted from
                # the rest of the panel. ``other_reasoning`` carries
                # the divergence summary rather than another model's
                # text — there isn't a single "other" to compare to
                # here, so a panel-level summary is more useful.
                this_reasoning = reasonings.get(model, "")
                sample = {
                    "this_reasoning": this_reasoning[:_MAX_REASONING_CHARS],
                    "other_reasoning": (
                        f"panel mean pairwise distance: {mean_pw:.3f} "
                        f"(threshold {divergence_threshold:.2f}); "
                        f"max pairwise: {float(metric['max_pairwise_distance']):.3f}; "
                        f"outlier of {int(metric['n_models'])} models"
                    ),
                }
            try:
                scorecard.record_event(
                    decision_class=decision_class,
                    model=model,
                    event_type=EventType.REASONING_DIVERGENCE,
                    outcome=outcome,
                    sample=sample,
                )
                n_recorded += 1
            except Exception as e:                       # noqa: BLE001
                # WARNING (not DEBUG): see consensus.py for rationale.
                logger.warning(
                    "record_reasoning_divergence: failed to record "
                    "%s/%s on %s: %s",
                    model, decision_class, fid, e,
                )
    return n_recorded


__all__ = [
    "record_reasoning_divergence",
    "DEFAULT_DIVERGENCE_THRESHOLD",
]

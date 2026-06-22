"""Calibrated aggregation entry point — Phase 3a.

Pulls per-finding panel verdicts out of ``/agentic``'s
``results_by_id`` map, runs the Dawid–Skene estimator per
``decision_class``, and emits a per-finding calibrated verdict that
the orchestrator attaches alongside the existing
``multi_model_analyses`` field.

Design constraints:

* **Additive only.** Existing fields (``is_exploitable``,
  ``multi_model_analyses``, ``ruling``) are untouched. Downstream
  consumers that don't know about ``calibrated_aggregation`` keep
  working.
* **Vote fallback.** Findings with fewer than two valid panel members
  (single-model runs, all-error panels) cannot feed D–S. They get a
  record with ``aggregation_method = "vote"`` and a non-null
  ``aggregation_fallback_reason``. The posterior is the legacy
  ``is_exploitable`` boolean cast to 0.0 / 1.0 so triage ordering
  still has something usable.
* **Pure function.** No IO; no scorecard reads; no logging. The
  orchestrator owns side effects. This module is reusable from
  test code and the (future) offline replay harness.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Dict, List, Mapping, Optional, Tuple

from core.llm.multi_model.dawid_skene import (
    FindingPosterior,
    estimate_partitioned,
)
from core.llm.multi_model.panel_log import (
    DEFAULT_DECISION_CLASS_PREFIX,
    PanelRecord,
    _decision_class_for,
)
from core.llm.scorecard.priors import BetaPrior, uniform_prior


# Aggregation method tag emitted on each finding. Surfaces in the
# output JSON so an operator can grep for which findings went through
# which path.
METHOD_DAWID_SKENE = "dawid_skene"
METHOD_VOTE = "vote"


@dataclass(frozen=True)
class CalibratedVerdict:
    """The shape attached to each finding under
    ``calibrated_aggregation``.

    JSON serialised via :func:`asdict` in the orchestrator; field
    names here are the on-disk schema.
    """
    posterior_true_positive: float
    credible_interval: Tuple[float, float]
    n_models: int
    decision_class: str
    aggregation_method: str  # METHOD_DAWID_SKENE | METHOD_VOTE
    aggregation_fallback_reason: Optional[str]
    converged: bool
    # Per-model inferred reliability for this decision class. Empty list
    # when method == METHOD_VOTE. Useful for explainability surfaces and
    # for Phase 4's posterior-weighted scorecard updates.
    model_reliabilities: List[Dict[str, float]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Conversion: orchestrator results → PanelRecord list
# ---------------------------------------------------------------------------


def _records_from_finding(
    finding_id: str, finding: Mapping, *,
    decision_class_prefix: str,
) -> List[PanelRecord]:
    """Extract panel records from one finding's ``multi_model_analyses``.

    Mirrors the validity filter in ``panel_log._extract_records_from_finding``
    but operates on the orchestrator's in-memory dict shape rather than
    on-disk JSON.
    """
    analyses = finding.get("multi_model_analyses")
    if not isinstance(analyses, list):
        return []
    decision_class = _decision_class_for(
        finding.get("rule_id"), decision_class_prefix,
    )
    out: List[PanelRecord] = []
    for entry in analyses:
        if not isinstance(entry, dict) or "error" in entry:
            continue
        model = entry.get("model")
        if not isinstance(model, str) or not model:
            continue
        verdict = entry.get("is_exploitable")
        if not isinstance(verdict, bool):
            continue
        out.append(PanelRecord(
            finding_id=finding_id,
            decision_class=decision_class,
            model=model,
            verdict=verdict,
        ))
    return out


def _vote_fallback_verdict(
    finding_id: str, finding: Mapping, *, reason: str,
    decision_class_prefix: str,
) -> CalibratedVerdict:
    """Build a vote-derived verdict when D–S cannot run on this finding.

    The posterior is the legacy ``is_exploitable`` cast to 0.0 / 1.0.
    The CI degenerates to ``(posterior, posterior)`` — there is no
    calibrated uncertainty when no panel exists. Phase 3 callers can
    detect the fallback via ``aggregation_method`` rather than by
    inspecting the CI width.
    """
    decision_class = _decision_class_for(
        finding.get("rule_id"), decision_class_prefix,
    )
    raw = finding.get("is_exploitable")
    posterior = 1.0 if raw is True else 0.0
    return CalibratedVerdict(
        posterior_true_positive=posterior,
        credible_interval=(posterior, posterior),
        n_models=0,
        decision_class=decision_class,
        aggregation_method=METHOD_VOTE,
        aggregation_fallback_reason=reason,
        converged=True,
        model_reliabilities=[],
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def calibrate_results(
    results_by_id: Mapping[str, Mapping],
    *,
    default_prior: Optional[BetaPrior] = None,
    priors_by_class: Optional[Mapping[str, BetaPrior]] = None,
    decision_class_prefix: str = DEFAULT_DECISION_CLASS_PREFIX,
    **estimate_kwargs,
) -> Dict[str, CalibratedVerdict]:
    """Run calibrated aggregation across every finding in
    ``results_by_id``.

    :param results_by_id: Orchestrator's ``{finding_id: finding_dict}``
        map. Each finding may or may not have ``multi_model_analyses``.
    :param default_prior: Beta prior used for any decision class not
        in ``priors_by_class``. Defaults to ``uniform_prior()`` per
        Phase 1b's "no audit-derived rate" stance.
    :param priors_by_class: Per-decision-class priors, when available.
        Typically populated by Phase 3 wire-up once a panel-log audit
        has been run.
    :param decision_class_prefix: Decision-class key prefix; matches
        ``consensus.py``'s ``agentic:<rule_id>`` convention by default.
    :param estimate_kwargs: Forwarded to ``estimate_partitioned`` —
        ``max_iter``, ``tolerance``, ``initial_reliability``,
        ``clip_eps``, ``credible_interval_level``.

    :returns: ``{finding_id: CalibratedVerdict}`` covering every
        finding in the input. Missing-panel findings get a vote-
        fallback record so downstream lookups never KeyError.
    """
    prior = default_prior or uniform_prior()
    priors_by_class = dict(priors_by_class or {})

    # Step 1: split findings into D–S-eligible vs vote-fallback.
    panel_records: List[PanelRecord] = []
    fallback_reasons: Dict[str, str] = {}
    eligible_finding_ids: set = set()
    for fid, finding in results_by_id.items():
        recs = _records_from_finding(
            fid, finding, decision_class_prefix=decision_class_prefix,
        )
        if len(recs) >= 2:
            panel_records.extend(recs)
            eligible_finding_ids.add(fid)
        else:
            fallback_reasons[fid] = (
                "no_panel" if not recs
                else f"insufficient_panel_size_{len(recs)}"
            )

    # Step 2: run D–S across all eligible records, partitioned by class.
    out: Dict[str, CalibratedVerdict] = {}
    if panel_records:
        ds_results = estimate_partitioned(
            panel_records, priors_by_class,
            default_prior=prior, **estimate_kwargs,
        )
        ds_index: Dict[str, FindingPosterior] = {}
        ds_convergence: Dict[str, bool] = {}
        ds_reliabilities: Dict[str, List[Dict[str, float]]] = {}
        for ds_result in ds_results:
            for fp in ds_result.findings:
                ds_index[fp.finding_id] = fp
                ds_convergence[fp.finding_id] = ds_result.converged
                ds_reliabilities[fp.finding_id] = [
                    {"model": r.model, "alpha": r.alpha, "beta": r.beta}
                    for r in ds_result.model_reliabilities
                ]
        for fid in eligible_finding_ids:
            fp = ds_index.get(fid)
            if fp is None:
                # Defensive: shouldn't happen — every eligible finding
                # was fed into the EM. Fall through to vote so the
                # consumer still gets a verdict.
                fallback_reasons[fid] = "ds_missing_in_result"
                continue
            converged = ds_convergence[fid]
            method = METHOD_DAWID_SKENE if converged else METHOD_VOTE
            reason: Optional[str] = (
                None if converged else "ds_did_not_converge"
            )
            out[fid] = CalibratedVerdict(
                posterior_true_positive=fp.posterior,
                credible_interval=fp.credible_interval,
                n_models=fp.n_models,
                decision_class=fp.decision_class,
                aggregation_method=method,
                aggregation_fallback_reason=reason,
                converged=converged,
                model_reliabilities=ds_reliabilities[fid],
            )

    # Step 3: vote fallback for everything else.
    for fid, finding in results_by_id.items():
        if fid in out:
            continue
        reason = fallback_reasons.get(fid, "unknown")
        out[fid] = _vote_fallback_verdict(
            fid, finding, reason=reason,
            decision_class_prefix=decision_class_prefix,
        )

    return out


# ---------------------------------------------------------------------------
# JSON helpers — emit shapes the orchestrator can serialise as-is
# ---------------------------------------------------------------------------


def verdict_to_json(verdict: CalibratedVerdict) -> dict:
    """Convert a CalibratedVerdict to a plain dict suitable for
    ``save_json``. Tuple → list for ``credible_interval`` so JSON
    round-trips correctly."""
    payload = asdict(verdict)
    payload["credible_interval"] = list(payload["credible_interval"])
    return payload


__all__ = [
    "CalibratedVerdict",
    "METHOD_DAWID_SKENE",
    "METHOD_VOTE",
    "calibrate_results",
    "verdict_to_json",
]

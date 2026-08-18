"""Calibrated cross-model merge decision for /audit panels.

The historical ``AuditVerdictAdapter.select_primary`` was pure
prefer-positive with one heuristic (lone-dissent downgrade) — model
reliability data sat unused at decision time and a panel's primary was
picked by list order among equals. This module wires the shipped
reliability machinery into that decision:

* **Per-model per-decision-class reliability weights** come from the
  scorecard store (``core.llm.scorecard.ModelScorecard``): the Beta
  posterior mean over the cell's correct/incorrect reliability events,
  under a uniform prior. Cells with fewer than
  ``MIN_RELIABILITY_EVENTS`` observations are treated as uninformative
  (weight 0.5 — a vote that moves nothing).
* **Priors** come from /validate ground truth recorded in the review
  journal (``validate_verdict`` corrections partitioned by CWE),
  through the shipped ``priors_from_validation`` builder. Classes with
  no adjudicated history fall back to the uniform prior.
* **Ties are broken by calibrated confidence, not order**: among
  candidates on the winning side, the variant produced by the most
  reliable model is primary.

Conservative defaults: cold-start panels (no reliability data, uniform
prior) and exact ties fall back to the legacy prefer-positive rule, and
a calibrated negative decision never silently drops a positive verdict
that carries mechanical tool evidence — it demotes it to suspicious
with the decision recorded.

Telemetry: every merge decision carries a ``merge_decision`` dict
(``method``, ``posterior``, ``decision_class``, per-model weights, or
the fallback reason) so runs can be audited for which path decided
each merge.
"""

from __future__ import annotations

import logging
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

METHOD_CALIBRATED = "calibrated"
METHOD_PREFER_POSITIVE = "prefer_positive"

# Decision-class namespace for /audit panel merges. Distinct from
# /agentic's "agentic:<rule_id>" convention — audit reviews are keyed
# by CWE class, the axis the strategy/exemplar machinery already uses.
DECISION_CLASS_PREFIX = "audit"
DEFAULT_DECISION_CLASS = "audit:review"

# Scorecard event types that measure verdict correctness (as opposed to
# schema discipline or cross-run consistency). Only these feed the
# reliability weight.
RELIABILITY_EVENT_TYPES = frozenset({
    "tool_evidence",
    "multi_model_consensus",
    "judge_review",
    "operator_feedback",
    "dataflow_validation",
    "cross_family_check",
    # The two audit:<CWE> producers: the offline corpus harness and
    # the live /validate Reflexion feedback importer.
    "corpus_ground_truth",
    "validate_feedback",
})

# A reliability cell must carry at least this many adjudicated events
# before its weight deviates from the uninformative 0.5. Below this the
# Beta posterior is too prior-dominated to justify outvoting anyone.
MIN_RELIABILITY_EVENTS = 5

# Posteriors this close to 0.5 are ties — decided by the legacy
# prefer-positive rule, never by floating-point noise.
_TIE_EPSILON = 1e-9

_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)

# Statuses that cast a vote. dormant/error/unknown variants are kept in
# the panel annotations but do not move the posterior.
_POSITIVE_STATUSES = frozenset({"finding", "suspicious"})
_NEGATIVE_STATUSES = frozenset({"clean"})


@dataclass
class MergeDecision:
    """A calibrated merge outcome: the chosen primary + telemetry."""

    primary: dict[str, Any]
    telemetry: dict[str, Any] = field(default_factory=dict)


def decision_class_for(variants: list[dict[str, Any]]) -> str:
    """Derive the scorecard decision class for a panel of variants.

    Uses the first normalisable CWE tag any panel member reported;
    falls back to the catch-all audit review class.
    """
    for v in variants:
        cwe = str(v.get("cwe") or v.get("cwe_class") or "")
        m = _CWE_RE.search(cwe)
        if m:
            return f"{DECISION_CLASS_PREFIX}:{m.group(0).upper()}"
    return DEFAULT_DECISION_CLASS


def model_reliability(
    scorecard: Any,
    decision_class: str,
    model: str,
) -> float | None:
    """Beta-posterior-mean reliability for a (model, decision class) cell.

    Returns None (uninformative) when the cell is absent or carries
    fewer than ``MIN_RELIABILITY_EVENTS`` adjudicated events across the
    verdict-correctness event types. Uniform Beta(1, 1) prior — the
    conservative default.
    """
    if scorecard is None or not model:
        return None
    try:
        stats = scorecard.get_stat(decision_class, model)
    except Exception:  # never let a store read break a merge
        logger.debug("scorecard read failed for %s/%s",
                     decision_class, model, exc_info=True)
        return None
    if stats is None:
        return None
    correct = incorrect = 0
    for event_type, counts in (stats.events or {}).items():
        if event_type not in RELIABILITY_EVENT_TYPES:
            continue
        correct += getattr(counts, "correct", 0)
        incorrect += getattr(counts, "incorrect", 0)
    total = correct + incorrect
    if total < MIN_RELIABILITY_EVENTS:
        return None
    # Uniform prior Beta(1,1): posterior mean (1+c)/(2+c+i), clipped
    # away from the boundaries so log-odds stay finite.
    mean = (1.0 + correct) / (2.0 + total)
    return min(max(mean, 0.01), 0.99)


def _logit(p: float) -> float:
    return math.log(p / (1.0 - p))


def _sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


@lru_cache(maxsize=8)
def _cached_priors(out_dir_str: str) -> Mapping[str, Any]:
    return _priors_from_journal_uncached(Path(out_dir_str))


def priors_from_journal(out_dir: Path | None) -> Mapping[str, Any]:
    """Per-decision-class Beta priors from /validate journal corrections.

    Walks the review journal for entries carrying a ``validate_verdict``
    (Reflexion corrections imported from /validate runs), counts
    confirmed vs disproven per CWE, and feeds the shipped
    ``priors_from_validation`` builder. Corrections predate the current
    run (they are imported at feedback time), so a per-run cache is
    sound.
    """
    if out_dir is None:
        return {}
    try:
        return _cached_priors(str(out_dir))
    except Exception:
        logger.debug("journal prior harvest failed", exc_info=True)
        return {}


def _priors_from_journal_uncached(out_dir: Path) -> Mapping[str, Any]:
    from core.llm.scorecard.priors import priors_from_validation

    try:
        from .journal import load_entries
        entries = load_entries(out_dir)
    except Exception:  # noqa: BLE001 — read-side prior harvest, never raise
        return {}
    if not entries:
        return {}

    latest: dict[str, Any] = {}
    for e in entries:
        if not getattr(e, "validate_verdict", None):
            continue
        prev = latest.get(e.key)
        if prev is None or e.ts > prev.ts:
            latest[e.key] = e

    counts: dict[str, list[int]] = {}
    for e in latest.values():
        cwe = str(getattr(e, "cwe", "") or "")
        m = _CWE_RE.search(cwe)
        if not m:
            continue
        dc = f"{DECISION_CLASS_PREFIX}:{m.group(0).upper()}"
        bucket = counts.setdefault(dc, [0, 0])
        verdict = (e.validate_verdict or "").strip().lower()
        if verdict in ("confirmed", "exploitable"):
            bucket[0] += 1
        elif verdict in ("disproven", "ruled_out"):
            bucket[1] += 1

    counts_by_class = {
        dc: (c[0], c[1]) for dc, c in counts.items() if c[0] + c[1] > 0
    }
    if not counts_by_class:
        return {}
    return priors_from_validation(counts_by_class)


def calibrated_decision(
    variants: list[dict[str, Any]],
    *,
    scorecard: Any,
    priors_by_class: Mapping[str, Any] | None = None,
) -> MergeDecision | None:
    """Attempt a calibrated merge decision over a panel of variants.

    Returns None when calibration cannot responsibly decide — fewer
    than two voting variants, a cold-start panel (no reliability data
    AND uniform prior), or an exact tie. The caller then applies the
    legacy prefer-positive rule.

    ``variants`` must already exclude error entries; each carries at
    least ``status`` and (via merge annotation) ``_model``.
    """
    decision_class = decision_class_for(variants)

    votes: list[tuple[dict[str, Any], bool, float | None]] = []
    for v in variants:
        status = v.get("status", "")
        if status in _POSITIVE_STATUSES:
            positive_vote = True
        elif status in _NEGATIVE_STATUSES:
            positive_vote = False
        else:
            continue
        model = v.get("_model") or v.get("model") or ""
        reliability = model_reliability(scorecard, decision_class, model)
        votes.append((v, positive_vote, reliability))

    if len(votes) < 2:
        return None

    prior_obj = (priors_by_class or {}).get(decision_class)
    prior_mean = 0.5
    if prior_obj is not None:
        try:
            prior_mean = min(max(float(prior_obj.mean), 0.01), 0.99)
        except Exception:  # noqa: BLE001 — malformed prior degrades to uniform
            prior_mean = 0.5

    informative = any(r is not None for _, _, r in votes)
    if not informative and abs(prior_mean - 0.5) < _TIE_EPSILON:
        return None  # cold start — legacy rule decides

    log_odds = _logit(prior_mean)
    weights: list[dict[str, Any]] = []
    for v, positive_vote, reliability in votes:
        r = reliability if reliability is not None else 0.5
        contribution = _logit(r) if positive_vote else -_logit(r)
        log_odds += contribution
        weights.append({
            "model": v.get("_model") or v.get("model") or "",
            "status": v.get("status", ""),
            "reliability": round(r, 4),
            "informative": reliability is not None,
        })

    posterior = _sigmoid(log_odds)
    if abs(posterior - 0.5) < _TIE_EPSILON:
        return None  # exact tie — legacy rule decides

    decide_positive = posterior > 0.5
    telemetry: dict[str, Any] = {
        "method": METHOD_CALIBRATED,
        "decision_class": decision_class,
        "posterior_positive": round(posterior, 6),
        "prior": round(prior_mean, 4),
        "weights": weights,
    }

    def _rel(entry: tuple) -> float:
        _, _, r = entry
        return r if r is not None else 0.5

    winning = [e for e in votes if e[1] == decide_positive]
    if not winning:
        return None  # defensive: nothing on the winning side

    if decide_positive:
        status_rank = {"finding": 0, "suspicious": 1}
        primary_entry = min(
            winning,
            key=lambda e: (status_rank.get(e[0].get("status", ""), 9),
                           -_rel(e)),
        )
        return MergeDecision(primary=dict(primary_entry[0]),
                             telemetry=telemetry)

    # Negative decision. Guard: a positive verdict backed by mechanical
    # tool evidence is never silently dropped by a textual majority —
    # demote it to suspicious with the decision recorded.
    losing_positive = [e for e in votes if e[1]]
    try:
        from .evidence_grade import is_tool_evidence
    except ImportError:  # pragma: no cover
        is_tool_evidence = lambda _ev: False
    tool_backed = [
        e for e in losing_positive
        if is_tool_evidence(e[0].get("evidence_tool", "") or "")
    ]
    if tool_backed:
        primary_entry = max(tool_backed, key=_rel)
        primary = dict(primary_entry[0])
        primary["status"] = "suspicious"
        primary["calibrated_downgrade"] = True
        telemetry["guard"] = "tool_evidence_preserved"
        return MergeDecision(primary=primary, telemetry=telemetry)

    primary_entry = max(winning, key=_rel)
    return MergeDecision(primary=dict(primary_entry[0]),
                         telemetry=telemetry)


__all__ = [
    "DECISION_CLASS_PREFIX",
    "DEFAULT_DECISION_CLASS",
    "METHOD_CALIBRATED",
    "METHOD_PREFER_POSITIVE",
    "MIN_RELIABILITY_EVENTS",
    "RELIABILITY_EVENT_TYPES",
    "MergeDecision",
    "calibrated_decision",
    "decision_class_for",
    "model_reliability",
    "priors_from_journal",
]

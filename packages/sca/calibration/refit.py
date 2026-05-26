"""Calibration refitter — grid search over multiplier constants.

When the validator's verdict is ``needs_retune``, this module
grid-searches each tunable multiplier in :mod:`packages.sca.risk`
for a value that improves top-20 precision against the calibration
corpus, subject to a max-delta cap and an improvement gate.

## Why grid search rather than logistic regression?

The risk formula in ``risk.py`` is multiplicative:

    score = (cvss/10)*100 × kev_mult × epss_mult × reach_mult × ...

Logistic regression would assume additive log-odds; mapping the
fitted coefficients back to specific named constants is fuzzy
(each constant flows through different parts of the formula).
Grid search, by contrast:

  * Directly evaluates each constant in terms of the metric we
    care about (top-20 precision).
  * Each step is interpretable: "we tried K=1.20, K=1.08, K=1.32;
    K=1.08 had best precision."
  * Pure-Python — no numpy / sklearn dependency. Refit is a
    monthly CI job; install cost matters.
  * Captures interactions implicitly: each per-constant search
    runs against the SAME live formula (with all other constants
    at current values), so the chosen value is best given the
    rest of the formula as-is.

## Algorithm

For each tunable constant C in ``risk.TUNABLE_CONSTANTS``:

    1. Compute top-20 precision with all current constants.
       Call this ``baseline``.
    2. Compute precision with C overridden at C × 0.9, C × 1.1.
       Call these ``low``, ``high``.
    3. Pick the variant with highest precision. Apply the
       max-delta cap (already enforced by the ±10% bracket).
    4. If the chosen variant ties baseline, leave C unchanged.

## Improvement gate

After per-constant search, run validation with all proposed
overrides applied AT ONCE. If overall top-20 precision improvement
is < ``improvement_threshold`` (default 5%), reject the refit —
return a report flagging it but not proposing changes.

## Sample-count floor

The refitter refuses to run with fewer than ``MIN_SAMPLES_FOR_REFIT``
labelled findings. Below that, return verdict=``insufficient_samples``;
the corpus needs to grow before a refit is meaningful.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# Below this many labelled findings, refit refuses to run.
# Logistic-regression-style fits need more, but grid search on
# top-20 precision can be informative at lower N. 100 is a
# pragmatic floor — fewer than that and the precision metric
# itself is noisy.
MIN_SAMPLES_FOR_REFIT = 100

# Per-constant max-delta. Each refit moves a constant at most
# ±10% from its current value. Capped to prevent a noisy corpus
# from swinging the formula wildly.
DEFAULT_MAX_DELTA = 0.10

# Minimum top-20 precision improvement (absolute, not relative)
# required for the refit to ship. 0.05 = "5 more percentage
# points of precision". Below that, the refit is rejected
# regardless of per-constant gains, on the grounds that small
# gains can be noise from the corpus's idiosyncrasies.
DEFAULT_IMPROVEMENT_THRESHOLD = 0.05


@dataclass
class ConstantRefit:
    """Per-constant search result."""

    name: str
    current: float
    proposed: float
    baseline_precision: float
    proposed_precision: float

    @property
    def changed(self) -> bool:
        return self.proposed != self.current

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "current": self.current,
            "proposed": self.proposed,
            "baseline_precision": self.baseline_precision,
            "proposed_precision": self.proposed_precision,
            "changed": self.changed,
        }


@dataclass
class RefitReport:
    """Top-level refit result.

    Status values:
      * ``"proposed"`` — refit ran, improvement gate passed,
        proposed values should be applied.
      * ``"rejected"`` — refit ran, improvement below threshold;
        proposed values shipped for inspection but should NOT be
        applied.
      * ``"insufficient_samples"`` — corpus too small;
        nothing proposed.
      * ``"error"`` — refit couldn't run (corpus missing,
        unreadable, etc.).
    """

    snapshot_date: str
    status: str
    sample_count: int
    overall_baseline_precision: float
    overall_proposed_precision: float
    improvement: float
    improvement_threshold: float
    max_delta: float
    per_constant: List[ConstantRefit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)

    @property
    def proposed_values(self) -> Dict[str, float]:
        """Return the proposed override dict — what to feed to
        ``compute_risk_estimate(overrides=...)`` to apply this
        refit. Only constants that genuinely changed appear."""
        return {
            c.name: c.proposed for c in self.per_constant
            if c.changed
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_date": self.snapshot_date,
            "status": self.status,
            "sample_count": self.sample_count,
            "overall_baseline_precision": self.overall_baseline_precision,
            "overall_proposed_precision": self.overall_proposed_precision,
            "improvement": self.improvement,
            "improvement_threshold": self.improvement_threshold,
            "max_delta": self.max_delta,
            "per_constant": [c.to_dict() for c in self.per_constant],
            "notes": list(self.notes),
            "proposed_values": self.proposed_values,
        }


def grid_search_refit(
    corpus_dir: Path,
    *,
    max_delta: float = DEFAULT_MAX_DELTA,
    improvement_threshold: float = DEFAULT_IMPROVEMENT_THRESHOLD,
    min_samples: int = MIN_SAMPLES_FOR_REFIT,
    out_path: Optional[Path] = None,
    ecosystem_filter: Optional[str] = None,
) -> RefitReport:
    """Run the per-constant grid search and emit a refit report.

    ``corpus_dir`` is the calibration data root containing
    ``kev_signals.json`` etc. + ``project_samples/<eco>/<name>.json``.

    Writes the report to ``corpus_dir/refit/<date>.json`` (or
    ``out_path`` when explicitly supplied).

    ``ecosystem_filter``: when set, drops findings outside the
    named ecosystem before fitting. Useful for "what would
    Maven-only optimal constants look like" investigations
    without changing the cross-ecosystem code path. The same
    ``min_samples`` cold-start gate applies to the filtered
    set — ecosystems with too few findings get rejected.
    """
    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    notes: List[str] = []

    samples = _load_findings_with_labels(corpus_dir)
    if ecosystem_filter is not None:
        before = len(samples)
        samples = [
            (f, label) for f, label in samples
            if (f.get("ecosystem") or "?") == ecosystem_filter
        ]
        notes.append(
            f"ecosystem_filter={ecosystem_filter!r}: "
            f"{before} → {len(samples)} samples"
        )
    if not samples:
        return _emit_report(
            RefitReport(
                snapshot_date=snapshot, status="error",
                sample_count=0,
                overall_baseline_precision=0.0,
                overall_proposed_precision=0.0,
                improvement=0.0,
                improvement_threshold=improvement_threshold,
                max_delta=max_delta,
                notes=[
                    "no project samples found under "
                    f"{corpus_dir}/project_samples/",
                ],
            ),
            corpus_dir, out_path,
        )

    if len(samples) < min_samples:
        return _emit_report(
            RefitReport(
                snapshot_date=snapshot,
                status="insufficient_samples",
                sample_count=len(samples),
                overall_baseline_precision=0.0,
                overall_proposed_precision=0.0,
                improvement=0.0,
                improvement_threshold=improvement_threshold,
                max_delta=max_delta,
                notes=[
                    f"only {len(samples)} labelled findings in corpus; "
                    f"need ≥ {min_samples} for refit",
                ],
            ),
            corpus_dir, out_path,
        )

    from packages.sca.risk import (
        TUNABLE_CONSTANTS, current_constants, is_admissible,
    )
    current = current_constants()

    # Baseline precision — score every sample with current constants.
    baseline = _top_20_precision(samples, overrides=None)
    notes.append(
        f"baseline top-20 precision = {baseline:.3f} on "
        f"{len(samples)} samples"
    )

    # Per-constant search. Each candidate runs in isolation against
    # the live formula (all other constants at their current values).
    # Admissibility check filters candidates that violate the bounds
    # or cross-constraints declared in risk.py — without it, a
    # wider --max-delta would happily propose values that maximise
    # top-20 on this corpus by violating design intent (e.g. EE_MULT
    # crossing KEV_MULT, NOT_EVALUATED becoming a bonus instead of
    # penalty). Inadmissible candidates produce a precision of -inf
    # so they're never picked even when they'd numerically maximise.
    # `_search_metric` returns (top_20, top_50). max() over tuples
    # compares lexicographically — top-20 dominates, top-50 breaks
    # ties. The legacy scalar `_top_20_precision` is preserved for
    # the verdict + report fields; the search itself runs on the
    # tuple so once the corpus saturates top-20 at 1.000 the search
    # keeps moving on top-50 instead of silently sticking to the
    # first-seen candidate.
    SENTINEL_INADMISSIBLE = (float("-inf"), float("-inf"), float("-inf"))

    per_constant: List[ConstantRefit] = []
    for name in TUNABLE_CONSTANTS:
        cur = current[name]
        candidates = [
            cur,                  # no change — always admissible
            cur * (1.0 - max_delta),
            cur * (1.0 + max_delta),
        ]
        metrics: List[Tuple[float, float, float]] = []
        for c in candidates:
            full_values = {**current, name: c}
            ok, _reason = is_admissible(full_values)
            if not ok:
                metrics.append(SENTINEL_INADMISSIBLE)
            else:
                metrics.append(
                    _search_metric(samples, overrides={name: c})
                )
        # Pick the highest metric tuple; tie → keep current (index 0).
        best_idx = max(range(3), key=lambda i: metrics[i])
        if metrics[best_idx] <= metrics[0]:
            best_idx = 0
        # Note inadmissible rejections so the report is honest about
        # which candidate was filtered (and why), rather than silently
        # picking the second-best.
        for idx, c in enumerate(candidates):
            if idx == 0:
                continue
            if metrics[idx] == SENTINEL_INADMISSIBLE:
                _ok, reason = is_admissible({**current, name: c})
                notes.append(
                    f"{name}={c:.4g} rejected: {reason}"
                )
        # Report fields keep the scalar top-20 precision (back-
        # compat with operator dashboards / the auto-PR diff).
        baseline_p20 = (metrics[0][0]
                        if metrics[0] != SENTINEL_INADMISSIBLE else 0.0)
        proposed_p20 = (metrics[best_idx][0]
                        if metrics[best_idx] != SENTINEL_INADMISSIBLE
                        else 0.0)
        per_constant.append(ConstantRefit(
            name=name,
            current=cur,
            proposed=candidates[best_idx],
            baseline_precision=baseline_p20,
            proposed_precision=proposed_p20,
        ))

    # Compose all proposed overrides and re-score. Per-constant
    # improvements may not stack additively; this is the joint
    # effect. The composed candidate must ALSO pass admissibility
    # — a per-constant search picks each constant in isolation, so
    # a cross-constraint that's only violated when TWO constants
    # both move in the same direction would slip past the per-
    # constant gate. Joint admissibility check catches that.
    joint_overrides = {
        c.name: c.proposed for c in per_constant if c.changed
    }
    if joint_overrides:
        joint_full = {**current, **joint_overrides}
        ok_joint, joint_reason = is_admissible(joint_full)
        if not ok_joint:
            notes.append(
                f"joint composition rejected: {joint_reason}; "
                f"falling back to baseline"
            )
            joint_overrides = {}
    joint_precision = (
        _top_20_precision(samples, overrides=joint_overrides)
        if joint_overrides else baseline
    )
    improvement = joint_precision - baseline

    # ρ-aware improvement gate. When P20 is saturated at 1.0
    # across many candidates (the post-Vulnrichment regime),
    # the legacy P20-only gate rejects everything because there's
    # no room to improve. ρ catches the case where the joint
    # weight set improves rank correlation across the WHOLE
    # corpus even when top-20 is already perfect. The two
    # improvements compose via OR — either dimension reaching
    # the threshold accepts the refit. Same threshold value is
    # reused for ρ (5% in [0, 1] terms = a meaningful jump for
    # rank correlation).
    baseline_rho_tuple = _search_metric(samples, overrides=None)
    baseline_rho = baseline_rho_tuple[2]
    joint_rho = (
        _search_metric(samples, overrides=joint_overrides)[2]
        if joint_overrides else baseline_rho
    )
    rho_improvement = joint_rho - baseline_rho

    if not joint_overrides:
        status = "rejected"
        notes.append("no per-constant variant beat the baseline")
    elif (improvement < improvement_threshold
            and rho_improvement < improvement_threshold):
        status = "rejected"
        notes.append(
            f"joint P20 improvement {improvement:+.3f} AND ρ "
            f"improvement {rho_improvement:+.3f} both below "
            f"threshold {improvement_threshold:.3f}; refit not shipped"
        )
    else:
        status = "proposed"
        if rho_improvement >= improvement_threshold:
            notes.append(
                f"accepted on ρ improvement {rho_improvement:+.3f} "
                f"(P20 improvement {improvement:+.3f})"
            )
        notes.append(
            f"joint improvement {improvement:.3f} ≥ threshold "
            f"{improvement_threshold:.3f}; refit ready to apply"
        )

    return _emit_report(
        RefitReport(
            snapshot_date=snapshot, status=status,
            sample_count=len(samples),
            overall_baseline_precision=baseline,
            overall_proposed_precision=joint_precision,
            improvement=improvement,
            improvement_threshold=improvement_threshold,
            max_delta=max_delta,
            per_constant=per_constant,
            notes=notes,
        ),
        corpus_dir, out_path,
    )


# ---------------------------------------------------------------------------
# Joint refitter — multi-pass coordinate descent with random restarts.
# ---------------------------------------------------------------------------
#
# The per-constant ``grid_search_refit`` above evaluates each constant
# in isolation, treating the rest of the formula as fixed at its
# CURRENT values. That misses interactions: pairs of constants where
# the optimal move for C₁ depends on C₂ already having moved (e.g.
# raising ``_KEV_MULTIPLIER`` alone hurts ρ, but raising
# ``_KEV_MULTIPLIER`` AND lowering ``_EPSS_FLOOR_MULTIPLIER`` together
# helps both).
#
# Full cartesian search over 16 constants is intractable
# (3¹⁶ ≈ 43M evaluations at ±max_delta-bracket grid). The realistic
# approach is **coordinate descent with random restarts**:
#
#   1. Pick a starting point (current_constants for restart 0; random
#      admissible point inside the ±max_delta bracket for the others).
#   2. PASS: for each constant, find its best value given the current
#      values of all other constants. Apply the winner before moving
#      to the next constant.
#   3. Repeat passes until no constant moves (converged) or
#      ``_MAX_JOINT_PASSES`` reached.
#   4. Repeat steps 1-3 across ``_DEFAULT_JOINT_RESTARTS`` restarts;
#      return the best metric tuple seen across all restarts.
#
# Total drift bound: every candidate considered in step 2 is clamped
# to ``[starting * (1 - max_delta), starting * (1 + max_delta)]`` —
# the ±max_delta cap from the STARTING constants, not the iteration
# constants. So no single refit run can move a constant by more than
# ±max_delta total, regardless of how many passes the coordinate
# descent ran. This preserves the safety-floor semantics that made
# the per-constant refitter safe to auto-apply.
#
# Improvement gate: joint must beat per-constant by
# ``improvement_threshold`` on the same composite metric the
# single-pass search uses (P20 ∨ ρ). The single-pass result is
# always preserved as a fallback so a no-improvement joint search
# isn't wasted compute — it confirms the per-constant search found
# the basin floor on this corpus.

# Coordinate-descent loop cap. Convergence on the per-constant
# bracket usually happens in 2-3 passes; the cap is a safety net
# against pathological non-converging cases.
_MAX_JOINT_PASSES = 6

# Default restart count. Restart 0 always starts from
# ``current_constants()`` (= the single-pass starting point); the
# remaining restarts seed from random admissible points inside the
# bracket. 4 restarts balances "robust against local optima" with
# "compute cost stays under ~10s on a 4000-finding corpus".
_DEFAULT_JOINT_RESTARTS = 4


@dataclass
class JointRestartTrace:
    """One restart's coordinate-descent trajectory.

    Surfaced in the report so an operator inspecting a joint refit
    can see WHY the search picked a particular endpoint — which
    restart converged where, how many passes each took, whether any
    restart got stuck on an inadmissible swap mid-iteration.
    """

    seed_index: int             # 0 = current, 1+ = random
    passes: int                 # iterations until convergence (or cap)
    converged: bool             # True if no constant moved in final pass
    starting_metric: Tuple[float, float, float]
    final_metric: Tuple[float, float, float]
    final_values: Dict[str, float]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seed_index": self.seed_index,
            "passes": self.passes,
            "converged": self.converged,
            "starting_metric": list(self.starting_metric),
            "final_metric": list(self.final_metric),
            "final_values": dict(self.final_values),
        }


@dataclass
class JointRefitReport:
    """Top-level joint-refit result. Mirrors :class:`RefitReport`
    fields for compatibility with downstream tools, adds joint-
    specific trace data."""

    snapshot_date: str
    status: str
    sample_count: int
    overall_baseline_precision: float
    overall_proposed_precision: float
    improvement: float
    improvement_threshold: float
    max_delta: float
    # Per-constant proposed values (winning restart's endpoint),
    # in the same shape as RefitReport.per_constant so
    # _apply_refit.py can consume either report type.
    per_constant: List[ConstantRefit] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    # Joint-specific:
    restarts: List[JointRestartTrace] = field(default_factory=list)
    single_pass_metric: Tuple[float, float, float] = (0.0, 0.0, 0.0)
    joint_winning_metric: Tuple[float, float, float] = (0.0, 0.0, 0.0)

    @property
    def proposed_values(self) -> Dict[str, float]:
        return {
            c.name: c.proposed for c in self.per_constant
            if c.changed
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_date": self.snapshot_date,
            "status": self.status,
            "sample_count": self.sample_count,
            "overall_baseline_precision": self.overall_baseline_precision,
            "overall_proposed_precision": self.overall_proposed_precision,
            "improvement": self.improvement,
            "improvement_threshold": self.improvement_threshold,
            "max_delta": self.max_delta,
            "per_constant": [c.to_dict() for c in self.per_constant],
            "notes": list(self.notes),
            "restarts": [r.to_dict() for r in self.restarts],
            "single_pass_metric": list(self.single_pass_metric),
            "joint_winning_metric": list(self.joint_winning_metric),
            "proposed_values": self.proposed_values,
            "mode": "joint",
        }


def joint_grid_search_refit(
    corpus_dir: Path,
    *,
    max_delta: float = DEFAULT_MAX_DELTA,
    improvement_threshold: float = DEFAULT_IMPROVEMENT_THRESHOLD,
    min_samples: int = MIN_SAMPLES_FOR_REFIT,
    restarts: int = _DEFAULT_JOINT_RESTARTS,
    max_passes: int = _MAX_JOINT_PASSES,
    seed: Optional[int] = None,
    out_path: Optional[Path] = None,
    ecosystem_filter: Optional[str] = None,
) -> JointRefitReport:
    """Multi-pass coordinate descent with random restarts.

    Find inter-constant interactions the per-constant search misses.
    See the section header above for the algorithm + safety bounds.

    ``seed`` makes the random-restart sampling deterministic — same
    seed produces the same restart trajectories, so refits run from
    CI auto-PRs are reproducible.
    """
    import random

    snapshot = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    notes: List[str] = []

    samples = _load_findings_with_labels(corpus_dir)
    if ecosystem_filter is not None:
        before = len(samples)
        samples = [
            (f, label) for f, label in samples
            if (f.get("ecosystem") or "?") == ecosystem_filter
        ]
        notes.append(
            f"ecosystem_filter={ecosystem_filter!r}: "
            f"{before} → {len(samples)} samples"
        )

    if not samples or len(samples) < min_samples:
        status = ("error" if not samples else "insufficient_samples")
        why = (
            "no project samples found"
            if not samples else
            f"only {len(samples)} labelled findings; need ≥ {min_samples}"
        )
        return _emit_joint_report(
            JointRefitReport(
                snapshot_date=snapshot, status=status,
                sample_count=len(samples),
                overall_baseline_precision=0.0,
                overall_proposed_precision=0.0,
                improvement=0.0,
                improvement_threshold=improvement_threshold,
                max_delta=max_delta,
                notes=[why],
            ),
            corpus_dir, out_path,
        )

    from packages.sca.risk import (
        TUNABLE_CONSTANTS, current_constants, is_admissible,
    )
    current = current_constants()
    bracket = {
        n: (
            current[n] * (1.0 - max_delta),
            current[n] * (1.0 + max_delta),
        ) for n in TUNABLE_CONSTANTS
    }

    rng = random.Random(seed)
    baseline_tuple = _search_metric(samples, overrides=None)
    notes.append(
        f"baseline metric (P20, NDCG, ρ) = "
        f"({baseline_tuple[0]:.3f}, {baseline_tuple[1]:.3f}, "
        f"{baseline_tuple[2]:.3f}) on {len(samples)} samples"
    )

    # Always run the single-pass per-constant search first so we
    # can compare joint to single. Cheap (~50 evals); gives a
    # fallback when joint doesn't improve.
    single_pass = grid_search_refit(
        corpus_dir, max_delta=max_delta,
        improvement_threshold=improvement_threshold,
        min_samples=min_samples,
        # Suppress the disk write — we'll emit our own joint
        # report. ``out_path=`` to /dev/null isn't supported on
        # Windows but tests pass an explicit tmp path; for the
        # in-line call we write to a throwaway path and clean it
        # up on success.
        out_path=corpus_dir / "refit" / f".{snapshot}.single.tmp",
        ecosystem_filter=ecosystem_filter,
    )
    try:
        (corpus_dir / "refit" / f".{snapshot}.single.tmp").unlink()
    except FileNotFoundError:
        pass
    single_pass_overrides = {
        c.name: c.proposed for c in single_pass.per_constant if c.changed
    }
    single_pass_metric = (
        _search_metric(samples, overrides=single_pass_overrides)
        if single_pass_overrides else baseline_tuple
    )
    notes.append(
        f"single-pass per-constant ends at "
        f"(P20={single_pass_metric[0]:.3f}, "
        f"NDCG={single_pass_metric[1]:.3f}, "
        f"ρ={single_pass_metric[2]:.3f})"
    )

    # Per-coordinate-descent-step candidate granularity. 5 points
    # per step covers the bracket density needed to find an interior
    # optimum without over-evaluating: current, ±max_delta/3, and
    # ±max_delta (bracket edges).
    def _step_candidates(name: str, cur_val: float) -> List[float]:
        lo, hi = bracket[name]
        step = (hi - cur_val) / 3.0
        step_lo = (cur_val - lo) / 3.0
        # Clamp to bracket — coordinate descent must not drift past
        # ±max_delta from the STARTING (current_constants) value.
        return sorted({
            cur_val,
            max(lo, cur_val - step_lo),
            min(hi, cur_val + step),
            lo,
            hi,
        })

    def _descent_from(
        seed_idx: int, start_values: Dict[str, float],
    ) -> JointRestartTrace:
        values = dict(start_values)
        starting_metric = _search_metric(samples, overrides=values)
        passes_used = 0
        converged = False
        for pass_num in range(max_passes):
            changed_any = False
            for name in TUNABLE_CONSTANTS:
                candidates = _step_candidates(name, values[name])
                best_metric = _search_metric(samples, overrides=values)
                best_val = values[name]
                for c in candidates:
                    if c == values[name]:
                        continue
                    trial = {**values, name: c}
                    ok, _reason = is_admissible(trial)
                    if not ok:
                        continue
                    m = _search_metric(samples, overrides=trial)
                    if m > best_metric:
                        best_metric = m
                        best_val = c
                if best_val != values[name]:
                    values[name] = best_val
                    changed_any = True
            passes_used = pass_num + 1
            if not changed_any:
                converged = True
                break
        final_metric = _search_metric(samples, overrides=values)
        return JointRestartTrace(
            seed_index=seed_idx,
            passes=passes_used,
            converged=converged,
            starting_metric=starting_metric,
            final_metric=final_metric,
            final_values=values,
        )

    # Restart 0 = current_constants. The remaining restarts seed
    # from random admissible points in the bracket.
    restart_traces: List[JointRestartTrace] = []
    restart_traces.append(_descent_from(0, current))

    for seed_idx in range(1, restarts):
        # Sample admissibly. Up to 10 rejections per seed before
        # giving up — if the admissible region is so narrow that
        # random sampling can't find an entry point in 10 tries,
        # the search isn't likely to discover much new anyway.
        sampled: Optional[Dict[str, float]] = None
        for _attempt in range(10):
            cand = {
                n: rng.uniform(bracket[n][0], bracket[n][1])
                for n in TUNABLE_CONSTANTS
            }
            ok, _reason = is_admissible(cand)
            if ok:
                sampled = cand
                break
        if sampled is None:
            notes.append(
                f"restart #{seed_idx}: skipped — could not sample "
                "an admissible starting point in 10 attempts"
            )
            continue
        restart_traces.append(_descent_from(seed_idx, sampled))

    # Pick the best restart endpoint by metric tuple.
    best_trace = max(restart_traces, key=lambda t: t.final_metric)
    joint_metric = best_trace.final_metric
    notes.append(
        f"best restart ends at "
        f"(P20={joint_metric[0]:.3f}, NDCG={joint_metric[1]:.3f}, "
        f"ρ={joint_metric[2]:.3f}) after {best_trace.passes} pass(es), "
        f"converged={best_trace.converged} (seed_index={best_trace.seed_index})"
    )

    # Build per-constant report rows from the winning restart's
    # endpoint values so downstream apply / dashboards see the
    # same shape as a single-pass refit.
    per_constant: List[ConstantRefit] = []
    for name in TUNABLE_CONSTANTS:
        cur_val = current[name]
        prop_val = best_trace.final_values[name]
        per_constant.append(ConstantRefit(
            name=name,
            current=cur_val,
            proposed=prop_val,
            # Single-value precision fields kept for back-compat;
            # the proposed value is what matters for apply.
            baseline_precision=baseline_tuple[0],
            proposed_precision=joint_metric[0],
        ))

    # Improvement gate: joint must beat the BETTER of (single-pass,
    # baseline) by ``improvement_threshold`` on either P20 or ρ.
    # Comparing to single-pass (rather than baseline) avoids
    # accepting a joint refit that just rediscovered what the
    # single-pass already found.
    reference_p20 = max(baseline_tuple[0], single_pass_metric[0])
    reference_rho = max(baseline_tuple[2], single_pass_metric[2])
    p20_improvement = joint_metric[0] - reference_p20
    rho_improvement = joint_metric[2] - reference_rho

    if (p20_improvement < improvement_threshold
            and rho_improvement < improvement_threshold):
        status = "rejected"
        # Surface whichever metric came closest to the gate so
        # operators reading the report know what's driving the
        # rejection.
        if p20_improvement >= rho_improvement:
            notes.append(
                f"joint P20 improvement vs single-pass "
                f"{p20_improvement:+.3f} (ρ {rho_improvement:+.3f}) "
                f"below threshold {improvement_threshold:.3f}; "
                f"joint search confirms per-constant is at the "
                f"basin floor on this corpus"
            )
        else:
            notes.append(
                f"joint ρ improvement vs single-pass "
                f"{rho_improvement:+.3f} (P20 {p20_improvement:+.3f}) "
                f"below threshold {improvement_threshold:.3f}; "
                f"joint search confirms per-constant is at the "
                f"basin floor on this corpus"
            )
        # Reset per_constant to the single-pass winners (or none)
        # so the report doesn't propose values we just rejected.
        per_constant = list(single_pass.per_constant)
    else:
        status = "proposed"
        notes.append(
            f"joint refit accepted: P20 {p20_improvement:+.3f}, "
            f"ρ {rho_improvement:+.3f} vs single-pass — at least "
            f"one above threshold {improvement_threshold:.3f}"
        )

    return _emit_joint_report(
        JointRefitReport(
            snapshot_date=snapshot, status=status,
            sample_count=len(samples),
            overall_baseline_precision=baseline_tuple[0],
            overall_proposed_precision=joint_metric[0],
            improvement=p20_improvement,
            improvement_threshold=improvement_threshold,
            max_delta=max_delta,
            per_constant=per_constant,
            notes=notes,
            restarts=restart_traces,
            single_pass_metric=single_pass_metric,
            joint_winning_metric=joint_metric,
        ),
        corpus_dir, out_path,
    )


def _emit_joint_report(
    report: JointRefitReport, corpus_dir: Path,
    out_path: Optional[Path],
) -> JointRefitReport:
    """Mirror of ``_emit_report`` for the joint variant. Writes to
    ``<corpus_dir>/refit/<date>.joint.json`` by default so a joint
    refit doesn't overwrite a same-day single-pass refit."""
    if out_path is None:
        refit_dir = corpus_dir / "refit"
        refit_dir.mkdir(parents=True, exist_ok=True)
        out_path = refit_dir / f"{report.snapshot_date}.joint.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


def _emit_report(
    report: RefitReport, corpus_dir: Path, out_path: Optional[Path],
) -> RefitReport:
    """Write the report to disk + return it. The CLI gates on
    return-value status; tests bypass the write by stubbing
    out_path to a tmp file."""
    if out_path is None:
        refit_dir = corpus_dir / "refit"
        refit_dir.mkdir(parents=True, exist_ok=True)
        out_path = refit_dir / f"{report.snapshot_date}.json"
    else:
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return report


# ---------------------------------------------------------------------------
# Sample → labelled-finding extraction
# ---------------------------------------------------------------------------


def _load_findings_with_labels(
    corpus_dir: Path,
) -> List[Tuple[Dict[str, Any], int]]:
    """Walk project samples; pair each finding with its exploited
    label (1 if any of the finding's CVE aliases appears in the
    KEV / EDB / MSF / GitHub-PoC ground-truth signals).

    Returns a list of ``(finding_dict, label)`` pairs. Findings
    without a usable score (no risk_components or non-float
    final) are dropped — the precision metric needs a numeric
    score.
    """
    signals = _load_ground_truth(corpus_dir)
    samples_dir = corpus_dir / "project_samples"
    if not samples_dir.is_dir():
        return []

    out: List[Tuple[Dict[str, Any], int]] = []
    for sample_path in sorted(samples_dir.rglob("*.json")):
        try:
            data = json.loads(sample_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        findings = data.get("findings") if isinstance(data, dict) else None
        if not isinstance(findings, list):
            continue
        for f in findings:
            if not isinstance(f, dict):
                continue
            cve_ids = _extract_cve_ids(f.get("advisory") or {})
            label = 1 if any(c in signals for c in cve_ids) else 0
            out.append((f, label))
    return out


def _load_ground_truth(corpus_dir: Path) -> set:
    """Union of CVE IDs marked as exploited across all ground-truth
    signal files. Mirrors ``validate.py::_load_ground_truth``.

    Signal files (built by ``calibration/build.py``) carry a top-
    level ``signals`` dict mapping CVE-id → metadata. The dict's
    keys ARE the CVE IDs we want. Earlier this function looked for
    a top-level ``items`` list shape that no signal file actually
    has — refit silently saw zero exploited CVEs and rejected every
    proposed weight as "no improvement vs baseline 0.000". Test
    fixtures were written to that wrong shape too, so the unit
    tests passed against a format the production builder never
    emitted. Fixed by matching the real format.
    """
    signals: set = set()
    for fname in (
        "kev_signals.json", "exploitdb_signals.json",
        "metasploit_signals.json", "github_poc_signals.json",
        "osv_evidence_signals.json",
        "vulnrichment_signals.json",
    ):
        path = corpus_dir / fname
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError, UnicodeDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        sig_dict = data.get("signals")
        if isinstance(sig_dict, dict):
            for cve in sig_dict:
                if isinstance(cve, str) and cve:
                    signals.add(cve)
    return signals


def _extract_cve_ids(advisory: Dict[str, Any]) -> List[str]:
    """Pull CVE IDs from an advisory record. Mirrors
    ``validate.py::_extract_cve_ids`` — including the
    ``informational`` skip so refit's ground-truth labelling
    stays aligned with the metric validate optimises."""
    out: List[str] = []
    if not isinstance(advisory, dict):
        return out
    if advisory.get("informational"):
        return out
    osv_id = advisory.get("osv_id")
    if isinstance(osv_id, str) and osv_id.startswith("CVE-"):
        out.append(osv_id)
    for alias in advisory.get("aliases", []) or []:
        if isinstance(alias, str) and alias.startswith("CVE-"):
            out.append(alias)
    return out


# ---------------------------------------------------------------------------
# Top-20 precision under override
# ---------------------------------------------------------------------------


def _top_20_precision(
    samples: List[Tuple[Dict[str, Any], int]],
    *,
    overrides: Optional[Dict[str, float]] = None,
) -> float:
    """Re-score every finding under the given overrides and
    measure the fraction of the top 20 by score that have label=1.

    Backwards-compatible scalar metric — kept for the existing
    refit verdict + report fields. The grid search itself uses
    `_search_metric` (a tuple of (top_20, top_50) precisions) so
    when top-20 saturates at 1.0 across multiple candidates,
    top-50 is the tiebreaker — without this, the search picks
    the first-seen candidate even when a strictly-better-packed
    top-50 exists.
    """
    return _search_metric(samples, overrides=overrides)[0]


def _search_metric(
    samples: List[Tuple[Dict[str, Any], int]],
    *,
    overrides: Optional[Dict[str, float]] = None,
) -> Tuple[float, float, float]:
    """Composite ``(top_20_precision, NDCG@20, spearman_rho)``
    used by the grid search's argmax.

    Tuple semantics: ``max()`` over Python tuples compares
    lexicographically:
      * top-20 precision dominates — the operator-facing verdict
        metric.
      * NDCG@20 breaks P20 ties — rewards within-top-20 ordering.
      * Spearman ρ breaks NDCG ties — captures rank correlation
        across the WHOLE corpus, not just top-20.

    The ρ term was added 2026-05-21 after the CISA Vulnrichment
    ground-truth integration. Adding 29,727 new exploited-CVE
    labels (most with SSVC=poc) pushed P20 to saturation (1.0)
    AND NDCG@20 close to saturation across many weight settings.
    Without a corpus-wide signal, the search couldn't
    distinguish weights that ranked the new SSVC-only findings
    correctly from weights that left them low. Adding ρ as a
    third tiebreaker lets the search prefer weight sets that
    rank ALL exploited findings appropriately, not just the top
    20. This matches validate.py's verdict gate (ρ ≥ 0.4) so the
    search optimises the same metric the verdict tests.

    Returns ``(top_20_precision, ndcg_20, spearman_rho)``. Each
    falls back to 0.0 when undefined (empty samples / no usable
    scores / constant labels — the last case happens when every
    finding has the same exploited-or-not label and ρ is
    mathematically undefined).
    """
    if not samples:
        return (0.0, 0.0, 0.0)
    rescored: List[Tuple[float, int]] = []
    for finding_dict, label in samples:
        score = _rescore_finding(finding_dict, overrides)
        if score is None:
            continue
        rescored.append((score, label))
    if not rescored:
        return (0.0, 0.0, 0.0)
    rescored.sort(key=lambda t: -t[0])
    top20 = rescored[:20]
    p20 = (sum(label for _, label in top20) / len(top20)) if top20 else 0.0
    ndcg20 = _ndcg_at_n(rescored, n=20)
    # ρ across the whole corpus. Use validate's hand-rolled
    # implementation (no scipy). ``None`` (constant labels)
    # collapses to 0.0 so the tuple comparison stays well-defined.
    from .validate import _spearman_rho
    scores = [s for s, _ in rescored]
    labels = [lbl for _, lbl in rescored]
    rho = _spearman_rho(scores, labels)
    return (p20, ndcg20, rho if rho is not None else 0.0)


def _ndcg_at_n(
    rescored: List[Tuple[float, int]], n: int = 20,
) -> float:
    """Normalised Discounted Cumulative Gain at rank N.

    ``rescored`` MUST be sorted by score descending (the caller
    in ``_search_metric`` does this). Binary relevance: each
    finding has label 0 (not exploited) or 1 (exploited).

    Formula (binary relevance, 0-indexed positions):
       DCG@n  = sum_{i=0..n-1}  label_i / log2(i + 2)
       IDCG@n = sum_{i=0..min(n, n_exploited)-1}  1 / log2(i + 2)
       NDCG@n = DCG@n / IDCG@n

    Returns ``0.0`` when no exploited findings exist (IDCG=0).
    Returns ``1.0`` when the top n positions are all exploited
    AND there are at most n exploited findings overall — a
    "perfect" ranking. When n_exploited > n, the cap is at
    DCG of the perfect-top-n which still equals IDCG@n, so
    NDCG remains 1.0 for any candidate whose top-n is fully
    exploited.
    """
    import math
    if not rescored:
        return 0.0
    n_exploited = sum(1 for _, label in rescored if label == 1)
    if n_exploited == 0:
        return 0.0
    dcg = sum(
        label / math.log2(i + 2)
        for i, (_, label) in enumerate(rescored[:n])
    )
    idcg = sum(
        1.0 / math.log2(i + 2)
        for i in range(min(n, n_exploited))
    )
    return dcg / idcg if idcg > 0 else 0.0


def _rescore_finding(
    finding: Dict[str, Any],
    overrides: Optional[Dict[str, float]],
) -> Optional[float]:
    """Recompute the risk score for a finding dict using the
    multiplier overrides.

    ``finding`` is the dict shape ``project_samples`` archives
    (the JSON shape of :class:`packages.sca.models.VulnFinding`
    plus a ``risk_components`` block). The archived
    ``raptor_risk_estimate`` reflects whatever constants were
    active when ``collect-samples`` ran — which drifts from the
    current ``risk.py`` constants every time refit-apply edits
    them. Reading the archive directly for the baseline (pre-fix)
    let drift accumulate: refit's baseline measured against stale
    scores, the joint-improvement gate fired against an obsolete
    metric, and a freshly-applied refit looked already-applied
    on the next refit run.

    Always re-score from the underlying inputs — using the current
    module constants when ``overrides`` is None, the proposed
    set otherwise. Both paths produce a metric coherent with the
    constants in code RIGHT NOW. Falls back to the archived
    score only when the rebuild is impossible (test fixtures
    that don't carry the full inputs).

    Returns the recomputed score, or ``None`` when the finding
    has no usable score at all.
    """
    try:
        score, _components = _compute_with_overrides(
            finding, overrides or {},
        )
        return score
    except Exception:                                   # noqa: BLE001
        # Fallback for archives missing reconstruction inputs
        # (older fixtures, tests that skip the full block).
        raw = finding.get("raptor_risk_estimate")
        if isinstance(raw, (int, float)):
            return float(raw)
        return None


def _compute_with_overrides(
    finding: Dict[str, Any], overrides: Dict[str, float],
) -> Tuple[float, Dict[str, Any]]:
    """Rebuild a :class:`VulnFinding` from the archived dict and
    call ``compute_risk_estimate(overrides=...)``."""
    from packages.sca.models import (
        Dependency, PinStyle, Reachability, VulnFinding,
    )
    from packages.sca.risk import compute_risk_estimate

    # Dependency reconstruction — the project-sample archive
    # writes a ``dependency`` sub-dict mirroring the dataclass
    # fields. Use frugal defaults for any field the archive
    # omitted (Path / Confidence are required positional args).
    dep_dict = finding.get("dependency") or {}
    pc_raw = dep_dict.get("parser_confidence") or {"level": "high",
                                                     "reason": ""}
    parser_conf = _confidence_from_dict(pc_raw)
    pin_raw = dep_dict.get("pin_style", "exact")
    try:
        pin_style = PinStyle(pin_raw)
    except ValueError:
        pin_style = PinStyle.EXACT
    dep = Dependency(
        ecosystem=dep_dict.get("ecosystem", "PyPI"),
        name=dep_dict.get("name", "unknown"),
        version=dep_dict.get("version"),
        declared_in=Path(dep_dict.get("declared_in", "/unknown")),
        scope=dep_dict.get("scope", "main"),
        is_lockfile=bool(dep_dict.get("is_lockfile", False)),
        pin_style=pin_style,
        direct=bool(dep_dict.get("direct", True)),
        purl=dep_dict.get("purl", ""),
        parser_confidence=parser_conf,
    )

    reach_dict = finding.get("reachability") or {}
    reach = Reachability(
        verdict=reach_dict.get("verdict", "imported"),
        confidence=_confidence_from_dict(
            reach_dict.get("confidence")
            or {"level": "high", "reason": ""},
        ),
        evidence=list(reach_dict.get("evidence") or []),
    )

    vmc = _confidence_from_dict(
        finding.get("version_match_confidence")
        or {"level": "high", "reason": ""},
    )

    # ExploitEvidence reconstruction. Without this, refit can't
    # exercise the EDB / MSF / GitHub-PoC weight branch — every
    # archived finding would re-score as ``has_evidence=False`` and
    # the new ``_EXPLOIT_EVIDENCE_*`` constants would have no effect
    # on the grid search. The archive carries the rendered shape
    # ({"kev_listed": .., "edb_ids": [...], ...}); we accept None
    # (older archives written before the field was preserved) as
    # an empty-evidence shim.
    from packages.sca.models import ExploitEvidence
    ee_raw = finding.get("exploit_evidence") or {}
    if isinstance(ee_raw, dict):
        ee = ExploitEvidence(
            kev_listed=bool(ee_raw.get("kev_listed", False)),
            edb_ids=list(ee_raw.get("edb_ids") or []),
            msf_modules=list(ee_raw.get("msf_modules") or []),
            github_poc_urls=list(ee_raw.get("github_poc_urls") or []),
        )
    else:
        ee = None

    # CISA Vulnrichment SSVC ``Exploitation`` field — same shape as
    # the runtime ``VulnFinding.ssvc_exploitation`` (``"active"`` /
    # ``"poc"`` / ``"none"`` / ``None``). Pre-fix this field was
    # dropped during rebuild, so refit's grid search couldn't see
    # the SSVC-active / SSVC-poc multiplier branches — every
    # rescored finding had ``ssvc_exploitation=None`` regardless
    # of what the archive recorded.
    ssvc = finding.get("ssvc_exploitation")
    if ssvc not in ("active", "poc", "none"):
        ssvc = None
    # SSVC Automatable. Paired with Exploitation — refit needs
    # both so the ``_SSVC_AUTOMATABLE_BONUS`` branch in
    # ``compute_risk_estimate`` fires correctly.
    ssvc_auto = finding.get("ssvc_automatable")
    if ssvc_auto not in ("yes", "no"):
        ssvc_auto = None

    vf = VulnFinding(
        finding_id=finding.get("finding_id", "?"),
        dependency=dep,
        advisories=[],          # not needed for risk computation
        in_kev=bool(finding.get("in_kev", False)),
        epss=finding.get("epss"),
        fixed_version=finding.get("fixed_version"),
        reachability=reach,
        version_match_confidence=vmc,
        cvss_score=finding.get("cvss_score"),
        cvss_vector=finding.get("cvss_vector"),
        severity=finding.get("severity", "low"),
        exposure_factor=float(finding.get("exposure_factor", 0.0)),
        transitive_depth=int(finding.get("transitive_depth", 0)),
        exploit_evidence=ee,
        ssvc_exploitation=ssvc,
        ssvc_automatable=ssvc_auto,
    )
    return compute_risk_estimate(vf, dep, overrides=overrides)


def _confidence_from_dict(raw: Dict[str, Any]) -> "Any":
    """Build a Confidence from a dict, defensive against shape
    drift."""
    from packages.sca.models import Confidence
    level = raw.get("level", "high")
    if level not in ("low", "medium", "high"):
        level = "high"
    reason = raw.get("reason") or ""
    numeric = raw.get("numeric")
    if isinstance(numeric, (int, float)):
        return Confidence(level=level, reason=reason, numeric=float(numeric))
    return Confidence(level=level, reason=reason)


__all__ = [
    "ConstantRefit",
    "DEFAULT_IMPROVEMENT_THRESHOLD",
    "DEFAULT_MAX_DELTA",
    "MIN_SAMPLES_FOR_REFIT",
    "RefitReport",
    "grid_search_refit",
]

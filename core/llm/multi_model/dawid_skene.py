"""Dawid–Skene calibrated multi-model aggregation — Phase 2b.

Replaces the vote-based consensus at ``consensus.py:131`` with an EM
estimator that treats the true label as latent and jointly infers (a)
the per-finding posterior P(truly exploitable), and (b) each model's
per-class confusion matrix ``(α_m, β_m) = (P(say-pos | truly-pos),
P(say-neg | truly-neg))``.

Why this is structurally different from vote:

* Vote: a historically-unreliable model casts the same weight as a
  reliable one; the scorecard's reliability data is unused at
  decision time.
* D–S: model reliability is estimated *jointly* with the latent label
  using only the panel observations themselves — no need to bootstrap
  from a possibly-circular ground-truth signal.

Implementation notes (verified against Dawid & Skene, 1979 §3):

* Binary verdict task (``is_exploitable`` ∈ {true, false}). Multi-class
  D–S generalises straightforwardly; we don't need it here.
* Class prior ``π = P(truly exploitable)`` is *held fixed* at the
  prior mean. Re-estimating π jointly with confusion matrices invites
  label-swap pathology — both parameter sets can flip together and EM
  has no way to prefer one. Fixing π breaks the symmetry; the prior
  from Phase 1b is the natural source.
* M-step uses the *posterior mean* of Beta(α, β) for parameter
  updates, not the MAP. The MAP form ``(α−1)/(α+β−2)`` is undefined
  / non-positive for ``α < 1`` (Jeffreys / sparse-prior regimes); the
  posterior mean ``α/(α+β)`` is always in (0, 1) for positive priors.
* E-step is computed in log-space with float clipping to ``[ε, 1−ε]``
  so a confidently-wrong model that pins ``α_m`` to a boundary does
  not collapse the likelihood.
* Credible interval: variational Beta approximation —
  ``Beta(n·p_i + prior.alpha, n·(1−p_i) + prior.beta).credible_interval()``
  where ``n`` is the number of contributing models. This is the
  textbook approximation when downstream needs a CI on the posterior
  but full uncertainty propagation through the EM Hessian is heavier
  than the use case warrants. Phase 3 may sharpen if needed.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Dict, List, Sequence, Tuple

from core.llm.scorecard.priors import BetaPrior, posterior_update
from core.llm.multi_model.panel_log import PanelRecord


# Default starting reliability — both α_m and β_m initialised here.
# 0.7 is the standard "informative but not confident" starting point
# in the D–S literature; high enough to break label-swap symmetry given
# the fixed class prior, low enough that EM still moves.
DEFAULT_INITIAL_RELIABILITY = 0.7

# Floor / ceiling on confusion-matrix entries to keep log-space E-step
# numerically stable. 1e-6 chosen because log(1e-6) ≈ -13.8 fits
# comfortably in double precision without underflow.
DEFAULT_CLIP_EPSILON = 1e-6


@dataclass(frozen=True)
class ModelReliability:
    """Per-model inferred confusion matrix for one decision class.

    ``alpha`` = sensitivity = P(model says positive | truly positive).
    ``beta``  = specificity = P(model says negative | truly negative).

    A perfectly reliable model has α = β = 1.0. A random-guessing
    model has α + β = 1.0 (whatever its rate of positive prediction).
    An anti-correlated model has α + β < 1.0 — the EM infers this
    correctly, and the posterior weights such a model's verdicts in
    the *opposite* direction in the E-step.
    """
    model: str
    alpha: float
    beta: float


@dataclass(frozen=True)
class FindingPosterior:
    """Estimated posterior on one finding's latent label."""
    finding_id: str
    decision_class: str
    posterior: float  # P(truly exploitable | panel)
    posterior_log_odds: float
    credible_interval: Tuple[float, float]
    n_models: int


@dataclass(frozen=True)
class DawidSkeneResult:
    """Outcome of one EM run over a single decision-class partition."""
    decision_class: str
    findings: List[FindingPosterior]
    model_reliabilities: List[ModelReliability]
    iterations: int
    converged: bool
    class_prior: BetaPrior
    fixed_class_rate: float


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _logit(p: float) -> float:
    """``logit(p) = log(p / (1−p))``. Caller is responsible for
    clipping ``p`` away from the boundaries before invoking."""
    return math.log(p / (1.0 - p))


def _sigmoid(z: float) -> float:
    """Numerically-stable sigmoid for both very-positive and
    very-negative arguments. Standard saturation trick."""
    if z >= 0.0:
        e = math.exp(-z)
        return 1.0 / (1.0 + e)
    e = math.exp(z)
    return e / (1.0 + e)


def _clip(x: float, eps: float) -> float:
    return max(eps, min(1.0 - eps, x))


def _e_step_one_finding(
    verdicts_by_model: Dict[str, bool],
    reliabilities: Dict[str, Tuple[float, float]],
    fixed_class_rate: float,
    eps: float,
) -> float:
    """Compute the posterior P(latent=1 | panel) for one finding.

    Log-space accumulation so that a panel of many strongly-informative
    models doesn't underflow ``L_pos`` or ``L_neg``.
    """
    pi = _clip(fixed_class_rate, eps)
    log_odds = _logit(pi)
    for model, verdict in verdicts_by_model.items():
        alpha_m, beta_m = reliabilities[model]
        alpha_m = _clip(alpha_m, eps)
        beta_m = _clip(beta_m, eps)
        if verdict:
            # log P(say-pos | truly-pos) − log P(say-pos | truly-neg)
            #   = log α_m − log(1 − β_m)
            log_odds += math.log(alpha_m) - math.log(1.0 - beta_m)
        else:
            # log P(say-neg | truly-pos) − log P(say-neg | truly-neg)
            #   = log(1 − α_m) − log β_m
            log_odds += math.log(1.0 - alpha_m) - math.log(beta_m)
    return _sigmoid(log_odds)


def _m_step_one_model(
    model: str,
    posteriors_by_finding: Dict[str, float],
    verdicts_by_finding: Dict[str, Dict[str, bool]],
    prior: BetaPrior,
) -> Tuple[float, float]:
    """Update one model's (α_m, β_m) using all findings where it voted.

    Posterior-mean update under Beta prior:
        α_m = (Σ_i p_i · I[v_{i,m}=1] + prior.alpha)
            / (Σ_i p_i + prior.alpha + prior.beta)

    Symmetric for β_m. Both are in (0, 1) for any positive prior — no
    boundary collapse, no MAP-undefined regime.
    """
    pos_num = 0.0
    pos_den = 0.0
    neg_num = 0.0
    neg_den = 0.0
    for fid, p_i in posteriors_by_finding.items():
        verdicts = verdicts_by_finding[fid]
        if model not in verdicts:
            continue
        verdict = verdicts[model]
        pos_den += p_i
        neg_den += 1.0 - p_i
        if verdict:
            pos_num += p_i
        else:
            neg_num += 1.0 - p_i
    alpha_m = (pos_num + prior.alpha) / (pos_den + prior.strength)
    beta_m = (neg_num + prior.beta) / (neg_den + prior.strength)
    return alpha_m, beta_m


def _credible_interval_for_posterior(
    p_i: float, n_models: int, prior: BetaPrior, level: float = 0.95,
) -> Tuple[float, float]:
    """Variational Beta CI on the latent-label posterior.

    Sources of uncertainty:
    * The point posterior ``p_i`` summarises the panel.
    * The strength of evidence is bounded by the panel size — a 2-model
      consensus is weaker than a 5-model consensus at the same ``p_i``.

    We model this by forming
    ``Beta(n·p_i + α, n·(1−p_i) + β)`` and reporting its credible
    interval. ``n = n_models`` weights the prior and the data
    commensurately. For large ``n`` the CI tightens around ``p_i``; for
    small ``n`` it inherits the prior's diffuseness.
    """
    posterior_dist = posterior_update(
        prior,
        successes=int(round(n_models * p_i)),
        failures=int(round(n_models * (1.0 - p_i))),
    )
    return posterior_dist.credible_interval(level)


# ---------------------------------------------------------------------------
# Estimator
# ---------------------------------------------------------------------------


def estimate(
    records: Sequence[PanelRecord],
    prior: BetaPrior,
    *,
    decision_class: str = "",
    max_iter: int = 50,
    tolerance: float = 1e-4,
    initial_reliability: float = DEFAULT_INITIAL_RELIABILITY,
    clip_eps: float = DEFAULT_CLIP_EPSILON,
    credible_interval_level: float = 0.95,
) -> DawidSkeneResult:
    """Run EM over a single decision-class partition.

    Caller invariant: every record in ``records`` must share the same
    ``decision_class`` (the function does not partition for you). Use
    ``estimate_partitioned`` for cross-class dispatch.

    ``prior`` is the Beta prior over the per-class true-positive rate.
    Its ``mean`` becomes the fixed ``π = P(truly exploitable)`` used in
    every E-step; its (α, β) also serves as the Beta prior on each
    model's reliability parameter, ensuring the M-step stays in (0, 1).

    Returns a ``DawidSkeneResult`` even when EM hits ``max_iter``
    without converging; the ``converged`` flag distinguishes the two
    cases. Downstream consumers (Phase 3 dispatch) check the flag and
    decide whether to fall back to vote.
    """
    if not records:
        return DawidSkeneResult(
            decision_class=decision_class,
            findings=[],
            model_reliabilities=[],
            iterations=0,
            converged=True,
            class_prior=prior,
            fixed_class_rate=prior.mean,
        )

    # ----- 1. Index records by finding and model ------------------------
    verdicts_by_finding: Dict[str, Dict[str, bool]] = {}
    for r in records:
        verdicts_by_finding.setdefault(r.finding_id, {})[r.model] = r.verdict
    finding_ids = list(verdicts_by_finding.keys())
    model_names = sorted({r.model for r in records})

    # ----- 2. Initialise model reliabilities ----------------------------
    reliabilities: Dict[str, Tuple[float, float]] = {
        m: (initial_reliability, initial_reliability)
        for m in model_names
    }
    fixed_class_rate = prior.mean

    # ----- 3. EM loop ---------------------------------------------------
    posteriors: Dict[str, float] = {fid: fixed_class_rate
                                    for fid in finding_ids}
    iterations = 0
    converged = False
    for iteration in range(1, max_iter + 1):
        iterations = iteration

        # E-step: update p_i for each finding.
        new_posteriors: Dict[str, float] = {}
        for fid in finding_ids:
            new_posteriors[fid] = _e_step_one_finding(
                verdicts_by_finding[fid], reliabilities,
                fixed_class_rate, clip_eps,
            )
        posteriors = new_posteriors

        # M-step: update each model's (α_m, β_m).
        new_reliabilities: Dict[str, Tuple[float, float]] = {}
        for model in model_names:
            new_reliabilities[model] = _m_step_one_model(
                model, posteriors, verdicts_by_finding, prior,
            )

        # Convergence: max L∞ change across all confusion-matrix entries.
        delta = 0.0
        for model in model_names:
            old_a, old_b = reliabilities[model]
            new_a, new_b = new_reliabilities[model]
            delta = max(delta, abs(new_a - old_a), abs(new_b - old_b))
        reliabilities = new_reliabilities
        if delta < tolerance:
            converged = True
            break

    # ----- 4. Materialise output ---------------------------------------
    findings: List[FindingPosterior] = []
    for fid in finding_ids:
        p_i = posteriors[fid]
        n_models = len(verdicts_by_finding[fid])
        lo, hi = _credible_interval_for_posterior(
            p_i, n_models, prior, credible_interval_level,
        )
        # Compute log-odds from the clipped posterior so callers
        # downstream don't have to re-clip.
        p_clip = _clip(p_i, clip_eps)
        findings.append(FindingPosterior(
            finding_id=fid,
            decision_class=decision_class,
            posterior=p_i,
            posterior_log_odds=_logit(p_clip),
            credible_interval=(lo, hi),
            n_models=n_models,
        ))
    findings.sort(key=lambda f: f.finding_id)

    model_reliabilities = [
        ModelReliability(model=m, alpha=reliabilities[m][0],
                          beta=reliabilities[m][1])
        for m in model_names
    ]
    return DawidSkeneResult(
        decision_class=decision_class,
        findings=findings,
        model_reliabilities=model_reliabilities,
        iterations=iterations,
        converged=converged,
        class_prior=prior,
        fixed_class_rate=fixed_class_rate,
    )


def estimate_partitioned(
    records: Sequence[PanelRecord],
    priors: Dict[str, BetaPrior],
    *,
    default_prior: BetaPrior,
    **estimate_kwargs,
) -> List[DawidSkeneResult]:
    """Run :func:`estimate` separately for each ``decision_class``.

    ``priors`` keys are decision-class identifiers (``"agentic:<rule>"``
    or whatever the panel-log loader produced). Classes not in
    ``priors`` use ``default_prior`` — typically ``uniform_prior()``
    when no audit-derived rate exists.

    Results returned in sorted decision-class order for deterministic
    downstream serialisation.
    """
    by_class: Dict[str, List[PanelRecord]] = {}
    for r in records:
        by_class.setdefault(r.decision_class, []).append(r)
    out: List[DawidSkeneResult] = []
    for decision_class in sorted(by_class.keys()):
        prior = priors.get(decision_class, default_prior)
        out.append(estimate(
            by_class[decision_class], prior,
            decision_class=decision_class,
            **estimate_kwargs,
        ))
    return out


__all__ = [
    "ModelReliability",
    "FindingPosterior",
    "DawidSkeneResult",
    "estimate",
    "estimate_partitioned",
    "DEFAULT_INITIAL_RELIABILITY",
    "DEFAULT_CLIP_EPSILON",
]

"""Iterative spec refinement loop.

Implements the IRIS paper's core insight: synthesise specs, run the
tool, collect TP/FP feedback, revise specs, repeat.  Two rounds
typically suffice for convergence (matching the paper's results).

The ``tool_runner`` abstraction lets callers plug in Joern, CodeQL,
or both — the refinement loop doesn't know which tool is running.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any
from collections.abc import Callable, Sequence

from core.evidence import EvidenceTier, TIER_RANK, stronger

from .assumptions import BypassFinding, SafetyAssumption
from .specs import CandidateFunction, TaintSpec
from .store import RoundRecord, _spec_key, merge_specs
from .synthesise import synthesise_assumptions, synthesise_specs, synthesise_specs_heuristic

logger = logging.getLogger(__name__)


@dataclass
class RefinementFeedback:
    """Feedback from one round of tool application.

    This dataclass captures what the *tool runner* reported — confirmed
    and refuted specs, plus tool errors.  Bypass findings are tracked
    separately in the refinement loop (they come from the bypass runner,
    not the tool runner).

    ``n_attempts`` / ``n_successes`` count the individual evaluation
    calls the runner made (Joern pair queries, CodeQL query runs, …).
    They exist so "evaluated everything and confirmed nothing" stays
    distinguishable from "could not evaluate anything" — a dead
    transport turns every call into an error and must not read as a
    legitimately empty round.  Runners that don't count calls leave
    both at 0; ``zero_signal`` then falls back to the error surface.
    """

    confirmed_keys: list[str] = field(default_factory=list)
    refuted_keys: list[str] = field(default_factory=list)
    tool_errors: list[str] = field(default_factory=list)
    n_attempts: int = 0
    n_successes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "confirmed_keys": self.confirmed_keys,
            "refuted_keys": self.refuted_keys,
            "tool_errors": self.tool_errors,
        }

    @property
    def n_confirmed(self) -> int:
        return len(self.confirmed_keys)

    @property
    def n_refuted(self) -> int:
        return len(self.refuted_keys)

    @property
    def tp_rate(self) -> float:
        total = self.n_confirmed + self.n_refuted
        if total == 0:
            return 0.0
        return self.n_confirmed / total

    @property
    def zero_signal(self) -> bool:
        """True when the round's evaluation produced no signal at all.

        A round carries signal when it confirmed or refuted anything,
        or when at least one evaluation call succeeded (a successful
        call that found no flow is a real "no true positive" verdict).
        Without explicit call counts, errors with zero verdicts mean
        nothing was evaluated.
        """
        if self.confirmed_keys or self.refuted_keys:
            return False
        if self.n_attempts > 0:
            return self.n_successes == 0
        return bool(self.tool_errors)


ToolRunner = Callable[[list[TaintSpec]], RefinementFeedback]
BypassRunner = Callable[[list[SafetyAssumption]], list[BypassFinding]]


def refine_loop(
    candidates: list[CandidateFunction],
    llm_client: Any,
    tool_runner: ToolRunner | None = None,
    *,
    prior_specs: Sequence[TaintSpec] = (),
    prior_assumptions: Sequence[SafetyAssumption] = (),
    bypass_runner: BypassRunner | None = None,
    target_path=None,
    max_rounds: int = 2,
    convergence_threshold: float = 0.9,
    scorecard: Any = None,
    model: str = "",
    model_version: str | None = None,
) -> tuple[list[TaintSpec], list[RoundRecord], list[SafetyAssumption], list[BypassFinding]]:
    """Run iterative spec refinement.

    Parameters
    ----------
    candidates:
        Functions to classify.
    llm_client:
        LLM client for synthesis (``None`` → heuristic only).
    tool_runner:
        ``(specs) -> RefinementFeedback``.  Compiles specs to
        Joern/CodeQL config, runs the tool, classifies results.
        When ``None``, synthesis runs but no iterative refinement
        occurs (graceful degradation when no tool is available).
    prior_specs:
        Specs from persistent store to merge with.
    prior_assumptions:
        Assumptions from persistent store to merge with.
    bypass_runner:
        ``(assumptions) -> [BypassFinding]``.  Runs the
        ``CompositionalAnalyzer`` over the project call graph.
        When ``None``, no bypass detection occurs.
    target_path:
        Root of the target codebase for reading source files.
    max_rounds:
        Maximum refinement rounds (0 = synthesis only, no tool run).
    convergence_threshold:
        Stop when TP/(TP+FP) >= this value.
    scorecard:
        ``ModelScorecard`` instance for recording per-spec outcomes.
        ``None`` disables scorecard recording (best-effort).
    model:
        Model identifier for scorecard attribution.
    model_version:
        Optional model version string for scorecard.

    Returns
    -------
    ``(final_specs, history, assumptions, bypass_findings)`` — the
    refined spec list, per-round records, final assumption set, and
    all bypass findings accumulated across rounds.  The caller is
    responsible for persisting specs and assumptions to the store
    via ``save_specs(..., assumptions=assumptions)``.
    """
    from core.audit.safety_contract import assert_boost_only
    assert_boost_only("bypass_loop")

    max_rounds = max(max_rounds, 0)

    specs = _initial_synthesis(
        candidates, llm_client, prior_specs=prior_specs,
        target_path=target_path,
    )

    if not specs:
        return list(prior_specs), [], list(prior_assumptions), []

    specs = merge_specs(list(prior_specs), specs)

    assumptions: list[SafetyAssumption] = list(prior_assumptions)
    all_bypass_findings: list[BypassFinding] = []

    if llm_client is not None:
        try:
            new_assumptions = synthesise_assumptions(
                specs, llm_client, target_path=target_path,
            )
            if new_assumptions:
                from .assumptions import merge_assumptions
                assumptions = merge_assumptions(assumptions, new_assumptions)
        except Exception as exc:
            _reraise_auth_abort(exc)
            logger.debug(
                "iris.refine: assumption synthesis failed",
                exc_info=True,
            )

    if bypass_runner is not None and assumptions:
        try:
            bp = bypass_runner(assumptions)
            all_bypass_findings.extend(bp)
        except Exception:
            logger.debug(
                "iris.refine: bypass runner failed", exc_info=True,
            )

    if tool_runner is None:
        logger.info(
            "iris.refine: no tool runner available — returning %d "
            "synthesis-only specs (no iterative refinement)",
            len(specs),
        )
        return specs, [], assumptions, all_bypass_findings

    history: list[RoundRecord] = []
    feedback: RefinementFeedback | None = None
    prev_keys: frozenset | None = None

    for round_num in range(max_rounds):
        feedback = _run_tool(tool_runner, specs, round_num)

        record = RoundRecord(
            round=round_num,
            n_specs=len(specs),
            n_confirmed=feedback.n_confirmed,
            n_refuted=feedback.n_refuted,
            n_errors=len(feedback.tool_errors),
            n_bypass=len(all_bypass_findings),
            # Key lists ride the round record so the store's merge
            # step can drop refuted specs instead of resurrecting
            # them from the add/upgrade-only merge next run.
            confirmed_keys=list(feedback.confirmed_keys),
            refuted_keys=list(feedback.refuted_keys),
            # A zero-signal round (nothing evaluated) is recorded as
            # aborted so the store's persist gate can refuse to
            # overwrite the shared spec store with a no-evidence run.
            aborted=feedback.zero_signal,
        )
        history.append(record)

        if scorecard is not None and model:
            try:
                from .scorecard_bridge import record_refinement_outcomes
                record_refinement_outcomes(
                    scorecard, specs,
                    feedback.confirmed_keys, feedback.refuted_keys,
                    model=model, round_num=round_num,
                    model_version=model_version,
                )
            except Exception:
                logger.debug(
                    "iris.refine: scorecard recording failed",
                    exc_info=True,
                )

        specs = _promote_confirmed(specs, feedback)
        specs = _demote_refuted(specs, feedback)

        logger.info(
            "iris.refine: round %d — %d specs, %d confirmed, %d refuted, "
            "TP rate %.1f%%",
            round_num, len(specs), feedback.n_confirmed,
            feedback.n_refuted, feedback.tp_rate * 100,
        )

        if feedback.zero_signal:
            # Nothing was evaluated this round — there is no signal to
            # converge on, so the round earns neither convergence nor
            # fixpoint credit.  When the runner counted its calls and
            # ALL of them failed the transport is dead: continuing
            # would only re-synthesise against the same dead transport,
            # so abort the loop loudly.  An uncounted single crash
            # (``tool_runner_crashed``) keeps its retry-next-round
            # semantics — a transient tool crash may recover.
            cause = "; ".join(feedback.tool_errors[:3]) or "no error detail"
            if feedback.n_attempts > 0:
                logger.warning(
                    "iris.refine: round %d — all %d evaluation call(s) "
                    "failed (%s) — refinement aborted, store unchanged",
                    round_num, feedback.n_attempts, cause,
                )
                break
            logger.warning(
                "iris.refine: round %d evaluated nothing (%s) — "
                "no fixpoint credit for this round",
                round_num, cause,
            )
        else:
            if feedback.tp_rate >= convergence_threshold and not feedback.tool_errors:
                logger.info(
                    "iris.refine: converged at round %d (TP rate %.1f%% >= %.1f%%)",
                    round_num, feedback.tp_rate * 100,
                    convergence_threshold * 100,
                )
                break

            current_keys = frozenset(_spec_key(s) for s in specs)
            if prev_keys is not None and current_keys == prev_keys:
                logger.info("iris.refine: fixpoint at round %d", round_num)
                break
            prev_keys = current_keys

        if round_num < max_rounds - 1 and llm_client is not None:
            fb_dict = feedback.to_dict()
            if all_bypass_findings:
                fb_dict["bypass_count"] = len(all_bypass_findings)
                fb_dict["bypass_intermediates"] = sorted({
                    bf.via_intermediate
                    for bf in all_bypass_findings
                    if bf.via_intermediate
                })
            try:
                from .scorecard_bridge import cwe_quality_summary
                outcomes = _build_outcomes(specs, feedback)
                cwe_q = cwe_quality_summary(outcomes)
                gaps = [
                    cwe for cwe, data in cwe_q.items()
                    if data.get("coverage") == "gap"
                ]
                if gaps:
                    fb_dict["cwe_gaps"] = gaps
            except Exception:
                # Best-effort prompt enrichment: the feedback dict is
                # complete without cwe_gaps, and the quality summary
                # runs over arbitrary spec/outcome data — any failure
                # here must not abort the refinement round.
                logger.debug(
                    "iris.refine: cwe-quality feedback enrichment "
                    "failed", exc_info=True,
                )

            expanded = _inject_bypass_candidates(
                candidates, all_bypass_findings,
            )
            try:
                revised = synthesise_specs(
                    expanded, llm_client,
                    prior_specs=specs,
                    feedback=fb_dict,
                    target_path=target_path,
                )
            except Exception as exc:
                _reraise_auth_abort(exc)
                logger.debug("Re-synthesis failed, keeping existing specs", exc_info=True)
                revised = []
            if revised:
                specs = merge_specs(specs, revised)

            try:
                new_assumptions = synthesise_assumptions(
                    specs, llm_client,
                    target_path=target_path,
                    bypass_findings=all_bypass_findings,
                )
                if new_assumptions:
                    from .assumptions import merge_assumptions
                    assumptions = merge_assumptions(
                        assumptions, new_assumptions,
                    )
            except Exception as exc:
                _reraise_auth_abort(exc)
                logger.debug(
                    "iris.refine: assumption re-synthesis failed",
                    exc_info=True,
                )

            if bypass_runner is not None and assumptions:
                try:
                    bp = bypass_runner(assumptions)
                    new_count = len(bp) - len(all_bypass_findings)
                    all_bypass_findings = bp
                    if new_count > 0:
                        logger.info(
                            "iris.refine: round %d bypass detection "
                            "found %d new findings",
                            round_num, new_count,
                        )
                except Exception:
                    logger.debug(
                        "iris.refine: bypass runner failed at round %d",
                        round_num, exc_info=True,
                    )

    return specs, history, assumptions, all_bypass_findings


def _inject_bypass_candidates(
    candidates: list[CandidateFunction],
    bypass_findings: list[BypassFinding],
) -> list[CandidateFunction]:
    """Expand candidates with intermediate functions from bypass findings."""
    if not bypass_findings:
        return candidates

    existing = {(c.function, c.file) for c in candidates}
    new_candidates = list(candidates)

    for bf in bypass_findings:
        if not bf.via_intermediate:
            continue
        key = (bf.via_intermediate, bf.caller_file)
        if key not in existing:
            existing.add(key)
            new_candidates.append(CandidateFunction(
                function=bf.via_intermediate,
                file=bf.caller_file,
                reason=f"bypass intermediate for {bf.assumption.target}",
            ))

    return new_candidates


def _reraise_auth_abort(exc: Exception) -> None:
    """Re-raise phase-abort auth errors through the refine loop's
    degrade-to-heuristic exception handling.

    Every synthesis leg here degrades on failure by design (transient
    LLM errors must not kill refinement) — but a persistent
    auth-layer refusal is fail-closed by contract: the phase must
    abort loudly, never zero-fill, so the typed abort punches through
    to the orchestrator's run-state recording.
    """
    from core.llm.client import LLMAuthPersistentError

    if isinstance(exc, LLMAuthPersistentError):
        raise exc


def _initial_synthesis(
    candidates: list[CandidateFunction],
    llm_client: Any,
    *,
    prior_specs: Sequence[TaintSpec],
    target_path,
) -> list[TaintSpec]:
    """Round 0: first synthesis pass."""
    if llm_client is not None:
        try:
            return synthesise_specs(
                candidates, llm_client,
                prior_specs=prior_specs,
                target_path=target_path,
            )
        except Exception as exc:
            _reraise_auth_abort(exc)
            logger.debug(
                "iris.refine: LLM synthesis failed, falling back to heuristic",
                exc_info=True,
            )
    return synthesise_specs_heuristic(candidates)


def _run_tool(
    tool_runner: ToolRunner,
    specs: list[TaintSpec],
    round_num: int,
) -> RefinementFeedback:
    """Run the tool and collect feedback."""
    try:
        return tool_runner(specs)
    except Exception:
        logger.warning(
            "iris.refine: tool runner failed at round %d",
            round_num, exc_info=True,
        )
        return RefinementFeedback(tool_errors=["tool_runner_crashed"])


def _promote_confirmed(
    specs: list[TaintSpec],
    feedback: RefinementFeedback,
) -> list[TaintSpec]:
    """Promote confirmed specs from HEURISTIC to XREF_BACKED."""
    confirmed = set(feedback.confirmed_keys)
    if not confirmed:
        return specs
    result = []
    for spec in specs:
        key = _spec_key(spec)
        if key in confirmed:
            spec.evidence_tier = stronger(
                spec.evidence_tier, EvidenceTier.XREF_BACKED,
            )
        result.append(spec)
    return result


def _demote_refuted(
    specs: list[TaintSpec],
    feedback: RefinementFeedback,
) -> list[TaintSpec]:
    """Remove specs that produced only false positives.

    Specs with evidence_tier >= XREF_BACKED are kept (previously
    confirmed by a tool — a single FP round doesn't invalidate them).
    """
    refuted = set(feedback.refuted_keys)
    if not refuted:
        return specs
    result = []
    for spec in specs:
        key = _spec_key(spec)
        if key in refuted:
            if TIER_RANK.get(spec.evidence_tier, 0) >= TIER_RANK[EvidenceTier.XREF_BACKED]:
                result.append(spec)
            else:
                logger.debug("iris.refine: demoted %s", key)
        else:
            result.append(spec)
    return result


def _build_outcomes(
    specs: list[TaintSpec],
    feedback: RefinementFeedback,
) -> list:
    """Build SpecOutcome objects for CWE quality computation."""
    from .scorecard_bridge import SpecOutcome

    confirmed_set = set(feedback.confirmed_keys)
    refuted_set = set(feedback.refuted_keys)
    outcomes = []
    for spec in specs:
        key = _spec_key(spec)
        if key in confirmed_set:
            is_confirmed: bool | None = True
        elif key in refuted_set:
            is_confirmed = False
        else:
            continue
        outcomes.append(SpecOutcome(
            function=spec.function,
            file=spec.file,
            role=spec.role,
            model="",
            round=0,
            confirmed=is_confirmed,
            taint_classes=list(spec.taint_classes),
        ))
    return outcomes

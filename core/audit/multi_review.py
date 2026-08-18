"""Multi-model review for /audit — consensus, adversarial, cross-model.

Bridges core.audit into core.llm.multi_model.dispatch. Three patterns:

1. Self-consistency: same model N times, majority vote on status.
2. Cross-model: different models review same function, merge verdicts.
3. Adversarial: after finding/suspicious, a ConditionalReviewer tries
   to refute the hypothesis.

All three go through run_multi_model() with an AuditVerdictAdapter
that merges per-function review results.

Reuse contract: The adapter, reviewer, and task factory are independent
of skill-vs-orchestrator execution. Both the CLI multi-review subcommand
and the future Python orchestrator call run_audit_multi_review().
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from core.llm.multi_model.adapters import BaseVerdictAdapter
from core.llm.multi_model.dispatch import run_multi_model
from core.llm.multi_model.types import (
    CostGate,
    ModelHandle,
    MultiModelResult,
)

logger = logging.getLogger(__name__)

# Status → normalized verdict for the multi-model substrate
_STATUS_TO_VERDICT = {
    "finding": "positive",
    "suspicious": "positive",
    "clean": "negative",
    "error": "unknown",
    "dormant": "inconclusive",
}


@dataclass(frozen=True)
class AuditModelHandle:
    """Wraps a model name to satisfy ModelHandle protocol."""
    model_name: str
    real_model: str = ""

    @property
    def effective_model(self) -> str:
        return self.real_model or self.model_name


class AuditVerdictAdapter(BaseVerdictAdapter):
    """Audit's verdict adapter on the shared BaseVerdictAdapter.

    Each model produces a list of single-item results:
        [{file, function, status, hypothesis, evidence, body}]

    The substrate base provides merge() and correlate() (with the
    distinct-model gate the hand-rolled copy lacked: one model
    answering twice no longer masquerades as a multi-model panel).
    Audit keeps only its POLICY pieces:

    - item_id / normalize_verdict (audit's status vocabulary);
    - the calibrated select_primary — per-model per-decision-class
      reliability weights + /validate priors when a scorecard store
      is supplied (see ``core.audit.calibrated_merge``), the legacy
      prefer-positive rule otherwise. Every merged item carries
      ``merge_decision`` telemetry naming which path decided it.
    - extract_analysis_record: audit consumers (reasoning divergence,
      the journal) read full per-model records, not the base's
      truncated summary.

    merge() wraps the base only to (a) skip malformed items instead of
    sinking the panel and (b) annotate ``_model`` for the calibrated
    estimator; the fold itself is inherited.
    """

    def __init__(
        self,
        *,
        scorecard: Any = None,
        priors_by_class: dict[str, Any] | None = None,
    ):
        self._scorecard = scorecard
        self._priors_by_class = priors_by_class

    def item_id(self, item: dict[str, Any]) -> str:
        file = item.get("file", "")
        function = item.get("function", "")
        if not file or not function:
            raise ValueError(f"item missing file/function: {item}")
        return f"{file}:{function}"

    def normalize_verdict(self, item: dict[str, Any]) -> str:
        status = item.get("status", "")
        return _STATUS_TO_VERDICT.get(status, "unknown")

    def select_primary(
        self, model_results: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Pick the panel's primary verdict.

        Calibrated path first (when a scorecard store is wired and the
        panel carries enough signal); legacy prefer-positive rule
        otherwise: keep finding > suspicious > clean, and with 3+
        responsive models a single dissenting "finding" against
        majority "clean" is downgraded to "suspicious".

        Error results never vote: they are excluded from both the
        calibrated posterior and the lone-dissent denominator (one
        finding plus two content-filter errors is not a dissent — no
        model disagreed).
        """
        live = [r for r in model_results if r.get("status") != "error"]
        pool = live or model_results

        if self._scorecard is not None and len(live) >= 2:
            try:
                from core.audit.calibrated_merge import calibrated_decision
                decision = calibrated_decision(
                    live,
                    scorecard=self._scorecard,
                    priors_by_class=self._priors_by_class,
                )
            except Exception:
                logger.debug("calibrated merge failed — falling back "
                             "to prefer-positive", exc_info=True)
                decision = None
            if decision is not None:
                primary = decision.primary
                primary["merge_decision"] = decision.telemetry
                return primary

        priority = {"finding": 0, "suspicious": 1, "dormant": 2,
                    "clean": 3, "error": 4}
        best = min(
            pool,
            key=lambda r: priority.get(r.get("status", ""), 99),
        )
        if (
            len(live) >= 3
            and best.get("status") == "finding"
        ):
            finding_count = sum(
                1 for r in live if r.get("status") == "finding"
            )
            if finding_count == 1:
                best = {**best, "status": "suspicious"}
        best = {**best}
        best["merge_decision"] = {
            "method": "prefer_positive",
            "fallback_reason": (
                "no_scorecard" if self._scorecard is None
                else "cold_start_or_tie"
            ),
        }
        return best

    def extract_analysis_record(
        self, result: dict[str, Any], model_name: str,
    ) -> dict[str, Any]:
        """Full per-model record (audit consumers read ``body``,
        ``hypothesis``, ``evidence_tool`` — not just the base's
        truncated verdict summary)."""
        record = {
            "model": model_name,
            **{k: v for k, v in result.items() if k != "_model"},
        }
        # The base correlate reads the normalized ``verdict`` and
        # surfaces minority reasoning via the ``reasoning`` key; audit
        # review results carry ``status`` and ``body`` instead — add
        # both aliases so agreement/insight extraction works.
        record.setdefault("verdict", self.normalize_verdict(result))
        record.setdefault("reasoning", result.get("body", ""))
        return record

    def merge(
        self, per_model_results: dict[str, list[dict[str, Any]]],
    ) -> list[dict[str, Any]]:
        """Inherited fold with audit pre/post-processing.

        Pre: drop malformed items (missing file/function) instead of
        crashing the panel, and annotate ``_model`` so the calibrated
        estimator can look up per-model reliability inside
        select_primary. Post: strip the annotation from the primary.
        """
        cleaned: dict[str, list[dict[str, Any]]] = {}
        for model_name, results in per_model_results.items():
            keep = []
            for item in results:
                try:
                    self.item_id(item)
                except (ValueError, KeyError):
                    continue
                keep.append({**item, "_model": model_name})
            cleaned[model_name] = keep
        merged = super().merge(cleaned)
        for item in merged:
            item.pop("_model", None)
        return merged


class AdversarialReviewer:
    """ConditionalReviewer that challenges positive verdicts.

    Only fires on items classified as 'disputed' or status=finding/suspicious.
    The review function is supplied by the consumer (it makes an LLM call
    asking the model to REFUTE the hypothesis).

    Reuse: both the CLI multi-review and the orchestrator supply their own
    refute_fn — this class handles the gating and item-filtering logic.
    """

    name: str = "audit_adversarial"
    cutoff_ratio: float = 0.85

    def __init__(
        self,
        refute_fn: Callable[[dict[str, Any]], dict[str, Any]],
        *,
        cutoff_ratio: float = 0.85,
    ):
        self._refute_fn = refute_fn
        self.cutoff_ratio = cutoff_ratio

    def should_review(self, item: dict[str, Any]) -> bool:
        status = item.get("status", "")
        return status in ("finding", "suspicious")

    def review(
        self, merged_items: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Run refutation on each item. Annotate with adversarial_review."""
        results = []
        for item in merged_items:
            if not self.should_review(item):
                results.append(item)
                continue
            try:
                refutation = self._refute_fn(item)
            except Exception as exc:  # noqa: BLE001 — one failed refutation must not sink the panel
                logger.warning(
                    "adversarial review failed for %s:%s: %s",
                    item.get("file"), item.get("function"), exc,
                )
                refutation = {"refuted": False, "reason": f"error: {exc}"}

            annotated = {**item, "adversarial_review": refutation}
            if refutation.get("needs_evidence"):
                # Route to dark verification: the refuter says the
                # question cannot be settled by reading — the dark
                # pass executes a concrete witness later.
                annotated["adversarial_needs_evidence"] = True
            if refutation.get("refuted"):
                # An LLM refutation may not erase tool-confirmed
                # evidence: with mechanical evidence present, downgrade
                # one level to suspicious (queued for re-review /
                # validate) instead of clean.
                from core.audit.evidence_grade import is_tool_evidence
                if is_tool_evidence(item.get("evidence_tool", "")):
                    annotated["status"] = "suspicious"
                else:
                    annotated["status"] = "clean"
                annotated["adversarial_downgrade"] = True
            results.append(annotated)
        return results


def build_task_factory(
    context_fn: Callable[[str, str], dict[str, Any]],
    review_fn: Callable[[dict[str, Any], str], dict[str, Any]],
    file_path: str,
    function_name: str,
) -> Callable[[ModelHandle], list[dict[str, Any]]]:
    """Build a task closure for run_multi_model.

    Args:
        context_fn: (file, function) -> context dict. Thread-safe read.
        review_fn: (context, model_name) -> review result dict. Makes LLM call.
        file_path: File being reviewed.
        function_name: Function being reviewed.

    Returns:
        A task function suitable for run_multi_model's first arg.
    """
    context = context_fn(file_path, function_name)

    def task(model: ModelHandle) -> list[dict[str, Any]]:
        effective = getattr(model, "effective_model", model.model_name)
        result = review_fn(context, effective)
        merged = {"file": file_path, "function": function_name}
        merged.update(result)
        return [merged]

    return task


def run_audit_multi_review(
    *,
    file_path: str,
    function_name: str,
    models: list[str],
    context_fn: Callable[[str, str], dict[str, Any]],
    review_fn: Callable[[dict[str, Any], str], dict[str, Any]],
    refute_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    cost_gate: CostGate | None = None,
    max_parallel: int = 3,
    scorecard: Any = None,
    priors_by_class: dict[str, Any] | None = None,
) -> MultiModelResult:
    """Run multi-model review for a single function.

    This is the primary entry point for both the CLI subcommand and the
    future orchestrator. It wires the audit-specific adapter and optional
    adversarial reviewer into run_multi_model().

    Args:
        file_path: Relative path to the source file.
        function_name: Name of the function to review.
        models: List of model names to dispatch to.
        context_fn: Returns context dict for (file, function). Called once.
        review_fn: (context, model_name) -> review result. Called N times.
        refute_fn: If provided, adversarial reviewer is enabled.
        cost_gate: Optional cost gate.
        max_parallel: Max concurrent model calls.
        scorecard: Optional ModelScorecard store — enables the
            calibrated merge decision (reliability-weighted posterior
            instead of prefer-positive).
        priors_by_class: Optional per-decision-class Beta priors for
            the calibrated merge (typically from /validate ground
            truth via ``calibrated_merge.priors_from_journal``).

    Returns:
        MultiModelResult with merged items, correlation, and optional
        adversarial annotations.
    """
    if not models:
        raise ValueError("models list must not be empty")
    handles = [AuditModelHandle(model_name=m) for m in models]
    adapter = AuditVerdictAdapter(
        scorecard=scorecard, priors_by_class=priors_by_class,
    )
    task = build_task_factory(context_fn, review_fn, file_path, function_name)

    reviewers = []
    if refute_fn is not None:
        reviewers.append(AdversarialReviewer(refute_fn))

    return run_multi_model(
        task=task,
        models=handles,
        adapter=adapter,
        reviewers=reviewers,
        cost_gate=cost_gate,
        max_parallel=max_parallel,
    )


def run_self_consistency(
    *,
    file_path: str,
    function_name: str,
    model: str,
    n_samples: int = 3,
    context_fn: Callable[[str, str], dict[str, Any]],
    review_fn: Callable[[dict[str, Any], str], dict[str, Any]],
    refute_fn: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    cost_gate: CostGate | None = None,
) -> MultiModelResult:
    """Self-consistency: same model N times, majority vote.

    Wang et al. (2022) showed that sampling multiple independent reasoning
    chains and taking the majority verdict outperforms a single chain.
    """
    if n_samples < 2:
        raise ValueError("n_samples must be >= 2 for self-consistency")
    handles = [
        AuditModelHandle(model_name=f"{model}#sc{i}", real_model=model)
        for i in range(n_samples)
    ]
    adapter = AuditVerdictAdapter()
    task = build_task_factory(context_fn, review_fn, file_path, function_name)

    reviewers = []
    if refute_fn is not None:
        reviewers.append(AdversarialReviewer(refute_fn))

    return run_multi_model(
        task=task,
        models=handles,
        adapter=adapter,
        reviewers=reviewers,
        cost_gate=cost_gate,
        max_parallel=n_samples,
    )


def compute_reasoning_divergence(
    result: MultiModelResult,
) -> dict[str, Any] | None:
    """Compute reasoning divergence across multi-model annotations.

    Uses token-set Jaccard distance to detect when models agreed on a
    status but reasoned about different things to get there — the
    "right answer for wrong reason" failure mode.

    Returns None if divergence can't be computed (too few models,
    too short reasoning, or semantic_entropy unavailable).
    """
    if not result.items:
        return None

    item = result.items[0]
    analyses = item.get("multi_model_analyses", [])
    if len(analyses) < 2:
        return None

    reasonings: dict[str, str] = {}
    for idx, analysis in enumerate(analyses):
        model_name = analysis.get("model", f"model-{idx}")
        body = analysis.get("body", analysis.get("reasoning", ""))
        if body:
            reasonings[model_name] = body

    if len(reasonings) < 2:
        return None

    try:
        from core.llm.semantic_entropy import divergence
        return divergence(reasonings, min_models=2)
    except ImportError:
        logger.debug("semantic_entropy not available for divergence")
        return None


def consensus_status(result: MultiModelResult) -> str | None:
    """Extract the consensus status from a multi-review result.

    Returns the final status after merge + adversarial, or None if
    no items were produced.
    """
    if not result.items:
        return None
    return result.items[0].get("status")


def is_disputed(result: MultiModelResult) -> bool:
    """Check whether any item in the result is disputed.

    Reads the base adapter's correlation shape
    (``confidence_signals: {item_id: signal}``).
    """
    if not result.correlation:
        return False
    signals = result.correlation.get("confidence_signals", {})
    return any(v == "disputed" for v in signals.values())

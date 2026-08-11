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
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

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


class AuditVerdictAdapter:
    """ItemAdapter + VerdictAdapter for audit review results.

    Each model produces a list of single-item results:
        [{file, function, status, hypothesis, evidence, body}]

    Merge groups by file:function, picks primary via prefer-positive
    (don't lose findings), attaches all per-model analyses.
    """

    def item_id(self, item: Dict[str, Any]) -> str:
        file = item.get("file", "")
        function = item.get("function", "")
        if not file or not function:
            raise ValueError(f"item missing file/function: {item}")
        return f"{file}:{function}"

    def normalize_verdict(self, item: Dict[str, Any]) -> str:
        status = item.get("status", "")
        return _STATUS_TO_VERDICT.get(status, "unknown")

    def select_primary(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Prefer-positive: keep finding > suspicious > clean.

        With 3+ models, a single dissenting "finding" against majority
        "clean" is downgraded to "suspicious" to reduce false positives
        while still surfacing the disagreement.
        """
        priority = {"finding": 0, "suspicious": 1, "dormant": 2,
                    "clean": 3, "error": 4}
        best = min(
            model_results,
            key=lambda r: priority.get(r.get("status", ""), 99),
        )
        if (
            len(model_results) >= 3
            and best.get("status") == "finding"
        ):
            finding_count = sum(
                1 for r in model_results if r.get("status") == "finding"
            )
            if finding_count == 1:
                best = {**best, "status": "suspicious"}
        return best

    def merge(
        self, per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Merge per-model results into a single list per function."""
        by_id: Dict[str, List[Dict[str, Any]]] = {}
        for model_name, results in per_model_results.items():
            for item in results:
                try:
                    item_id = self.item_id(item)
                except (ValueError, KeyError):
                    continue
                item_with_model = {**item, "_model": model_name}
                by_id.setdefault(item_id, []).append(item_with_model)

        merged = []
        for item_id, variants in by_id.items():
            primary = self.select_primary(variants)
            merged_item = {**primary}
            merged_item.pop("_model", None)
            merged_item["multi_model_analyses"] = [
                {"model": v.pop("_model", "unknown"), **v}
                for v in variants
            ]
            merged.append(merged_item)
        return merged

    def correlate(
        self,
        merged_items: List[Dict[str, Any]],
        per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Compute per-function agreement classification."""
        n_models = len(per_model_results)
        per_item: Dict[str, Dict[str, Any]] = {}

        for item in merged_items:
            item_id = self.item_id(item)
            analyses = item.get("multi_model_analyses", [])
            verdicts = [
                self.normalize_verdict(a) for a in analyses
                if self.normalize_verdict(a) != "unknown"
            ]

            if not verdicts:
                classification = "unknown"
            elif len(set(verdicts)) == 1:
                classification = "unanimous"
            else:
                from collections import Counter
                counts = Counter(verdicts)
                top = counts.most_common(1)[0]
                if top[1] > len(verdicts) / 2:
                    classification = "majority"
                else:
                    classification = "disputed"

            per_item[item_id] = {
                "verdicts": verdicts,
                "classification": classification,
                "n_models": n_models,
                "n_responding": len(analyses),
            }

        n_unanimous = sum(
            1 for v in per_item.values() if v["classification"] == "unanimous"
        )
        n_disputed = sum(
            1 for v in per_item.values() if v["classification"] == "disputed"
        )

        return {
            "per_item": per_item,
            "summary": {
                "total": len(per_item),
                "unanimous": n_unanimous,
                "majority": len(per_item) - n_unanimous - n_disputed,
                "disputed": n_disputed,
            },
        }


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
        refute_fn: Callable[[Dict[str, Any]], Dict[str, Any]],
        *,
        cutoff_ratio: float = 0.85,
    ):
        self._refute_fn = refute_fn
        self.cutoff_ratio = cutoff_ratio

    def should_review(self, item: Dict[str, Any]) -> bool:
        status = item.get("status", "")
        return status in ("finding", "suspicious")

    def review(
        self, merged_items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Run refutation on each item. Annotate with adversarial_review."""
        results = []
        for item in merged_items:
            if not self.should_review(item):
                results.append(item)
                continue
            try:
                refutation = self._refute_fn(item)
            except Exception as exc:
                logger.warning(
                    "adversarial review failed for %s:%s: %s",
                    item.get("file"), item.get("function"), exc,
                )
                refutation = {"refuted": False, "reason": f"error: {exc}"}

            annotated = {**item, "adversarial_review": refutation}
            if refutation.get("refuted"):
                annotated["status"] = "clean"
                annotated["adversarial_downgrade"] = True
            results.append(annotated)
        return results


def build_task_factory(
    context_fn: Callable[[str, str], Dict[str, Any]],
    review_fn: Callable[[Dict[str, Any], str], Dict[str, Any]],
    file_path: str,
    function_name: str,
) -> Callable[[ModelHandle], List[Dict[str, Any]]]:
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

    def task(model: ModelHandle) -> List[Dict[str, Any]]:
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
    models: List[str],
    context_fn: Callable[[str, str], Dict[str, Any]],
    review_fn: Callable[[Dict[str, Any], str], Dict[str, Any]],
    refute_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    cost_gate: Optional[CostGate] = None,
    max_parallel: int = 3,
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

    Returns:
        MultiModelResult with merged items, correlation, and optional
        adversarial annotations.
    """
    if not models:
        raise ValueError("models list must not be empty")
    handles = [AuditModelHandle(model_name=m) for m in models]
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
        max_parallel=max_parallel,
    )


def run_self_consistency(
    *,
    file_path: str,
    function_name: str,
    model: str,
    n_samples: int = 3,
    context_fn: Callable[[str, str], Dict[str, Any]],
    review_fn: Callable[[Dict[str, Any], str], Dict[str, Any]],
    refute_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    cost_gate: Optional[CostGate] = None,
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
) -> Optional[Dict[str, Any]]:
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

    reasonings: Dict[str, str] = {}
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


def consensus_status(result: MultiModelResult) -> Optional[str]:
    """Extract the consensus status from a multi-review result.

    Returns the final status after merge + adversarial, or None if
    no items were produced.
    """
    if not result.items:
        return None
    return result.items[0].get("status")


def is_disputed(result: MultiModelResult) -> bool:
    """Check whether any item in the result is disputed."""
    if not result.correlation:
        return False
    per_item = result.correlation.get("per_item", {})
    return any(
        v.get("classification") == "disputed" for v in per_item.values()
    )

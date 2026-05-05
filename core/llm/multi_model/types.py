"""Protocol/type layer for the multi-model substrate.

These are pure interface definitions — no behaviour. Implementations live
in adapters.py, reviewer.py, aggregator.py.

Contracts in plain English:
  - The substrate calls task(model) once per model, in parallel. The
    consumer's task() callable must be thread-safe — closures that mutate
    shared state across model invocations will race. Cost tracking is
    safe (CostTracker is locked); other shared writes are not.
  - The substrate validates inputs before dispatch: an empty models list
    raises, and duplicate model_name values raise (silent collision in
    per_model_raw would lose data).
  - An "error entry" is any dict with a top-level "error" key. The
    substrate filters error entries out before calling merge() and
    correlate(); adapters never see them. Raw outputs (including errors)
    are still available on MultiModelResult.per_model_raw for debugging.
  - Models whose task() raises, or whose result list contains only error
    entries, are added to MultiModelResult.failed_models. The run still
    completes with the surviving models.
  - Adapters' merge() and correlate() are expected to be pure: deterministic,
    no IO, no randomness. They MUST handle N=1 gracefully (degenerate but
    sensible output, never raise).
  - Reviewers run after merge, in registration order, and return new item
    dicts; substrate replaces by id. Items omitted from a reviewer's return
    keep their prior version (reviewers cannot delete items — deletion is
    a verdict change, not a review).
  - Mutating reviewer-input lists in place is undefined behaviour.
  - Each Reviewer/Aggregator carries cutoff_ratio (fraction of max_cost,
    typically 0.70-0.95). When cost exceeds that ratio at the moment the
    substrate is about to invoke the phase, it skips the phase entirely —
    for ConditionalReviewer this means should_review() is not called.
"""

from dataclasses import dataclass, field
from typing import (
    Any, Callable, Dict, Hashable, List, Optional, Protocol, runtime_checkable,
)


@runtime_checkable
class ModelHandle(Protocol):
    """Anything with a stable model_name string.

    Implemented by core.llm.config.ModelConfig (external LLMs). For
    Claude Code dispatch (no external LLM), consumers can wrap a sentinel
    object exposing model_name="Claude Code". Substrate only ever reads
    model_name; consumer's task() is the one that knows how to dispatch.
    """
    model_name: str


@dataclass
class MultiModelResult:
    """Output of a multi-model run.

    items: merged items. Verdict adapters return one item per id; set
        adapters return the union annotated with `found_by_models`.
    correlation: shape-specific agreement summary from adapter.correlate().
        None only if the adapter explicitly opts out (rare).
    aggregation: aggregator output. Tri-state:
        None  — aggregator did not run (not configured, or skipped because
                cost exceeded its cutoff_ratio — see logs for the reason)
        {}    — aggregator ran but produced no usable output (errored or empty)
        {...} — aggregator succeeded
    per_model_raw: raw outputs keyed by model name (model_name → list of
        whatever task() returned, including any error entries). The shape
        is stable; downstream parsing patterns are not a public contract.
        Distinct from the per_model_results dict passed to merge/correlate,
        which is error-filtered.
    failed_models: model names whose task() raised or returned only errors.
        The run still completes with the survivors; consumers may choose
        to fail loudly if too many failed.
    """
    items: List[Dict[str, Any]] = field(default_factory=list)
    correlation: Optional[Dict[str, Any]] = None
    aggregation: Optional[Dict[str, Any]] = None
    per_model_raw: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    failed_models: List[str] = field(default_factory=list)


@runtime_checkable
class ItemAdapter(Protocol):
    """How a consumer's item shape is identified, merged, and correlated.

    A run of N models produces a dict of model_name → result list. The
    adapter says how to fold that into a single item list and how to
    compute agreement. Implementations MUST handle N=1 gracefully.
    """

    def item_id(self, item: Dict[str, Any]) -> str:
        """Stable, non-empty string ID. Consistent across models.

        Implementations must return a non-empty string. Items without a
        valid id should raise rather than return "" — empty ids would
        collide on merge and produce silent data loss.
        """
        ...

    def merge(
        self, per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> List[Dict[str, Any]]:
        """Fold per-model result lists into a single merged item list.

        Substrate filters out error entries before calling. Implementation
        must be deterministic and side-effect-free. Must handle N=1.
        """
        ...

    def correlate(
        self,
        merged_items: List[Dict[str, Any]],
        per_model_results: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Compute agreement matrix / confidence signals over merged items.

        Returns a shape-specific summary:
            verdict adapter: per-id verdicts + agreement classification
            set adapter:     per-item recall + presence matrix

        With N=1, return a sensible degenerate result (e.g., all items
        marked "single-model"); never raise. Must be pure.
        """
        ...


@runtime_checkable
class VerdictAdapter(ItemAdapter, Protocol):
    """Adapter for tasks where each model returns a verdict per input item.

    Used by /agentic (per-finding analysis) and /understand --trace
    (per-trace reachability). Merge groups by item_id, picks one primary
    via select_primary, attaches multi_model_analyses.
    """

    def normalize_verdict(self, item: Dict[str, Any]) -> str:
        """Return one of: 'positive', 'negative', 'inconclusive', 'unknown'.

        'unknown' items are kept in merge but excluded from agreement
        classification in correlate.
        """
        ...

    def select_primary(
        self, model_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Pick one result as primary when N models all returned for one id.

        Policy is consumer-defined. /agentic uses prefer-positive to avoid
        losing exploitable verdicts; trace may use a different rule.
        """
        ...


@runtime_checkable
class SetAdapter(ItemAdapter, Protocol):
    """Adapter for tasks where each model returns a set of items.

    Used by /understand --hunt (variants), and other "find all instances"
    tasks. Merge unions by item_key, annotates with found_by_models.
    """

    def item_key(self, item: Dict[str, Any]) -> Hashable:
        """Hashable dedup key. Items with equal keys are the same item.

        Implementations should normalize before key generation (e.g.,
        lowercase paths, strip trailing whitespace) to avoid spurious
        duplicates.
        """
        ...


@runtime_checkable
class Reviewer(Protocol):
    """A second-look pass over per-item results.

    Reviewers run after the per-model dispatch and merge, before aggregation.
    Each reviewer reads merged items and returns NEW dicts with annotations
    attached. Substrate replaces items by id. Items omitted from the return
    keep their prior version — reviewers cannot delete items.

    Examples: ConsensusTask (blind vote), JudgeTask (non-blind critique).

    cutoff_ratio: fraction of cost_tracker.max_cost (typically 0.70-0.95).
        If spend exceeds this ratio when the substrate is about to invoke
        the reviewer, the reviewer is skipped — for ConditionalReviewer
        this means should_review() is not called per item. Set to 1.0
        (or higher) to disable the cost gate.
    """

    name: str
    cutoff_ratio: float

    def review(
        self, merged_items: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Return new dicts with reviewer annotations; substrate replaces.

        For ConditionalReviewer, the substrate filters via should_review()
        before calling review() — the reviewer only sees applicable items.
        """
        ...


@runtime_checkable
class ConditionalReviewer(Reviewer, Protocol):
    """A reviewer that only inspects items meeting a condition.

    The substrate enforces the filter: it calls should_review() on each
    item and passes only matching ones to review(). This is what makes
    ConditionalReviewer distinct from Reviewer — should_review is part
    of the substrate contract, not just a hint.

    Used by /agentic's CrossFamilyCheck (only runs on items whose merged
    result looks suspicious — low quality or nonce leaked).
    """

    def should_review(self, item: Dict[str, Any]) -> bool:
        """Return True if this reviewer should process the item."""
        ...


@runtime_checkable
class CostGate(Protocol):
    """Minimal interface the substrate needs to gate on budget.

    The existing CostTracker (packages/llm_analysis/orchestrator.py) is
    expected to grow a public budget_ratio() method as part of PR3
    (/agentic migration). For PR1/PR2, consumers can pass any object
    implementing this protocol, or None to disable cost gating.
    """

    def budget_ratio(self) -> float:
        """Current spend as fraction of budget. 0.0 when no budget set."""
        ...


@runtime_checkable
class Aggregator(Protocol):
    """Optional final LLM synthesis over merged + correlated items.

    Distinct from reviewers: produces a single artefact (summary, top
    findings, recommendations) rather than per-item annotations.

    cutoff_ratio: same semantics as Reviewer — fraction of max_cost
        (typically 0.70-0.95) above which the substrate skips this
        aggregator entirely.
    """

    cutoff_ratio: float

    def aggregate(
        self,
        merged_items: List[Dict[str, Any]],
        correlation: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        """Produce the synthesis dict.

        Return value is stored on MultiModelResult.aggregation:
          dict   — success
          {}     — ran but produced no usable output
          None   — equivalent to {} (substrate normalizes)
        """
        ...


# Type alias for the consumer-supplied per-model task callable.
# Substrate calls this once per model in parallel.
TaskFn = Callable[[ModelHandle], List[Dict[str, Any]]]

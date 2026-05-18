"""Substrate dispatch loop.

run_multi_model() is the only function consumers call. Everything else
in this module is private machinery.

Pipeline:
    1. Validate inputs (non-empty models, no duplicate model_name).
    2. Run task(model) in parallel via ThreadPoolExecutor.
    3. Collect raw outputs; classify model failures.
    4. Filter error entries (dicts with "error" key) before adapter sees them.
    5. adapter.merge() folds per-model results into a single item list.
    6. adapter.correlate() computes agreement signals over the merged list.
    7. Reviewers run in registration order, replacing items by id.
       ConditionalReviewer instances filter via should_review() first.
    8. Aggregator runs once over (merged, correlation), if configured.
    9. Cost gating: each reviewer/aggregator's cutoff_ratio is checked
       against cost_gate.budget_ratio() before invocation.

Cost-gate failure semantics (W36.B / F090):

  - **Transient failure** (``budget_ratio()`` raises an exception):
    gating is *suspended* for ``_GATE_RETRY_SECONDS`` (60s by default)
    then re-probed automatically. Subsequent invocations during the
    cooldown skip the gate (return ``False, None``). Recovery is
    announced via:

        logger.info("cost_gate: retrying budget_ratio() after %.0fs "
                    "transient-failure cooldown", ...)

    Operators monitoring cost-gate health should grep run logs for
    this string to detect cost-gate flapping.

  - **Permanent failure** (``budget_ratio()`` returns a non-numeric
    value — type-contract violation): gating is disabled for the rest
    of the run with a single ``logger.warning`` at the moment of
    disable. A wrong return type is a code bug, not a network
    hiccup, so automatic retry would not help.

  Transient exceptions are recoverable (network glitch, transient DB
  error in a backing CostGate impl); type-contract violations are
  not. The distinction lives at ``over_budget()`` below.
"""

import logging
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, Iterable, List, Optional, Sequence

from core.llm.multi_model.types import (
    Aggregator,
    ConditionalReviewer,
    CostGate,
    ItemAdapter,
    ModelHandle,
    MultiModelResult,
    Reviewer,
    TaskFn,
)

logger = logging.getLogger(__name__)

_GATE_RETRY_SECONDS = 60.0


def run_multi_model(
    task: TaskFn,
    models: Iterable[ModelHandle],
    adapter: ItemAdapter,
    *,
    reviewers: Optional[Iterable[Reviewer]] = (),
    aggregator: Optional[Aggregator] = None,
    cost_gate: Optional[CostGate] = None,
    max_parallel: int = 3,
) -> MultiModelResult:
    """Run a task across N models in parallel and merge results.

    Args:
        task: Callable that takes one model and returns its result list.
            Closure-captured by the consumer; substrate doesn't know what
            "running the task" means. Must be thread-safe.
        models: Non-empty sequence of ModelHandles. Each model_name must
            be unique — duplicates raise.
        adapter: ItemAdapter (typically VerdictAdapter or SetAdapter)
            describing how to merge and correlate the per-model outputs.
        reviewers: Optional ordered sequence of Reviewers run after merge,
            in the order given. ConditionalReviewers are filtered via
            should_review() before review() is called.
        aggregator: Optional final synthesizer. Runs once over (merged,
            correlation) and produces a free-form dict (or None).
        cost_gate: Optional cost tracker. When provided, reviewers and
            the aggregator are skipped if budget_ratio() exceeds their
            cutoff_ratio. None disables cost gating entirely.
        max_parallel: Thread pool size for the per-model dispatch.

    Returns:
        MultiModelResult with merged items, correlation, optional
        aggregation, raw per-model outputs, and any failed model names.

    Raises:
        ValueError: empty models list; duplicate model_name; empty
            model_name on any model; or adapter returned items with
            duplicate item_id.
        TypeError: task is not callable; adapter, any reviewer, the
            aggregator, or cost_gate doesn't implement its protocol;
            any model element doesn't implement ModelHandle; any
            cutoff_ratio is non-numeric; adapter.merge() returned
            non-list, .correlate() returned non-dict, or .item_id()
            returned non-str.

    Exception handling at runtime:
        - adapter.merge() / .correlate() exceptions propagate unchanged
          (adapter bugs should surface).
        - reviewer.review() / .should_review() exceptions are caught,
          logged with traceback, and skipped — the reviewer contributes
          no annotations but the run continues.
        - aggregator.aggregate() exceptions are caught, logged, and
          produce aggregation={} per the documented tri-state.
        - cost_gate.budget_ratio() exceptions are caught once and gating
          is disabled for the rest of the run.
    """
    # Materialize models to list once — defends against generators that
    # would be consumed by validation and leave dispatch with nothing.
    models = list(models)
    reviewers = list(reviewers or ())
    _validate_inputs(task, models, adapter, reviewers, aggregator, cost_gate)

    per_model_raw, failed_models = _dispatch_parallel(task, models, max_parallel)
    # Sort for deterministic adapter input regardless of completion order.
    per_model_raw = dict(sorted(per_model_raw.items()))
    failed_models = sorted(failed_models)
    per_model_filtered = _filter_errors(per_model_raw)

    if failed_models and len(failed_models) == len(models):
        logger.warning(
            f"All {len(models)} model(s) failed: {failed_models}. "
            f"Adapter will receive empty per-model results."
        )

    merged = adapter.merge(per_model_filtered)
    if not isinstance(merged, list):
        raise TypeError(
            f"adapter.merge() must return a list; got "
            f"{type(merged).__name__}. Adapter is buggy."
        )
    _check_unique_ids(merged, adapter)
    correlation = adapter.correlate(merged, per_model_filtered)
    if not isinstance(correlation, dict):
        raise TypeError(
            f"adapter.correlate() must return a dict; got "
            f"{type(correlation).__name__}. Adapter is buggy."
        )

    # Local gate state — never mutate the external cost_gate.
    # Transient exceptions from budget_ratio() suspend gating for
    # _GATE_RETRY_SECONDS, then re-probe automatically (circuit-breaker).
    # Type-contract violations (non-float return) permanently disable
    # gating for the run — a wrong return type is a code bug, not a
    # network hiccup, and recovery would not help.
    _gate_permanent_off = [cost_gate is None]
    _gate_disabled_at: list = [None]  # None or monotonic timestamp of last transient fail

    def over_budget(cutoff_ratio: float) -> tuple[bool, Optional[float]]:
        """Return (skip, current_ratio). ratio is None when gating is off."""
        if _gate_permanent_off[0]:
            return False, None
        if cutoff_ratio >= 1.0:
            return False, None
        if _gate_disabled_at[0] is not None:
            elapsed = time.monotonic() - _gate_disabled_at[0]
            if elapsed < _GATE_RETRY_SECONDS:
                return False, None
            _gate_disabled_at[0] = None
            logger.info(
                "cost_gate: retrying budget_ratio() after %.0fs transient-failure cooldown",
                elapsed,
            )
        try:
            ratio = cost_gate.budget_ratio()  # type: ignore[union-attr]
        except Exception as exc:
            logger.warning(
                f"cost_gate.budget_ratio() raised {type(exc).__name__}: {exc} — "
                f"suspending cost gating for {_GATE_RETRY_SECONDS:.0f}s",
                exc_info=True,
            )
            _gate_disabled_at[0] = time.monotonic()
            return False, None
        # Defensive: protocol says budget_ratio returns float, but
        # @runtime_checkable doesn't enforce return types. A non-numeric
        # value would crash the comparison below with a confusing error.
        # Type-contract violation → permanent disable (not transient).
        if isinstance(ratio, bool) or not isinstance(ratio, (int, float)):
            logger.warning(
                f"cost_gate.budget_ratio() returned {type(ratio).__name__} "
                f"({ratio!r}), expected float — permanently disabling cost "
                f"gating for the rest of this run"
            )
            _gate_permanent_off[0] = True
            return False, None
        return ratio >= cutoff_ratio, ratio

    for reviewer in reviewers:
        skip, spend = over_budget(reviewer.cutoff_ratio)
        if skip:
            logger.info(
                f"Skipping reviewer {reviewer.name!r} — over budget "
                f"(spend={spend:.2f}, cutoff={reviewer.cutoff_ratio:.2f})"
            )
            continue
        merged = _apply_reviewer(merged, reviewer, adapter)

    # aggregation tri-state:
    #   None  — aggregator not configured OR skipped for budget (see logs)
    #   {}    — aggregator ran but produced no usable output (errored or empty)
    #   {...} — aggregator succeeded
    aggregation: Optional[Dict[str, Any]] = None
    if aggregator is not None:
        skip, spend = over_budget(aggregator.cutoff_ratio)
        if skip:
            logger.info(
                f"Skipping aggregator — over budget "
                f"(spend={spend:.2f}, cutoff={aggregator.cutoff_ratio:.2f})"
            )
        else:
            try:
                result = aggregator.aggregate(merged, correlation)
            except Exception as exc:
                logger.warning(
                    f"Aggregator raised {type(exc).__name__}: {exc}",
                    exc_info=True,
                )
                aggregation = {}
            else:
                if result is None:
                    aggregation = {}
                elif not isinstance(result, dict):
                    logger.warning(
                        f"Aggregator returned {type(result).__name__}, expected "
                        f"dict — treating as empty per the documented contract"
                    )
                    aggregation = {}
                else:
                    aggregation = result

    return MultiModelResult(
        items=merged,
        correlation=correlation,
        aggregation=aggregation,
        per_model_raw=per_model_raw,
        failed_models=failed_models,
    )


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _validate_inputs(
    task: TaskFn,
    models: Sequence[ModelHandle],
    adapter: ItemAdapter,
    reviewers: Sequence[Reviewer],
    aggregator: Optional[Aggregator],
    cost_gate: Optional[CostGate],
) -> None:
    if not callable(task):
        raise TypeError(f"task must be callable; got {type(task).__name__}")
    if not isinstance(adapter, ItemAdapter):
        raise TypeError(
            f"adapter must implement ItemAdapter (item_id, merge, correlate); "
            f"got {type(adapter).__name__}"
        )
    if not models:
        raise ValueError("models must be non-empty")
    for i, m in enumerate(models):
        if not hasattr(m, "model_name") or not isinstance(m.model_name, str):
            raise TypeError(
                f"models[{i}] does not implement ModelHandle "
                f"(needs str-typed model_name); got {type(m).__name__}"
            )
        if not m.model_name:
            raise ValueError(f"models[{i}].model_name must be non-empty")
    names = [m.model_name for m in models]
    counts = Counter(names)
    dupes = sorted(name for name, c in counts.items() if c > 1)
    if dupes:
        raise ValueError(f"duplicate model_name(s): {dupes}")
    for i, r in enumerate(reviewers):
        if not isinstance(r, Reviewer):
            raise TypeError(
                f"reviewers[{i}] does not implement Reviewer "
                f"(needs name, cutoff_ratio, review); got {type(r).__name__}"
            )
        _check_cutoff_ratio(r.cutoff_ratio, f"reviewers[{i}].cutoff_ratio")
    if aggregator is not None:
        if not isinstance(aggregator, Aggregator):
            raise TypeError(
                f"aggregator does not implement Aggregator "
                f"(needs cutoff_ratio, aggregate); got {type(aggregator).__name__}"
            )
        _check_cutoff_ratio(aggregator.cutoff_ratio, "aggregator.cutoff_ratio")
    if cost_gate is not None and not isinstance(cost_gate, CostGate):
        raise TypeError(
            f"cost_gate does not implement CostGate "
            f"(needs budget_ratio); got {type(cost_gate).__name__}"
        )


def _check_cutoff_ratio(value: Any, label: str) -> None:
    """Reviewer.cutoff_ratio and Aggregator.cutoff_ratio are documented as
    floats. runtime_checkable Protocol only checks attribute presence, not
    type — so do an explicit numeric check at the boundary."""
    # bool is a subclass of int; exclude it explicitly.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError(
            f"{label} must be int/float; got {type(value).__name__}"
        )


def _check_unique_ids(
    merged: List[Dict[str, Any]], adapter: ItemAdapter,
) -> None:
    """Validate adapter.merge() output: ids must be unique non-empty strings.

    Duplicate ids would silently corrupt reviewer dispatch (later items
    overwrite earlier in the by-id dict). Non-string ids would break
    by-id lookups. Raise to surface the adapter bug at the boundary
    instead of letting it propagate.
    """
    ids: List[str] = []
    for idx, item in enumerate(merged):
        item_id = adapter.item_id(item)
        if not isinstance(item_id, str) or not item_id:
            raise TypeError(
                f"adapter.item_id() returned {type(item_id).__name__!r} "
                f"({item_id!r}) for merged[{idx}]; expected non-empty str"
            )
        ids.append(item_id)
    counts = Counter(ids)
    dupes = sorted(i for i, c in counts.items() if c > 1)
    if dupes:
        raise ValueError(
            f"adapter.merge() returned duplicate item_id(s): {dupes}. "
            f"Adapter is buggy."
        )


def _dispatch_parallel(
    task: TaskFn,
    models: Sequence[ModelHandle],
    max_parallel: int,
) -> tuple[Dict[str, List[Dict[str, Any]]], List[str]]:
    """Run task in parallel across models. Returns (per_model_raw, failed).

    A model is "failed" if task() raised, OR if every entry in its result
    list is an error dict. Empty result lists are NOT failures (the model
    just had nothing to say).
    """
    per_model_raw: Dict[str, List[Dict[str, Any]]] = {}
    failed: List[str] = []

    workers = max(1, min(max_parallel, len(models)))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(task, m): m for m in models}
        for future in as_completed(futures):
            model = futures[future]
            name = model.model_name
            try:
                results = future.result()
            except Exception as exc:
                logger.warning(f"Model {name!r} task raised: {exc}", exc_info=True)
                per_model_raw[name] = []
                failed.append(name)
                continue

            if not isinstance(results, list):
                logger.warning(
                    f"Model {name!r} task returned {type(results).__name__}, "
                    f"expected list — treating as failure"
                )
                per_model_raw[name] = []
                failed.append(name)
                continue

            non_dict = [type(r).__name__ for r in results if not isinstance(r, dict)]
            if non_dict:
                logger.warning(
                    f"Model {name!r} task returned non-dict items "
                    f"({non_dict[:3]}{'...' if len(non_dict) > 3 else ''}) — "
                    f"treating as failure. Item contract is List[Dict[str, Any]]."
                )
                per_model_raw[name] = []
                failed.append(name)
                continue

            per_model_raw[name] = results
            if results and all(_is_error(r) for r in results):
                failed.append(name)

    return per_model_raw, failed


def _filter_errors(
    per_model_raw: Dict[str, List[Dict[str, Any]]],
) -> Dict[str, List[Dict[str, Any]]]:
    """Strip error entries before passing to adapter.merge / .correlate."""
    return {
        name: [r for r in results if not _is_error(r)]
        for name, results in per_model_raw.items()
    }


def _is_error(item: Any) -> bool:
    """Substrate convention: any dict with a top-level 'error' key."""
    return isinstance(item, dict) and "error" in item


def _apply_reviewer(
    merged: List[Dict[str, Any]],
    reviewer: Reviewer,
    adapter: ItemAdapter,
) -> List[Dict[str, Any]]:
    """Run a reviewer and replace items by id.

    Items omitted from the reviewer's return keep their prior version.
    Items returned with ids that didn't exist in the input are ignored —
    reviewers cannot inject new items.

    Reviewer exceptions and bad return types are caught: the reviewer's
    contribution is dropped (no annotations) but the run continues.
    """
    # For ConditionalReviewer, the substrate restricts replacement to ids
    # that passed should_review. A buggy/malicious reviewer cannot sneak
    # changes onto items the condition rejected.
    allowed_ids: Optional[set[str]] = None
    try:
        if isinstance(reviewer, ConditionalReviewer):
            applicable = [item for item in merged if reviewer.should_review(item)]
            if not applicable:
                return merged
            allowed_ids = {adapter.item_id(item) for item in applicable}
            reviewed = reviewer.review(applicable)
        else:
            reviewed = reviewer.review(merged)
    except Exception as exc:
        logger.warning(
            f"Reviewer {reviewer.name!r} raised {type(exc).__name__}: {exc} — "
            f"skipping this reviewer's annotations",
            exc_info=True,
        )
        return merged

    if not isinstance(reviewed, list):
        logger.warning(
            f"Reviewer {reviewer.name!r} returned {type(reviewed).__name__}, "
            f"expected list — skipping this reviewer's annotations"
        )
        return merged

    by_id: Dict[str, Dict[str, Any]] = {
        adapter.item_id(item): item for item in merged
    }
    for new_item in reviewed:
        if not isinstance(new_item, dict):
            logger.debug(
                f"Reviewer {reviewer.name!r} returned non-dict item "
                f"({type(new_item).__name__}) — ignored"
            )
            continue
        new_id = adapter.item_id(new_item)
        if allowed_ids is not None and new_id not in allowed_ids:
            logger.debug(
                f"ConditionalReviewer {reviewer.name!r} returned item "
                f"{new_id!r} that wasn't in its applicable set — ignored "
                f"(reviewers cannot widen their own scope)"
            )
            continue
        if new_id in by_id:
            by_id[new_id] = new_item
        else:
            logger.debug(
                f"Reviewer {reviewer.name!r} returned item with unknown id "
                f"{new_id!r} — ignored"
            )

    # Preserve original input order.
    return [by_id[adapter.item_id(orig)] for orig in merged]


# _over_budget is now inlined inside run_multi_model() to capture
# per-run gate state without mutating the external cost_gate object.

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
from collections.abc import Iterable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

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
    reviewers: Iterable[Reviewer] | None = (),
    aggregator: Aggregator | None = None,
    cost_gate: CostGate | None = None,
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
        - cost_gate.budget_ratio() exceptions are caught and suspend
          gating for a cooldown (then re-probe automatically); a
          non-numeric return permanently disables gating for the run.
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
            "All %s model(s) failed: %s. Adapter will receive empty per-model results.", len(models), failed_models
        )

    merged = adapter.merge(per_model_filtered)
    if not isinstance(merged, list):
        msg = (
            f"adapter.merge() must return a list; got "
            f"{type(merged).__name__}. Adapter is buggy."
        )
        raise TypeError(msg)
    _check_unique_ids(merged, adapter)
    correlation = adapter.correlate(merged, per_model_filtered)
    if not isinstance(correlation, dict):
        msg = (
            f"adapter.correlate() must return a dict; got "
            f"{type(correlation).__name__}. Adapter is buggy."
        )
        raise TypeError(msg)

    # Local gate state — never mutate the external cost_gate.
    # Transient exceptions from budget_ratio() suspend gating for
    # _GATE_RETRY_SECONDS, then re-probe automatically (circuit-breaker).
    # Type-contract violations (non-float return) permanently disable
    # gating for the run — a wrong return type is a code bug, not a
    # network hiccup, and recovery would not help.
    _gate_permanent_off = [cost_gate is None]
    _gate_disabled_at: list = [None]  # None or monotonic timestamp of last transient fail

    def over_budget(cutoff_ratio: float) -> tuple[bool, float | None]:
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
                "cost_gate.budget_ratio() raised %s: %s — "
                "suspending cost gating for %.0fs",
                type(exc).__name__,
                exc,
                _GATE_RETRY_SECONDS,
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
                "cost_gate.budget_ratio() returned %s (%r), expected float — permanently disabling cost gating for the rest of this run", type(ratio).__name__, ratio
            )
            _gate_permanent_off[0] = True
            return False, None
        return ratio >= cutoff_ratio, ratio

    for reviewer in reviewers:
        skip, spend = over_budget(reviewer.cutoff_ratio)
        if skip:
            logger.info(
                "Skipping reviewer %r — over budget "
                "(spend=%.2f, cutoff=%.2f)",
                reviewer.name,
                spend,
                reviewer.cutoff_ratio,
            )
            continue
        merged = _apply_reviewer(merged, reviewer, adapter)

    # aggregation tri-state:
    #   None  — aggregator not configured OR skipped for budget (see logs)
    #   {}    — aggregator ran but produced no usable output (errored or empty)
    #   {...} — aggregator succeeded
    aggregation: dict[str, Any] | None = None
    if aggregator is not None:
        skip, spend = over_budget(aggregator.cutoff_ratio)
        if skip:
            logger.info(
                "Skipping aggregator — over budget "
                "(spend=%.2f, cutoff=%.2f)",
                spend,
                aggregator.cutoff_ratio,
            )
        else:
            try:
                result = aggregator.aggregate(merged, correlation)
            except Exception as exc:
                logger.warning(
                    "Aggregator raised %s: %s", type(exc).__name__, exc,
                    exc_info=True,
                )
                aggregation = {}
            else:
                if result is None:
                    aggregation = {}
                elif not isinstance(result, dict):
                    logger.warning(
                        "Aggregator returned %s, expected dict — treating as empty per the documented contract", type(result).__name__)
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


def _warn_same_weights(names: Sequence[str]) -> None:
    """Warn when two panel entries peel to the same underlying model.

    Distinct model_name values can be the SAME weights reached over
    two transports — a bare Bedrock id (``anthropic.claude-x``), its
    regionally-prefixed form (``us.anthropic.claude-x``) and the
    direct-API name (``claude-x``) all resolve to one model.  The
    duplicate-name check above can't see that, and treating the pair
    as independent opinions silently inflates consensus confidence.
    Warning, not error: same-weights panels are legitimate for
    transport A/B comparisons — the operator just shouldn't read the
    agreement as diversity.
    """
    try:
        from core.security.llm_family import bare_model_id
    except Exception:  # noqa: BLE001 — advisory only
        return
    peeled: dict[str, list[str]] = {}
    for name in names:
        try:
            bare = bare_model_id(name)
        except Exception:  # noqa: BLE001 — advisory only
            continue
        if bare:
            peeled.setdefault(bare, []).append(name)
    for bare, group in sorted(peeled.items()):
        if len(group) > 1:
            logger.warning(
                "multi-model panel: %s all resolve to the same "
                "underlying model (%s) — their agreement is transport "
                "consistency, not independent consensus",
                group, bare,
            )


def _validate_inputs(
    task: TaskFn,
    models: Sequence[ModelHandle],
    adapter: ItemAdapter,
    reviewers: Sequence[Reviewer],
    aggregator: Aggregator | None,
    cost_gate: CostGate | None,
) -> None:
    if not callable(task):
        msg = f"task must be callable; got {type(task).__name__}"
        raise TypeError(msg)
    if not isinstance(adapter, ItemAdapter):
        msg = (
            f"adapter must implement ItemAdapter (item_id, merge, correlate); "
            f"got {type(adapter).__name__}"
        )
        raise TypeError(msg)
    if not models:
        msg = "models must be non-empty"
        raise ValueError(msg)
    for i, m in enumerate(models):
        if not hasattr(m, "model_name") or not isinstance(m.model_name, str):
            msg = (
                f"models[{i}] does not implement ModelHandle "
                f"(needs str-typed model_name); got {type(m).__name__}"
            )
            raise TypeError(msg)
        if not m.model_name:
            msg = f"models[{i}].model_name must be non-empty"
            raise ValueError(msg)
    names = [m.model_name for m in models]
    counts = Counter(names)
    dupes = sorted(name for name, c in counts.items() if c > 1)
    if dupes:
        msg = f"duplicate model_name(s): {dupes}"
        raise ValueError(msg)
    _warn_same_weights(names)
    for i, r in enumerate(reviewers):
        if not isinstance(r, Reviewer):
            msg = (
                f"reviewers[{i}] does not implement Reviewer "
                f"(needs name, cutoff_ratio, review); got {type(r).__name__}"
            )
            raise TypeError(msg)
        _check_cutoff_ratio(r.cutoff_ratio, f"reviewers[{i}].cutoff_ratio")
    if aggregator is not None:
        if not isinstance(aggregator, Aggregator):
            msg = (
                f"aggregator does not implement Aggregator "
                f"(needs cutoff_ratio, aggregate); got {type(aggregator).__name__}"
            )
            raise TypeError(msg)
        _check_cutoff_ratio(aggregator.cutoff_ratio, "aggregator.cutoff_ratio")
    if cost_gate is not None and not isinstance(cost_gate, CostGate):
        msg = (
            f"cost_gate does not implement CostGate "
            f"(needs budget_ratio); got {type(cost_gate).__name__}"
        )
        raise TypeError(msg)


def _check_cutoff_ratio(value: Any, label: str) -> None:
    """Reviewer.cutoff_ratio and Aggregator.cutoff_ratio are documented as
    floats. runtime_checkable Protocol only checks attribute presence, not
    type — so do an explicit numeric check at the boundary."""
    # bool is a subclass of int; exclude it explicitly.
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        msg = f"{label} must be int/float; got {type(value).__name__}"
        raise TypeError(msg)


def _check_unique_ids(
    merged: list[dict[str, Any]], adapter: ItemAdapter,
) -> None:
    """Validate adapter.merge() output: ids must be unique non-empty strings.

    Duplicate ids would silently corrupt reviewer dispatch (later items
    overwrite earlier in the by-id dict). Non-string ids would break
    by-id lookups. Raise to surface the adapter bug at the boundary
    instead of letting it propagate.
    """
    ids: list[str] = []
    for idx, item in enumerate(merged):
        item_id = adapter.item_id(item)
        if not isinstance(item_id, str) or not item_id:
            msg = (
                f"adapter.item_id() returned {type(item_id).__name__!r} "
                f"({item_id!r}) for merged[{idx}]; expected non-empty str"
            )
            raise TypeError(msg)
        ids.append(item_id)
    counts = Counter(ids)
    dupes = sorted(i for i, c in counts.items() if c > 1)
    if dupes:
        msg = (
            f"adapter.merge() returned duplicate item_id(s): {dupes}. "
            f"Adapter is buggy."
        )
        raise ValueError(msg)


def _dispatch_parallel(
    task: TaskFn,
    models: Sequence[ModelHandle],
    max_parallel: int,
    timeout: float = 600.0,
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Run task in parallel across models. Returns (per_model_raw, failed).

    A model is "failed" if task() raised, OR if every entry in its result
    list is an error dict. Empty result lists are NOT failures (the model
    just had nothing to say).

    On timeout the incomplete models are marked failed and this
    function RETURNS — it deliberately does not join hung workers
    (``shutdown(wait=False, cancel_futures=True)``): queued tasks are
    cancelled, but a worker thread blocked inside ``task()`` may
    linger until its underlying call unblocks or the process exits.
    Pre-fix the executor context manager's ``__exit__`` re-joined
    those hung workers, so the caller stayed blocked for as long as
    the very hang the timeout had just recorded.
    """
    per_model_raw: dict[str, list[dict[str, Any]]] = {}
    failed: list[str] = []

    workers = max(1, min(max_parallel, len(models)))
    ex = ThreadPoolExecutor(max_workers=workers)
    try:
        futures = {ex.submit(task, m): m for m in models}
        try:
            completed = as_completed(futures, timeout=timeout)
            for future in completed:
                model = futures[future]
                name = model.model_name
                try:
                    results = future.result(timeout=timeout)
                except Exception as exc:
                    logger.warning(
                        "Model %r task raised: %s", name, exc,
                        exc_info=True,
                    )
                    per_model_raw[name] = []
                    failed.append(name)
                    continue

                if not isinstance(results, list):
                    logger.warning(
                        "Model %r task returned %s, expected list — treating as failure", name, type(results).__name__)
                    per_model_raw[name] = []
                    failed.append(name)
                    continue

                non_dict = [
                    type(r).__name__
                    for r in results
                    if not isinstance(r, dict)
                ]
                if non_dict:
                    logger.warning(
                        "Model %r task returned non-dict items (%s%s) — treating as failure. Item contract is List[Dict[str, Any]].", name, non_dict[:3], ('...' if len(non_dict) > 3 else '')
                    )
                    per_model_raw[name] = []
                    failed.append(name)
                    continue

                per_model_raw[name] = results
                if results and all(_is_error(r) for r in results):
                    failed.append(name)
        except TimeoutError:
            # Mark models that didn't complete as failed.
            for model in futures.values():
                if model.model_name not in per_model_raw:
                    logger.warning(
                        "Model %r timed out after %.0fs",
                        model.model_name, timeout,
                    )
                    per_model_raw[model.model_name] = []
                    failed.append(model.model_name)
    finally:
        # Never wait on hung workers (see docstring) — cancel what's
        # still queued and return; on the happy path everything has
        # already completed so this is a no-op.
        ex.shutdown(wait=False, cancel_futures=True)

    return per_model_raw, failed


def _filter_errors(
    per_model_raw: dict[str, list[dict[str, Any]]],
) -> dict[str, list[dict[str, Any]]]:
    """Strip error entries before passing to adapter.merge / .correlate."""
    return {
        name: [r for r in results if not _is_error(r)]
        for name, results in per_model_raw.items()
    }


def _is_error(item: Any) -> bool:
    """Substrate convention: any dict with a top-level 'error' key."""
    return isinstance(item, dict) and "error" in item


def _apply_reviewer(
    merged: list[dict[str, Any]],
    reviewer: Reviewer,
    adapter: ItemAdapter,
) -> list[dict[str, Any]]:
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
    allowed_ids: set[str] | None = None
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
            "Reviewer %r raised %s: %s — skipping this reviewer's annotations", reviewer.name, type(exc).__name__, exc,
            exc_info=True,
        )
        return merged

    if not isinstance(reviewed, list):
        logger.warning(
            "Reviewer %r returned %s, expected list — skipping this reviewer's annotations", reviewer.name, type(reviewed).__name__)
        return merged

    by_id: dict[str, dict[str, Any]] = {
        adapter.item_id(item): item for item in merged
    }
    for new_item in reviewed:
        if not isinstance(new_item, dict):
            logger.debug(
                "Reviewer %r returned non-dict item (%s) — ignored", reviewer.name, type(new_item).__name__)
            continue
        try:
            new_id = adapter.item_id(new_item)
        except Exception as exc:  # noqa: BLE001 — reviewer output is untrusted
            # Adapters implement item_id as plain dict-field access, so
            # a reviewer item missing the id field raises KeyError.
            # Per the docstring's contract, bad reviewer return shapes
            # drop that item — they must not crash the run (matches
            # the non-dict handling above).
            logger.debug(
                "Reviewer %r returned item without a usable id (%s) — ignored", reviewer.name, type(exc).__name__)
            continue
        if allowed_ids is not None and new_id not in allowed_ids:
            logger.debug(
                "ConditionalReviewer %r returned item %r that wasn't in its applicable set — ignored (reviewers cannot widen their own scope)", reviewer.name, new_id
            )
            continue
        if new_id in by_id:
            by_id[new_id] = new_item
        else:
            logger.debug(
                "Reviewer %r returned item with unknown id %r — ignored", reviewer.name, new_id)

    # Preserve original input order.
    return [by_id[adapter.item_id(orig)] for orig in merged]


# over_budget is now inlined inside run_multi_model() to capture
# per-run gate state without mutating the external cost_gate object.

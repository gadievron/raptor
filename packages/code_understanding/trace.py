"""Multi-model orchestrator for /understand --trace.

Runs N models against a list of traces (entry-point flows), merges
their per-trace verdicts via prefer-positive rules, and optionally
synthesizes via an aggregator.

The actual LLM call lives in `dispatch_fn` (consumer-supplied).
PR2b will provide a default dispatch_fn; for now mocks work cleanly.
"""

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional

from core.llm.multi_model import (
    Aggregator,
    CostGate,
    ModelHandle,
    MultiModelResult,
    Reviewer,
    run_multi_model,
)

from packages.code_understanding.adapters import TraceAdapter

logger = logging.getLogger(__name__)


TraceDispatchFn = Callable[
    [ModelHandle, List[Dict[str, Any]]],  # (model, traces_to_classify)
    List[Dict[str, Any]],                  # list of verdict dicts
]
# Asymmetry note: HuntDispatchFn takes (model, pattern, repo_path) while
# TraceDispatchFn takes (model, traces). That's intentional — hunt has a
# single pattern applied across the codebase, while trace has a list of
# pre-built traces (each carrying its own entry/sink/steps). The
# dispatch_fn signatures reflect what each mode actually needs, not a
# shared shape.


def trace(
    *,
    traces: List[Dict[str, Any]],
    repo_path: str,
    models: Iterable[ModelHandle],
    dispatch_fn: TraceDispatchFn,
    reviewers: Optional[Iterable[Reviewer]] = (),
    aggregator: Optional[Aggregator] = None,
    cost_gate: Optional[CostGate] = None,
    max_parallel: int = 3,
) -> MultiModelResult:
    """Multi-model trace verdict.

    Args:
        traces: List of trace dicts to classify. Each must have at
            least a `trace_id` field; other fields (entry, sink, steps)
            are dispatch_fn's responsibility to interpret.
        repo_path: Repository to analyse.
        models: Sequence of ModelHandles.
        dispatch_fn: Callable that takes a model + the trace list and
            returns one verdict dict per trace. Each verdict dict must
            include `trace_id` (matching the input) and `verdict`
            (reachable | not_reachable | uncertain).
        reviewers: Optional review phase — runs after merge.
        aggregator: Optional LLM synthesis.
        cost_gate: Optional budget gate.
        max_parallel: Thread pool size.

    Returns:
        MultiModelResult with `items` = one merged trace per trace_id
        (primary = prefer-positive winner) and `correlation` carrying
        agreement signals (high / high-negative / disputed / mixed /
        high-inconclusive / single_model).
    """
    if not traces:
        raise ValueError("traces must be non-empty")
    if not callable(dispatch_fn):
        raise TypeError(
            f"dispatch_fn must be callable; got {type(dispatch_fn).__name__}"
        )

    def task(model: ModelHandle) -> List[Dict[str, Any]]:
        return dispatch_fn(model, traces)

    # repo_path isn't needed by the substrate (the dispatch_fn closes
    # over it via its own arguments), but we keep it on the signature
    # for symmetry with hunt() and so a future PR2b dispatch can use it.
    _ = repo_path

    return run_multi_model(
        task=task,
        models=models,
        adapter=TraceAdapter(),
        reviewers=reviewers,
        aggregator=aggregator,
        cost_gate=cost_gate,
        max_parallel=max_parallel,
    )

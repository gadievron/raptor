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
    [ModelHandle, List[Dict[str, Any]], str],  # (model, traces, repo_path)
    List[Dict[str, Any]],                       # list of verdict dicts
]
# Symmetric with HuntDispatchFn (which is (model, pattern, repo_path)).
# PR2a originally typed this as 2-arg (omitting repo_path), reasoning
# that traces "carry their own metadata." That was wrong: a real LLM
# trace dispatcher needs to read the codebase to verify reachability.
# PR2b corrects to 3-arg.


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
        return dispatch_fn(model, traces, repo_path)

    return run_multi_model(
        task=task,
        models=models,
        adapter=TraceAdapter(),
        reviewers=reviewers,
        aggregator=aggregator,
        cost_gate=cost_gate,
        max_parallel=max_parallel,
    )

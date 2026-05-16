"""Multi-model orchestrator for /understand --hunt.

Runs N models in parallel against a hunt task, unions their variant
findings, and optionally synthesizes them via an aggregator.

The actual LLM call lives in `dispatch_fn` (consumer-supplied) — the
orchestrator is dispatch-agnostic. PR2b will provide a default
dispatch_fn that talks to the LLM SDK; for now, callers provide their
own (which makes mock testing trivial).
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

from packages.code_understanding.adapters import VariantAdapter

logger = logging.getLogger(__name__)


HuntDispatchFn = Callable[
    [ModelHandle, str, str],     # (model, pattern, repo_path)
    List[Dict[str, Any]],        # list of variant dicts
]


def hunt(
    *,
    pattern: str,
    repo_path: str,
    models: Iterable[ModelHandle],
    dispatch_fn: HuntDispatchFn,
    reviewers: Optional[Iterable[Reviewer]] = (),
    aggregator: Optional[Aggregator] = None,
    cost_gate: Optional[CostGate] = None,
    max_parallel: int = 3,
) -> MultiModelResult:
    """Multi-model variant hunt.

    Args:
        pattern: The pattern to hunt — natural-language description, a
            sample finding id, or a regex. Interpretation is dispatch_fn's
            responsibility.
        repo_path: Repository to search.
        models: Sequence of ModelHandles. Substrate validates non-empty
            and unique model_names.
        dispatch_fn: Callable that takes a single model + pattern + repo
            and returns its list of variant dicts. Each variant dict
            should match VariantAdapter's expected shape (file, line,
            function, ...).
        reviewers: Optional review phase — runs after merge.
        aggregator: Optional LLM synthesis — runs once over merged + correlated.
        cost_gate: Optional budget gate. None disables gating.
        max_parallel: Thread pool size.

    Returns:
        MultiModelResult with `items` = unioned variants annotated with
        `found_by_models`, and `correlation` carrying recall signals.
    """

    if not isinstance(pattern, str) or not pattern.strip():
        raise ValueError("pattern must be a non-empty string")
    if not callable(dispatch_fn):
        raise TypeError(
            f"dispatch_fn must be callable; got {type(dispatch_fn).__name__}"
        )
    # Strip permanently so dispatch_fn doesn't have to handle leading/
    # trailing whitespace from copy-paste mistakes.
    pattern = pattern.strip()

    def task(model: ModelHandle) -> List[Dict[str, Any]]:
        # Substrate calls this once per model in parallel. dispatch_fn
        # is the consumer-supplied actual-work; we just bind args.
        return dispatch_fn(model, pattern, repo_path)

    return run_multi_model(
        task=task,
        models=models,
        adapter=VariantAdapter(),
        reviewers=reviewers,
        aggregator=aggregator,
        cost_gate=cost_gate,
        max_parallel=max_parallel,
    )

"""Adapter: orchestrator dispatch_fn → hypothesis_validation LLMClientProtocol.

The /agentic orchestrator builds a `dispatch_fn(prompt, schema,
system_prompt, temperature, model) -> DispatchResult` that handles
external-LLM and CC-fallback modes uniformly. hypothesis_validation
expects a different shape: `client.generate_structured(prompt, schema,
system_prompt=..., task_type=..., **kwargs) -> dict-or-None`.

This adapter bridges the two so the dataflow-validation pass can reuse
the orchestrator's already-configured client without forcing
hypothesis_validation to know about DispatchResult, role resolution, or
CostTracker.
"""

import logging
from collections.abc import Callable
from typing import Any

from core.llm.coerce import structured_result

logger = logging.getLogger(__name__)


class DispatchClient:
    """Wrap a dispatch_fn so it satisfies LLMClientProtocol.

    Args:
        dispatch_fn: The orchestrator's dispatch callable. Signature:
            (prompt, schema, system_prompt, temperature, model) -> DispatchResult
            where DispatchResult has .result (dict) and .cost (float).
        model: Model spec (typically a ModelConfig) to use for every
            call this adapter makes. The orchestrator selects this once
            per /agentic run; we don't need per-call model selection.
        cost_tracker: Optional CostTracker. When provided, each call's
            cost is added so the budget guard sees dataflow validation
            work.
        temperature: Sampling temperature, default 0.0 (deterministic).
            hypothesis_validation generates rules and evaluates evidence;
            both want low entropy.
    """

    def __init__(
        self,
        dispatch_fn: Callable,
        model: Any,
        *,
        cost_tracker: Any | None = None,
        temperature: float = 0.0,
    ):
        self._dispatch_fn = dispatch_fn
        self._model = model
        self._cost_tracker = cost_tracker
        self._temperature = temperature

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None = None,
        task_type: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any] | None:
        """Invoke the orchestrator's dispatch_fn and return the parsed dict.

        `task_type` is accepted for protocol compatibility but ignored —
        the model is fixed at construction time per the orchestrator's
        role resolution. `kwargs` are also ignored.

        Returns the result dict on success, or None on any failure
        (exception, missing result attribute, error in payload). Never
        raises — hypothesis_validation's runner.validate is documented
        to handle None as "LLM did not return a usable response."
        """
        try:
            response = self._dispatch_fn(
                prompt, schema, system_prompt, self._temperature, self._model,
            )
        except Exception as e:  # noqa: BLE001 — fail-open: any dispatch failure means "no verdict"
            logger.warning("dispatch_fn raised during dataflow validation: %s", e)
            return None

        cost = getattr(response, "cost", 0.0) or 0.0
        if cost and self._cost_tracker is not None:
            try:
                model_name = (
                    getattr(self._model, "model", None)
                    or str(self._model)
                )
                self._cost_tracker.add_cost(model_name, cost)
            except Exception as e:  # noqa: BLE001 — cost accounting must never sink the validation
                logger.debug(
                    "cost_tracker.add_cost failed: %s", e,
                )

        result = structured_result(response)
        if not isinstance(result, dict):
            return None
        if "error" in result:
            logger.warning(
                "dispatch_fn returned error during dataflow validation: %s",
                result.get("error"),
            )
            return None
        return result


__all__ = ["DispatchClient"]

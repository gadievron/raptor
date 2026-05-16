"""Multi-model substrate.

Generic, schema-agnostic infrastructure for running N models against the
same task, merging results, and optionally synthesizing the output.

Public API:
    run_multi_model        — orchestrate dispatch, merge, review, aggregate
    MultiModelResult       — return type
    ItemAdapter            — protocol: merge + correlate
    VerdictAdapter         — adapter for verdict-style tasks (positive/negative)
    SetAdapter             — adapter for set-style tasks (union with recall)
    Reviewer               — pluggable per-item reviewer (judge/consensus)
    ConditionalReviewer    — reviewer that runs only on certain items
    Aggregator             — optional LLM synthesis at end
    wrap_model_output      — wrap prior-model output as untrusted input

The substrate handles dispatch, merge, review, and aggregation. It does
NOT handle: retry-on-contradiction, cross-finding group analysis, or
generation tasks (best-of-N). Those stay in their respective consumers.
"""

from core.llm.multi_model.adapters import BaseSetAdapter, BaseVerdictAdapter
from core.llm.multi_model.dispatch import run_multi_model
from core.llm.multi_model.prompt_helpers import wrap_model_output
from core.llm.multi_model.types import (
    Aggregator,
    ConditionalReviewer,
    CostGate,
    ItemAdapter,
    ModelHandle,
    MultiModelResult,
    Reviewer,
    SetAdapter,
    TaskFn,
    VerdictAdapter,
)

__all__ = [
    "Aggregator",
    "BaseSetAdapter",
    "BaseVerdictAdapter",
    "ConditionalReviewer",
    "CostGate",
    "ItemAdapter",
    "ModelHandle",
    "MultiModelResult",
    "Reviewer",
    "SetAdapter",
    "TaskFn",
    "VerdictAdapter",
    "run_multi_model",
    "wrap_model_output",
]

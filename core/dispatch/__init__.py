"""Unified dispatch — model selection, routing, and scheduling.

Layer 1 (Substrate): ``core.llm.providers`` — call a specific model.
Layer 2 (Broker):    ``core.dispatch.broker`` — pick and call the best
                     available model for a task shape.
Layer 3 (Scheduler): future — priority queuing, DAG deps, concurrency.

Consumers bind to the layer that matches their needs.  See
``~/design/unified-dispatch.md`` for the full architecture.
"""

from .broker.hints import ModelHint, SpeedTier
from .broker.context_routing import select_by_context
from .broker.decision_log import DecisionLog, DecisionRecord

__all__ = [
    "DecisionLog",
    "DecisionRecord",
    "ModelHint",
    "SpeedTier",
    "select_by_context",
]

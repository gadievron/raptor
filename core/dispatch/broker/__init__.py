"""Broker layer — model selection, routing, and dispatch primitives."""

from .hints import ModelHint, SpeedTier
from .context_routing import select_by_context
from .decision_log import DecisionLog, DecisionRecord

__all__ = [
    "ModelHint",
    "SpeedTier",
    "select_by_context",
    "DecisionLog",
    "DecisionRecord",
]

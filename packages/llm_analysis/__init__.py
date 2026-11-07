"""
RAPTOR LLM Analysis Package

Autonomous security agent with LLM-powered vulnerability analysis,
exploit generation, and patch creation.

Public API:
    from packages.llm_analysis import LLMClient, LLMConfig, get_client
    from packages.llm_analysis import detect_llm_availability
    from packages.llm_analysis.orchestrator import orchestrate
"""

from __future__ import annotations

import logging
from importlib import import_module as _import_module
from typing import TYPE_CHECKING, Any

# Preserve static dependency edges and type information without initializing
# clients or the agent for leaf helpers such as journal_emit.
if TYPE_CHECKING:
    from core.llm.client import LLMClient
    from core.llm.config import LLMConfig, ModelConfig
    from core.llm.detection import LLMAvailability, detect_llm_availability
    from core.llm.factory import get_client
    from .agent import AutonomousSecurityAgentV2

# Reload refreshes aliases just as the previous eager imports did.
for _cached_export in globals().get("_LAZY_EXPORTS", ()):
    globals().pop(_cached_export, None)
globals().pop("_cached_export", None)

_LAZY_EXPORTS = {
    "agent": ("packages.llm_analysis.agent", None),
    "AutonomousSecurityAgentV2": ("packages.llm_analysis.agent", "AutonomousSecurityAgentV2"),
    "LLMAvailability": ("core.llm.detection", "LLMAvailability"),
    "LLMClient": ("core.llm.client", "LLMClient"),
    "LLMConfig": ("core.llm.config", "LLMConfig"),
    "ModelConfig": ("core.llm.config", "ModelConfig"),
    "detect_llm_availability": ("core.llm.detection", "detect_llm_availability"),
    "get_client": ("core.llm.factory", "get_client"),
}


def __getattr__(name: str) -> Any:
    spec = _LAZY_EXPORTS.get(name)
    if spec is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = spec
    module = _import_module(module_name)
    value = module if attribute is None else getattr(module, attribute)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_EXPORTS))


logger = logging.getLogger(__name__)


__all__ = [
    "AutonomousSecurityAgentV2",
    "LLMAvailability",
    "LLMClient",
    "LLMConfig",
    "ModelConfig",
    "detect_llm_availability",
    "get_client",
]

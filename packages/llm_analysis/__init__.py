"""
RAPTOR LLM Analysis Package

Autonomous security agent with LLM-powered vulnerability analysis,
exploit generation, and patch creation.

Public API:
    from packages.llm_analysis import LLMClient, LLMConfig, get_client
    from packages.llm_analysis import detect_llm_availability
    from packages.llm_analysis import orchestrate
"""

import logging

from .llm.client import LLMClient
from .llm.config import LLMConfig, ModelConfig
from .llm.detection import detect_llm_availability, LLMAvailability
from .agent import AutonomousSecurityAgentV2

logger = logging.getLogger(__name__)


def get_client(config: LLMConfig = None) -> LLMClient | None:
    """Get an LLM client, returning None if no provider is available.

    Use this instead of the try/except LLMClient() pattern.
    """
    try:
        cfg = config or LLMConfig()
        if not cfg.primary_model:
            return None
        return LLMClient(cfg)
    except Exception as e:
        logger.warning(f"LLM client not available: {e}")
        return None


__all__ = [
    "LLMClient",
    "LLMConfig",
    "ModelConfig",
    "LLMAvailability",
    "detect_llm_availability",
    "get_client",
    "AutonomousSecurityAgentV2",
]

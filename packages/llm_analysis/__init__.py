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

from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.detection import LLMAvailability, detect_llm_availability

# Canonical home is core/llm/factory.py; re-exported here so the
# documented `from packages.llm_analysis import get_client` surface
# keeps working while remaining callers migrate to
# `from core.llm.factory import get_client`.
from core.llm.factory import get_client

from .agent import AutonomousSecurityAgentV2

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

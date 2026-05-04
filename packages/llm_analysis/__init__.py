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
from core.llm.detection import detect_llm_availability, LLMAvailability
from .agent import AutonomousSecurityAgentV2

logger = logging.getLogger(__name__)


def get_client(
    config: LLMConfig = None,
    *,
    prefer: str | list[str] | None = None,
) -> LLMClient | None:
    """Get an LLM client, returning None if no provider is available.

    Use this instead of the try/except LLMClient() pattern.

    ``prefer`` lets a consumer express its own provider preference
    (e.g. cve-diff prefers ``"anthropic"`` for ``cache_control``
    savings + ``task_budget`` beta) without depending on the default
    autodetect order. Unknown / unavailable preferred providers are
    silently skipped; falls through to the default order for the
    rest. Ignored when ``config`` is explicitly passed (caller has
    already chosen a primary).

    Examples:
        get_client()                              # default autodetect
        get_client(prefer="anthropic")            # cve-diff
        get_client(prefer=["openai", "gemini"])   # ordered fallthrough
    """
    try:
        if config is None:
            from core.llm.config import _get_default_primary_model
            primary = _get_default_primary_model(prefer=prefer)
            if primary is None:
                return None
            cfg = LLMConfig(primary_model=primary)
        else:
            cfg = config
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

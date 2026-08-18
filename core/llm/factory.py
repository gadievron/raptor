"""Soft-fail LLM client factory — the one way to say "give me a
client, or None if no provider is configured".

Moved here from ``packages/llm_analysis`` (which re-exports it for
compatibility): the factory is pure core/llm plumbing — config
autodetection + ``LLMClient`` construction — and consumers that are
not part of the agentic package (raptor_codeql, raptor_fuzzing, SCA,
codeql's evidence validator) were importing a sibling package just to
reach it. Other bespoke factory spellings in the tree (sca's
``get_llm_client``, codeql's ``_construct_default_llm_client``, the
audit pipeline's budget-capped builder) are adoption-sweep candidates;
audit's builder adds budget semantics and stays separate.
"""

from __future__ import annotations

import logging

from core.llm.client import LLMClient
from core.llm.config import LLMConfig

logger = logging.getLogger(__name__)

__all__ = ["get_client"]


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
    except Exception as e:  # noqa: BLE001 — soft-fail factory by contract
        logger.warning("LLM client not available: %s", e)
        return None

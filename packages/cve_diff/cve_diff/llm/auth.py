"""Provider resolution + Claude Code OAuth fallback for cve-diff.

cve-diff is model-agnostic: ``--model gpt-5`` calls OpenAI,
``--model gemini-2.5-pro`` calls Gemini, etc. Provider resolution
delegates to :func:`core.security.llm_family.provider_of`.

Auth resolution delegates to :mod:`core.llm.providers` — the provider
class checks ``RAPTOR_LLM_SOCKET`` and routes via the credential-
isolation dispatcher when set, else lets the SDK read its own env
var. cve-diff doesn't need to enumerate provider env vars; the
central LLM config (:data:`core.config.RaptorConfig.LLM_API_KEY_VARS`)
does that already.

cve-diff's only special case: when the operator wants an Anthropic
model but has neither ``ANTHROPIC_API_KEY`` nor the dispatcher,
fall through to ``provider="claudecode"`` so Claude Code's OAuth
auth handles the call (historical cve-diff behaviour: cheap-by-
default Anthropic preference). Other providers don't have this
fallback — passing ``--model gpt-5`` with no OpenAI auth surfaces
a clear SDK error.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class AuthDecision:
    """Resolution result for a model id.

    ``provider`` is what the caller should pass to ``ModelConfig``.
    ``api_key`` is left as ``None`` so the provider's SDK reads
    its own env var directly (``ANTHROPIC_API_KEY`` etc.) or the
    dispatcher route in :mod:`core.llm.providers` handles auth.
    """
    provider: str
    api_key: Optional[str] = None
    via_dispatcher: bool = False


def resolve_auth(model_id: str) -> AuthDecision:
    """Resolve provider from model id, with the Claude Code OAuth
    fallback for Anthropic models when no other auth is available."""
    # Lazy import — keep this module importable in minimal envs.
    from core.security.llm_family import provider_of

    provider = provider_of(model_id) or "anthropic"
    via_dispatcher = bool(os.environ.get("RAPTOR_LLM_SOCKET"))

    # Claude Code OAuth fallback for Anthropic-family models when
    # neither dispatcher nor ANTHROPIC_API_KEY is available.
    # Historical cve-diff behaviour preserved (operator without an
    # Anthropic key but with Claude Code installed gets free
    # Anthropic-routed analysis).
    if (provider == "anthropic"
            and not via_dispatcher
            and not os.environ.get("ANTHROPIC_API_KEY")):
        return AuthDecision(provider="claudecode")

    # Everything else: hand off to ``core.llm.providers``. Pass
    # ``api_key=None`` so the SDK / dispatcher route picks it up
    # without cve-diff needing to enumerate provider env vars.
    # If neither auth path is set, the SDK construction surfaces
    # a clean error at first use.
    return AuthDecision(provider=provider, via_dispatcher=via_dispatcher)

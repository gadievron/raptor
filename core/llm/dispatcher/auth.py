"""Per-provider auth-header injection rules.

Each provider's authentication scheme is a small fact: which headers
to strip from the worker's request, which to inject from the parent's
secret store, which upstream URL to forward to. Encoded as data so
adding a provider is a single dict entry plus a credentials-source.

Only providers RAPTOR actively dispatches to are supported here. If
``api_key`` is None at request time, the dispatcher rejects with
``503 Service Unavailable: provider not configured`` so the worker's
SDK surfaces a clear error rather than a mysterious 401 from upstream.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable


@dataclass(frozen=True)
class ProviderRule:
    """One provider's auth-injection rule.

    ``upstream_base_url`` is the real upstream the dispatcher forwards
    to (e.g. ``https://api.anthropic.com``). ``inject_headers`` is a
    callable so the secret value is read at request time, not at
    rule-construction time — lets the parent rotate keys without
    rebuilding the dispatcher.

    ``strip_request_headers`` removes any auth-shaped header the worker
    might have added (the SDK is given a dummy key but might still echo
    it back). Defence-in-depth — without this, a worker that overrode
    ``api_key`` with a real-looking value would have its value forwarded
    upstream alongside the real one.
    """

    name: str
    upstream_base_url: str
    inject_headers: Callable[[], dict[str, str]]
    strip_request_headers: tuple[str, ...] = (
        "authorization", "x-api-key", "x-goog-api-key",
        "api-key", "openai-organization",
    )


def _read_env(var: str) -> str | None:
    """Read an env var and immediately erase it from the process env.

    The dispatcher reads each provider's key once at startup; after
    that the parent process's environ no longer contains the key.
    Reduces blast radius if the parent is later compromised.
    """
    val = os.environ.get(var)
    if val is not None:
        os.environ.pop(var, None)
    return val


class CredentialStore:
    """In-memory store of provider API keys.

    Loaded once from the parent's environ at dispatcher startup,
    keys then erased from environ. The store is the single point
    that holds plaintext credentials for the lifetime of the run.
    """

    def __init__(self) -> None:
        # Read each provider's key into private state. Store is
        # mutable so tests can inject fakes without touching env.
        self._keys: dict[str, str | None] = {
            "anthropic": _read_env("ANTHROPIC_API_KEY"),
            "openai":    _read_env("OPENAI_API_KEY"),
            "gemini":    _read_env("GEMINI_API_KEY") or _read_env("GOOGLE_API_KEY"),
        }

    def get(self, provider: str) -> str | None:
        return self._keys.get(provider)

    def set(self, provider: str, key: str | None) -> None:
        """Test seam — production code does not call this."""
        self._keys[provider] = key


def build_rules(creds: CredentialStore) -> dict[str, ProviderRule]:
    """Return the rules table for v1 — Anthropic only.

    OpenAI and Gemini will join the table once the v1 design is
    proven. Each addition is one ``ProviderRule`` entry.
    """

    def _anthropic_headers() -> dict[str, str]:
        key = creds.get("anthropic")
        if not key:
            return {}
        return {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }

    return {
        "anthropic": ProviderRule(
            name="anthropic",
            upstream_base_url="https://api.anthropic.com",
            inject_headers=_anthropic_headers,
        ),
    }

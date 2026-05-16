"""Per-provider auth-header injection rules.

Each provider's authentication scheme is a small fact: which headers
to strip from the worker's request, which to inject from the parent's
secret store, which upstream URL to forward to. Encoded as data so
adding a provider is a single dict entry plus a credentials-source.

Only providers RAPTOR actively dispatches to are supported here. If
``api_key`` is None at request time, the dispatcher rejects with
``503 Service Unavailable: provider not configured`` so the worker's
SDK surfaces a clear error rather than a mysterious 401 from upstream.

Out of scope for the proxy-based dispatcher (Phase C-β):

  * **AWS Bedrock** — uses sigv4 request signing. The signing
    happens inside the AWS SDK over the request body, in worker
    process address space (where the keys must live to sign).
    The proxy can't transparently re-sign without a custom Bedrock
    client shim that sends unsigned requests for the dispatcher to
    sign with the parent's keys + per-model-family request shapes.
    Until that ships, ``AWS_*`` env vars stay flowing through to
    workers; operators wanting Bedrock isolation should rely on
    AWS-native short-lived credentials (EC2/EKS instance roles,
    SSO cache) which obviate the env-var question.

  * **GCP Vertex AI** — uses OAuth refresh from a service-account
    JSON file (``GOOGLE_APPLICATION_CREDENTIALS``). The dispatcher
    would need ``google-auth`` integration to refresh the bearer
    token at request time. Deferred to a focused follow-up; until
    then ``GOOGLE_APPLICATION_CREDENTIALS`` flows through env to
    workers and the SDK does its own OAuth exchange.

The remaining providers in ``LLM_API_KEY_VARS`` (the three OG
providers + the Phase C-β aggregators below) are all bearer-auth
on a known upstream URL and route cleanly through the proxy.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
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
            "anthropic":  _read_env("ANTHROPIC_API_KEY"),
            "openai":     _read_env("OPENAI_API_KEY"),
            "gemini":     _read_env("GEMINI_API_KEY") or _read_env("GOOGLE_API_KEY"),
            # OpenAI-compatible aggregators + ecosystem providers.
            # Same Bearer-auth shape; different upstream URLs.
            "mistral":    _read_env("MISTRAL_API_KEY"),
            "groq":       _read_env("GROQ_API_KEY"),
            "together":   _read_env("TOGETHER_API_KEY"),
            "openrouter": _read_env("OPENROUTER_API_KEY"),
            "fireworks":  _read_env("FIREWORKS_API_KEY"),
            "deepinfra":  _read_env("DEEPINFRA_API_KEY"),
            "perplexity": _read_env("PERPLEXITY_API_KEY"),
            "cohere":     _read_env("COHERE_API_KEY"),
            # Replicate — uses ``Token <key>`` prefix, not ``Bearer``.
            "replicate":  _read_env("REPLICATE_API_TOKEN"),
            # Azure OpenAI — operator-configured endpoint URL +
            # api-key header. Endpoint read once at startup; if
            # absent the rule's upstream is a sentinel that produces
            # 503 at request time (consistent with other unconfigured
            # providers).
            "azure_openai":           _read_env("AZURE_OPENAI_API_KEY"),
            "azure_openai_endpoint":  _read_env("AZURE_OPENAI_ENDPOINT"),
        }

    def get(self, provider: str) -> str | None:
        return self._keys.get(provider)

    def set(self, provider: str, key: str | None) -> None:
        """Test seam — production code does not call this."""
        self._keys[provider] = key


def build_rules(creds: CredentialStore) -> dict[str, ProviderRule]:
    """Return the rules table.

    Each provider is a single :class:`ProviderRule` entry. Adding a
    new provider is a closure that returns the right header shape
    plus a ``ProviderRule`` row — no other code changes required.
    Providers whose key is unset at build time are still in the
    table; the dispatcher rejects requests to them with
    ``503 provider not configured`` so worker SDK calls surface a
    clear error.
    """

    def _anthropic_headers() -> dict[str, str]:
        key = creds.get("anthropic")
        if not key:
            return {}
        return {
            "x-api-key": key,
            "anthropic-version": "2023-06-01",
        }

    def _openai_headers() -> dict[str, str]:
        key = creds.get("openai")
        if not key:
            return {}
        return {"Authorization": f"Bearer {key}"}

    def _gemini_headers() -> dict[str, str]:
        key = creds.get("gemini")
        if not key:
            return {}
        # Gemini's REST API accepts the key either as ``?key=...`` query
        # param or as the ``x-goog-api-key`` header; SDKs default to
        # the header so the dispatcher injects it that way.
        return {"x-goog-api-key": key}

    # Bearer-auth aggregators — closure factory keeps each header
    # injector tight (just reads the matching credential). All use
    # the OpenAI-style ``Authorization: Bearer <key>`` shape.
    def _bearer_headers(provider_key: str):
        def _impl() -> dict[str, str]:
            key = creds.get(provider_key)
            if not key:
                return {}
            return {"Authorization": f"Bearer {key}"}
        return _impl

    def _replicate_headers() -> dict[str, str]:
        # Replicate uses ``Token <key>`` (not Bearer). One-off rather
        # than parameterising the factory above for clarity.
        key = creds.get("replicate")
        if not key:
            return {}
        return {"Authorization": f"Token {key}"}

    def _azure_openai_headers() -> dict[str, str]:
        # Azure OpenAI uses ``api-key`` header (not Bearer). Endpoint
        # is operator-configured per Azure deployment; the
        # ``upstream_base_url`` for this rule is filled from
        # ``AZURE_OPENAI_ENDPOINT`` at build time. When the operator
        # didn't set the endpoint, the rule's upstream is the
        # sentinel below and the dispatcher rejects with 503
        # ``provider not configured`` — same UX as missing key.
        key = creds.get("azure_openai")
        if not key:
            return {}
        return {"api-key": key}

    azure_endpoint = (
        creds.get("azure_openai_endpoint")
        or "https://azure-openai-not-configured.invalid"
    )

    return {
        "anthropic": ProviderRule(
            name="anthropic",
            upstream_base_url="https://api.anthropic.com",
            inject_headers=_anthropic_headers,
        ),
        "openai": ProviderRule(
            name="openai",
            upstream_base_url="https://api.openai.com",
            inject_headers=_openai_headers,
        ),
        "gemini": ProviderRule(
            name="gemini",
            upstream_base_url="https://generativelanguage.googleapis.com",
            inject_headers=_gemini_headers,
        ),
        "mistral": ProviderRule(
            name="mistral",
            upstream_base_url="https://api.mistral.ai",
            inject_headers=_bearer_headers("mistral"),
        ),
        "groq": ProviderRule(
            name="groq",
            upstream_base_url="https://api.groq.com",
            inject_headers=_bearer_headers("groq"),
        ),
        "together": ProviderRule(
            name="together",
            upstream_base_url="https://api.together.xyz",
            inject_headers=_bearer_headers("together"),
        ),
        "openrouter": ProviderRule(
            name="openrouter",
            # OpenRouter's API is rooted at ``/api/v1`` rather than the
            # bare host; SDKs typically configure ``base_url=https://
            # openrouter.ai/api/v1``. Forward to the bare host — the
            # SDK's path component (``/api/v1/chat/completions`` etc.)
            # is preserved end-to-end through the dispatcher.
            upstream_base_url="https://openrouter.ai",
            inject_headers=_bearer_headers("openrouter"),
        ),
        "fireworks": ProviderRule(
            name="fireworks",
            upstream_base_url="https://api.fireworks.ai",
            inject_headers=_bearer_headers("fireworks"),
        ),
        "deepinfra": ProviderRule(
            name="deepinfra",
            upstream_base_url="https://api.deepinfra.com",
            inject_headers=_bearer_headers("deepinfra"),
        ),
        "perplexity": ProviderRule(
            name="perplexity",
            upstream_base_url="https://api.perplexity.ai",
            inject_headers=_bearer_headers("perplexity"),
        ),
        "cohere": ProviderRule(
            name="cohere",
            upstream_base_url="https://api.cohere.ai",
            inject_headers=_bearer_headers("cohere"),
        ),
        "replicate": ProviderRule(
            name="replicate",
            upstream_base_url="https://api.replicate.com",
            inject_headers=_replicate_headers,
        ),
        "azure_openai": ProviderRule(
            name="azure_openai",
            upstream_base_url=azure_endpoint,
            inject_headers=_azure_openai_headers,
            # Azure echoes the api-key in some error responses;
            # strip ``api-key`` from worker requests on top of the
            # default Bearer/x-api-key set so the dispatcher's
            # injected value isn't shadowed.
            strip_request_headers=(
                "authorization", "x-api-key", "x-goog-api-key",
                "api-key", "openai-organization",
            ),
        ),
    }

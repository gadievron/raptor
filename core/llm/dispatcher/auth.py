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
import sys
from dataclasses import dataclass
from pathlib import Path
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

    The launcher may also call :func:`seed_from_config` after
    constructing the store to fill any provider slots that env
    didn't supply, from ``~/.config/raptor/models.json``. Env-set
    keys are preserved (the seed only fills ``None`` slots).
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
        """Set or clear one provider's key.

        Used by tests, and by :func:`seed_from_config` to fill slots
        from ``models.json``. No other production caller touches this.
        """
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


def seed_from_config(store: CredentialStore) -> None:
    """Fill empty slots in *store* from ``~/.config/raptor/models.json``.

    The ``CredentialStore`` reads API keys from env at construction.
    Operators who instead keep their keys in ``models.json`` (the
    documented UX that the startup banner advertises with
    ``via models.json``) would otherwise see a configured-looking
    system that still 503s every request — the proxy has no creds to
    inject.

    The launcher calls this after constructing the store, before
    handing it to ``LLMDispatcher(..., creds=...)``. Env-supplied keys
    always win: only slots where ``store.get(provider) is None`` are
    filled, so an explicit env override of a ``models.json`` entry is
    preserved.

    Path resolution matches ``core/llm/detection.py:_read_config_models``:
    ``$RAPTOR_CONFIG`` if set, else ``~/.config/raptor/models.json``.

    Silent on file-missing, parse-error, or schema-error — same posture
    as the rest of the config-reading path. A misconfigured file looks
    the same as no file at all and surfaces later as the dispatcher's
    own ``503 provider not configured``.
    """
    try:
        from core.json import load_json_with_comments
    except ImportError:
        return

    config_path_str = os.environ.get("RAPTOR_CONFIG")
    if config_path_str:
        config_path = Path(config_path_str).expanduser().resolve()
    else:
        config_path = Path.home() / ".config" / "raptor" / "models.json"

    # Permission posture warning: models.json carries API keys when the
    # operator uses the inline ``api_key`` field. World-readable mode
    # (any of ``0o004`` / ``0o040`` / group-readable on a multi-user
    # box) means another local UID can grep the file. We don't *refuse*
    # to load — that would be a footgun on systems where umask sets
    # 0o644 and the operator didn't notice — but log once at WARNING so
    # the operator can ``chmod 600`` it. Skip on Windows where POSIX
    # bits don't have the same meaning.
    if sys.platform != "win32":
        try:
            st = config_path.stat()
            if st.st_mode & 0o077:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "models.json at %s is mode %04o — contains API keys "
                    "when populated inline. Consider `chmod 600 %s`.",
                    config_path, st.st_mode & 0o777, config_path,
                )
        except OSError:
            # Missing file / unreadable: load_json_with_comments below
            # will handle the "missing" case (returns None) and the
            # operator hits the "no key configured" path naturally.
            pass

    data = load_json_with_comments(config_path)
    if data is None:
        return

    if isinstance(data, dict):
        entries = data.get("models") or []
    elif isinstance(data, list):
        entries = data
    else:
        return
    if not isinstance(entries, list):
        return

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        provider = entry.get("provider")
        api_key = entry.get("api_key")
        if not isinstance(provider, str) or not isinstance(api_key, str):
            continue
        # Env wins: only fill empty slots. Also handles the duplicate-
        # provider case (operator lists two gemini entries for different
        # roles, same key) — first match seeds, rest are no-ops.
        if store.get(provider) is None:
            store.set(provider, api_key)

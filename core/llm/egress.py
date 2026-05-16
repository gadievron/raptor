"""Route in-process LLM SDK calls (anthropic, openai, google-genai)
through RAPTOR's existing in-process egress proxy.

Why this exists
---------------
``packages/llm_analysis/cc_dispatch.py`` already routes the Claude Code
subprocess through the in-process proxy (``use_egress_proxy=True,
proxy_hosts=["api.anthropic.com"]``). The OTHER LLM consumers — direct
in-process SDK calls used by /agentic external-LLM dispatch, /codeql's
autonomous_analyzer, etc. — have historically gone direct, with no
chokepoint to enforce hostname allowlist or surface egress for audit.

This module closes that gap by setting ``HTTPS_PROXY`` in the parent
process env to point at the same in-process proxy CC already uses.
``httpx``-based SDKs (anthropic, openai, google-genai all use httpx
under the hood) honour the env var and route accordingly.

Hostname allowlist comes from ``LLMConfig`` itself — the operator's own
configured ``api_base`` per ``ModelConfig`` is the authoritative
source. Operators who route through LiteLLM proxy / corporate gateway
/ vLLM by setting ``api_base`` automatically get that hostname
allowlisted; defaults from :data:`PROVIDER_ENDPOINTS` cover the
unconfigured case.

No TLS interception
-------------------
The in-process proxy is a CONNECT-tunnel proxy: it sees host:port for
allowlist enforcement and audit logging, but never decrypts the
TLS body. So no CA injection is needed; SDK trust-store behaviour is
unchanged. Cert pinning is irrelevant. (TLS-intercepting MITM is the
separately-tracked /web feature.)

Subprocess interaction
----------------------
``RaptorConfig.get_safe_env()`` strips ``HTTPS_PROXY`` from subprocess
envs as a defence against env-injection attacks (a malicious target
repo's ``.claude/settings.json`` could otherwise redirect a CodeQL
build subprocess to an attacker proxy). That stripping is at a
DIFFERENT layer from this module — we set ``HTTPS_PROXY`` in the
parent process for the in-process LLM SDKs; subprocess builds do not
inherit it. The two co-exist cleanly.

Corporate-proxy chaining
------------------------
If the operator has ``HTTPS_PROXY=http://corp:8080`` set when RAPTOR
launches, the in-process proxy reads it at first-construction time and
chains through it for upstream connections. We MUST call
``get_proxy()`` BEFORE overwriting ``HTTPS_PROXY`` — otherwise the
proxy reads its own pointer and loops. Order is enforced in
:func:`enable_llm_egress`.

Process-wide effect on non-LLM HTTP callers
-------------------------------------------
Setting ``HTTPS_PROXY`` in ``os.environ`` affects every ``httpx`` /
``requests`` caller in the same process, not just the LLM SDKs we
intend to gate. Audit performed 2026-05-07:

  * ``core.startup.init._test_key`` — hits the LLM provider hosts
    (api.anthropic.com, api.openai.com, api.mistral.ai, ...). All in
    the allowlist (they're the configured providers). Tunneled
    through the chokepoint cleanly.
  * ``core.llm.detection.detect_llm_availability`` (Ollama) — hits
    ``localhost:11434``. Bypassed via the ``NO_PROXY`` augmentation
    so this still works.
  * ``core.sage.client`` (httpx.get on the configured SAGE URL) —
    default ``http://localhost:8090`` is bypassed via ``NO_PROXY``.
    For remote SAGE URLs, ``SageClient.__init__`` calls
    ``get_proxy([sage_host])`` to add the host to the in-process
    proxy's allowlist, so SAGE's health check + SDK calls flow
    through the same chokepoint cleanly.
  * ``packages.cve_diff`` — uses its own ``ResilientLLMClient`` that
    calls ``create_provider`` directly, never constructing
    ``LLMClient``, so this module's ``enable_llm_egress`` never
    fires for cve-diff. cve-diff retains direct egress.
  * ``core.git.clone`` — git runs as a sandboxed subprocess with
    its own sanitised env (``RaptorConfig.get_git_env()``); parent
    HTTPS_PROXY is not inherited.
"""

from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING, Set
from urllib.parse import urlparse

if TYPE_CHECKING:
    from .config import LLMConfig

logger = logging.getLogger(__name__)


# Static fallback for providers that bypass ``api_base`` because their
# native SDK hardcodes the base URL (Anthropic). Other providers go
# through ``PROVIDER_ENDPOINTS`` in :mod:`core.llm.model_data`.
_KNOWN_DEFAULTS = {
    "anthropic": "https://api.anthropic.com",
}


# Local-loop hosts that must NOT route through the chokepoint — Ollama
# / vLLM / LiteLLM-on-localhost loop back through the proxy and break
# its allowlist semantics for non-loopback callers.
_LOCAL_BYPASS = ("localhost", "127.0.0.1")


# Idempotency: once enabled in this process, repeated calls are no-ops
# beyond union-ing the allowlist on the singleton proxy. Tracks the
# port we set in HTTPS_PROXY so we don't re-overwrite an
# operator-supplied value.
_enabled = False


def derive_allowlist(config: "LLMConfig") -> Set[str]:
    """Walk ``config`` and extract the set of hostnames the in-process
    proxy must allow.

    For each ModelConfig (primary, fallbacks, specialized), pick the
    hostname from its ``api_base`` if set, else ``PROVIDER_ENDPOINTS``,
    else ``_KNOWN_DEFAULTS``. Returns ``set[str]`` of hostnames (host
    only, no scheme/port/path).

    Empty when no models are configured (e.g. CC-prep-only run, or
    autodetect found no provider). Caller treats empty as "don't
    bother enabling egress" — it's a no-op from the proxy's
    perspective.
    """
    from .model_data import PROVIDER_ENDPOINTS

    candidates: list = []
    if config.primary_model is not None:
        candidates.append(config.primary_model)
    candidates.extend(config.fallback_models or [])
    if config.specialized_models:
        candidates.extend(config.specialized_models.values())

    hosts: Set[str] = set()
    for model in candidates:
        if model is None:
            continue
        # Per-model api_base wins; otherwise fall back to provider
        # default. PROVIDER_ENDPOINTS first (what the SDK actually
        # uses), _KNOWN_DEFAULTS for native-SDK Anthropic which
        # bypasses api_base entirely.
        url = (
            getattr(model, "api_base", None)
            or PROVIDER_ENDPOINTS.get(getattr(model, "provider", None))
            or _KNOWN_DEFAULTS.get(getattr(model, "provider", None))
        )
        if not url:
            continue
        host = _hostname_of(url)
        if host:
            hosts.add(host)
    return hosts


def _hostname_of(url: str) -> str:
    """Extract the bare hostname (no port, no scheme, no path) from
    a URL. Returns empty string on parse failure."""
    try:
        parsed = urlparse(url)
    except (ValueError, TypeError):
        return ""
    # urlparse leaves ``hostname`` lowercased and port-stripped, which
    # is what allowlist comparison wants.
    return parsed.hostname or ""


def _is_loopback(host: str) -> bool:
    return host.lower() in _LOCAL_BYPASS


def _augment_no_proxy(existing: str) -> str:
    """Return a NO_PROXY value that includes ``localhost`` and
    ``127.0.0.1`` UNION-ed with whatever the operator already set.
    Order-preserving (operator entries first); de-duplicated."""
    parts = [p.strip() for p in (existing or "").split(",") if p.strip()]
    seen = {p.lower() for p in parts}
    for entry in _LOCAL_BYPASS:
        if entry.lower() not in seen:
            parts.append(entry)
            seen.add(entry.lower())
    return ",".join(parts)


def enable_llm_egress(config: "LLMConfig") -> None:
    """Wire LLM SDK calls through the in-process proxy.

    Idempotent: safe to call once per ``LLMClient`` instantiation; the
    first call brings up the proxy and mutates env, subsequent calls
    only union the allowlist.

    Order-critical: ``get_proxy()`` is invoked BEFORE we overwrite
    ``HTTPS_PROXY`` so the proxy reads operator-supplied upstream
    chain (corporate proxy autodetect) at first-construction time,
    not our self-pointer.

    No-op when ``config`` resolves to an empty allowlist (e.g. no
    models configured) — saves the proxy bring-up cost and avoids
    surprising env mutation in CC-only or autodetect-empty modes.
    """
    global _enabled

    allowlist = derive_allowlist(config)
    # Drop loopback hosts from the proxy allowlist — they bypass the
    # proxy entirely via NO_PROXY (set below). Adding them to the
    # allowlist would let an attacker register a localhost service
    # and have it reachable via the chokepoint, defeating the
    # isolation the chokepoint exists to provide.
    remote_hosts = {h for h in allowlist if not _is_loopback(h)}

    if not remote_hosts:
        # Nothing to chokepoint — Ollama-only, autodetect-empty, or
        # CC-only setups. Skip silently.
        return

    # Step 1: bring up / extend the in-process proxy. MUST happen
    # before we mutate HTTPS_PROXY so upstream-chain autodetect sees
    # the operator's value (if any), not our self-pointer.
    from core.sandbox.proxy import get_proxy
    proxy = get_proxy(list(remote_hosts))

    # Step 2: only mutate env on the first call. Subsequent
    # LLMClient constructors just union the allowlist via get_proxy
    # above; HTTPS_PROXY is already pointing where we want.
    if _enabled:
        return

    # Step 3: point HTTPS_PROXY at our in-process proxy so httpx-based
    # SDKs route through it. Honour http (not https) — the in-process
    # proxy is plain-HTTP-on-loopback (CONNECT to upstream is what
    # carries the TLS).
    os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy.port}"
    os.environ["https_proxy"] = os.environ["HTTPS_PROXY"]

    # Step 4: ensure local-loop hosts (Ollama, vLLM-localhost,
    # LiteLLM-localhost) bypass the chokepoint. Union with whatever
    # the operator already had so corporate ``NO_PROXY=internal.corp``
    # is preserved.
    existing = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    new_no_proxy = _augment_no_proxy(existing)
    os.environ["NO_PROXY"] = new_no_proxy
    os.environ["no_proxy"] = new_no_proxy

    _enabled = True
    logger.debug(
        "LLM egress enabled: HTTPS_PROXY=127.0.0.1:%d, allowlist=%s",
        proxy.port, sorted(remote_hosts),
    )


def _reset_for_tests() -> None:
    """Test-only helper: reset the module-level idempotency flag.
    Does NOT clear env vars or the singleton proxy — those are
    process-wide concerns the test fixture handles separately."""
    global _enabled
    _enabled = False


__all__ = [
    "derive_allowlist",
    "enable_llm_egress",
]

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

This module closes that gap by setting ``HTTPS_PROXY`` — and
``HTTP_PROXY``, so plain ``http://`` endpoints cannot slip past the
chokepoint by consulting the un-set variable — in the parent process
env to point at the same in-process proxy CC already uses.
``httpx``-based SDKs (anthropic, openai, google-genai all use httpx
under the hood) honour the env vars and route accordingly.

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
    ``LLMClient``. Its provider construction calls
    :func:`enable_llm_egress_for_model` for the direct-SDK lane, which
    applies this module's chokepoint and additionally registers
    cve-diff's own fixed fetch hosts (OSV, NVD, GitHub API, distro
    security trackers) on the proxy allowlist so the package's
    proxy-env-honouring ``UrllibClient`` lanes keep working once
    ``HTTPS_PROXY`` points at the chokepoint. Dispatcher-routed calls
    (``RAPTOR_LLM_SOCKET``) skip this — the UDS dispatcher is its own
    chokepoint.
  * ``core.git.clone`` — git runs as a sandboxed subprocess with
    its own sanitised env (``RaptorConfig.get_git_env()``); parent
    HTTPS_PROXY is not inherited.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
from typing import TYPE_CHECKING, cast
from urllib.parse import urlparse

if TYPE_CHECKING:
    from collections.abc import Iterable

    from .config import LLMConfig, ModelConfig

logger = logging.getLogger(__name__)


# Static fallback for providers that bypass ``api_base`` because their
# native SDK hardcodes the base URL (Anthropic). Other providers go
# through ``PROVIDER_ENDPOINTS`` in :mod:`core.llm.model_data`.
_KNOWN_DEFAULTS = {
    "anthropic": "https://api.anthropic.com",
}


# Local-loop hosts that must NOT route through the chokepoint — Ollama
# / vLLM / LiteLLM-on-localhost loop back through the proxy and break
# its allowlist semantics for non-loopback callers. ::1 and 0.0.0.0
# included: operators point clients at "0.0.0.0:11434" surprisingly
# often (copy-pasted from the server's bind address), and it
# genuinely resolves to loopback on connect (kernel routes 0.0.0.0 to
# the local host), so it carries no extra reach.
#
# 169.254.169.254 (EC2 IMDS) is deliberately NOT here: it is a
# credential-bearing metadata service, not a local service. Listing
# it made every _LOCAL_BYPASS consumer treat IMDS as loopback-safe —
# url_is_loopback()/loopback_safe_get() would fetch it DIRECT and the
# NO_PROXY augmentation exempted it from the chokepoint, so hostile
# in-process code could read role credentials without ever meeting
# the allowlist. The removal DOES affect botocore's role-credential
# fetch on proxied hosts: without a NO_PROXY exemption its link-local
# IMDS probes travel to the operator's HTTP(S)_PROXY and are denied
# there — that operational plane is served by _NO_PROXY_ONLY below,
# which never feeds the chokepoint bypass check.
_LOCAL_BYPASS = (
    "localhost", "127.0.0.1", "::1", "0.0.0.0",
)

# Operational NO_PROXY additions that are NOT chokepoint bypasses —
# link-local probes must never travel to an operator proxy (botocore's
# credential-chain resolution otherwise spams the proxy with denied
# PUT /latest/api/token + GET /latest/meta-data/... pairs on every
# resolution), but IMDS stays a DENIED chokepoint target because it
# is not in _LOCAL_BYPASS: _is_loopback()/url_is_loopback() still
# refuse it, and the in-process proxy's allowlist never carries it.
_NO_PROXY_ONLY = (
    "169.254.169.254",
)


# Idempotency: once enabled in this process, repeated calls are no-ops
# beyond union-ing the allowlist on the singleton proxy. Tracks the
# port we set in HTTPS_PROXY so we don't re-overwrite an
# operator-supplied value.
_enabled = False

# The proxy env exactly as the operator had it before enable_llm_egress
# mutated os.environ (None = never mutated). Consumers that spawn
# trusted egress-needing subprocesses (the claude CLI transport) must
# hand children the OPERATOR's route, not our in-process loopback
# pointer — the in-process proxy's allowlist is derived from the
# SDK-model config and doesn't cover whatever backend the child CLI
# resolves for itself (e.g. Bedrock).
_PROXY_VAR_NAMES = (
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
    "http_proxy", "https_proxy", "no_proxy", "all_proxy",
)
_original_proxy_env: dict[str, str] | None = None

# Serialises the enable/disable state transitions. Without it, two
# first-callers racing enable_llm_egress can both pass the
# ``_original_proxy_env is None`` check-then-act, and the loser
# snapshots the ALREADY-REWRITTEN loopback pointer as the "operator"
# proxy env — poisoning every trusted-subprocess env later derived
# from operator_proxy_env().
_STATE_LOCK = threading.Lock()

# Fail-closed opt-in for chokepoint bring-up (shared toggle spellings
# via ``core.config.env_flag``). Bring-up deliberately fails OPEN by
# default — an LLM run must not die because a loopback port could not
# be bound — but operators who run RAPTOR for the allowlist + audit
# guarantees can set this so a bring-up failure aborts instead of
# silently downgrading every in-process SDK call to direct outbound.
EGRESS_STRICT_ENV = "RAPTOR_LLM_EGRESS_STRICT"

# One stderr notice per process for the fail-open downgrade. The
# logger and telemetry records repeat per failed bring-up attempt;
# the operator-surface print carries the same fact every time, so a
# single line suffices. Guarded by _STATE_LOCK.
_degraded_notice_printed = False

# Same once-per-process rule for the post-bring-up extra-host
# registration failure (a distinct fact: the chokepoint stays live and
# only the caller's extra fetch hosts fail closed). Guarded by
# _STATE_LOCK.
_extra_host_notice_printed = False


class LLMEgressBringupError(RuntimeError):
    """Egress chokepoint bring-up failed while ``RAPTOR_LLM_EGRESS_STRICT``
    is set — the run aborts rather than proceeding with direct,
    un-allowlisted outbound."""


def operator_proxy_env() -> dict[str, str]:
    """Proxy vars as the operator set them at launch.

    Returns the pre-``enable_llm_egress`` snapshot when this process
    has mutated proxy env, else the live values. Hosts with no proxy
    configured get an empty dict.
    """
    if _original_proxy_env is not None:
        return dict(_original_proxy_env)
    return {
        k: v for k in _PROXY_VAR_NAMES
        if (v := os.environ.get(k)) is not None
    }


def derive_allowlist(config: LLMConfig) -> set[str]:
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

    hosts: set[str] = set()
    for model in candidates:
        if model is None:
            continue
        if getattr(model, "provider", None) == "bedrock":
            # Bedrock has no static endpoint — the host is
            # region-derived per surface, and credential refresh
            # (assume-role / SSO) additionally needs STS.  Without
            # these the dispatcher's outbound would be denied by the
            # very proxy this module installs.
            hosts.update(_bedrock_hosts_for(model))
            continue
        # Per-model api_base wins; otherwise fall back to provider
        # default. PROVIDER_ENDPOINTS first (what the SDK actually
        # uses), _KNOWN_DEFAULTS for native-SDK Anthropic which
        # bypasses api_base entirely.
        url = (
            getattr(model, "api_base", None)
            or PROVIDER_ENDPOINTS.get(getattr(model, "provider", None) or "")
            or _KNOWN_DEFAULTS.get(getattr(model, "provider", None) or "")
        )
        if not url:
            continue
        host = _hostname_of(url)
        if host:
            hosts.add(host)
    return hosts


def _bedrock_hosts_for(model) -> set[str]:
    """Hosts one Bedrock ModelConfig needs through the egress proxy:
    the surface endpoint for its resolved region, plus the STS hosts
    botocore's credential refresh uses (global + regional endpoints —
    botocore defaults to regional STS).

    Region ladder mirrors the signer: the entry's pin → env → the
    profile's configured region via the botocore chain (no-network
    lookup).  When no region resolves, only the endpoint-override host
    (if any) is returned — the dispatcher will 503 the request with
    its own no-region diagnostic; a guessed host here would just mask
    that with a proxy denial for the wrong hostname.
    """
    endpoint_override = os.environ.get("AWS_ENDPOINT_URL_BEDROCK")
    if endpoint_override:
        # The override replaces the SURFACE endpoint only — botocore
        # still refreshes profile/role credentials through STS, so
        # the STS hosts must ride the allowlist too or every
        # credential refresh 503s at the chokepoint. Global STS
        # always; regional STS when a region resolves (botocore
        # defaults to regional endpoints).
        host = _hostname_of(endpoint_override)
        hosts = {host} if host else set()
        if hosts:
            hosts.add("sts.amazonaws.com")
            region = _bedrock_region_for(model)
            if region:
                hosts.add(f"sts.{region}.amazonaws.com")
        return hosts
    region = _bedrock_region_for(model)
    if not region:
        return set()
    surface = getattr(model, "bedrock_api", "mantle") or "mantle"
    if surface == "runtime":
        endpoint_host = f"bedrock-runtime.{region}.amazonaws.com"
    else:
        endpoint_host = f"bedrock-mantle.{region}.api.aws"
    return {
        endpoint_host,
        "sts.amazonaws.com",
        f"sts.{region}.amazonaws.com",
    }


def _bedrock_region_for(model) -> str | None:
    """Resolved AWS region for *model*: entry pin → env → the
    profile's configured region via the botocore chain (no-network
    lookup). ``None`` when nothing resolves."""
    region = (
        getattr(model, "aws_region", None)
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
    )
    if not region:
        try:
            import botocore.session
            session = botocore.session.Session(
                profile=getattr(model, "aws_profile", None)
                or os.environ.get("RAPTOR_BEDROCK_PROFILE")
                or os.environ.get("AWS_PROFILE"),
            )
            region = session.get_config_variable("region")
        except Exception:  # noqa: BLE001 — botocore optional here
            region = None
    return region or None


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
    from ipaddress import ip_address
    h = host.lower().strip().strip("[]")
    if h in _LOCAL_BYPASS:
        return True
    # Only IP LITERALS earn the loopback classification. The previous
    # substring test (``startswith("127.")``) also matched HOSTNAMES
    # like ``127.attacker.example``, which were then fetched DIRECT —
    # past the operator proxy and the chokepoint allowlist. Parse
    # first (same shape as detection.py's ``_host_is_local``); names
    # that merely look loopback-ish take the normal proxy path, and
    # ``is_loopback`` covers all of 127.0.0.0/8 plus IPv6 ``::1``.
    try:
        return ip_address(h).is_loopback
    except ValueError:
        return False


def url_is_loopback(url: str) -> bool:
    """True when ``url``'s host is a loopback / local-bind address."""
    from urllib.parse import urlsplit
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return False
    return _is_loopback(host)


def is_local_inference(provider: str, api_base: str | None = None) -> bool:
    """True when (provider, api_base) points at a local inference server.

    Covers ollama (always local — even a remote GPU box via OLLAMA_HOST
    shares a single server) and any provider whose api_base resolves to a
    loopback address (vLLM, LM Studio, llama.cpp — typically provider
    ``openai`` with a custom api_base).
    """
    if (provider or "").lower() == "ollama":
        return True
    if api_base:
        return url_is_loopback(api_base)
    return False


def loopback_safe_get(url: str, timeout: float):
    """``requests.get`` that bypasses proxy env for loopback targets.

    On mandatory-proxy hosts whose NO_PROXY doesn't cover loopback
    (common: only the cloud metadata IP is listed), a plain
    ``requests.get("http://localhost:11434/...")`` routes through the
    corporate proxy and fails — Ollama then looks "not running" even
    though it's up. Non-loopback URLs keep full proxy-env behaviour.
    """
    import requests
    if url_is_loopback(url):
        with requests.Session() as s:
            s.trust_env = False
            return s.get(url, timeout=timeout)
    return requests.get(url, timeout=timeout)


def loopback_safe_post(url: str, *, json: dict, timeout: float):
    """``requests.post`` that bypasses proxy env for loopback targets."""
    import requests
    if url_is_loopback(url):
        with requests.Session() as s:
            s.trust_env = False
            return s.post(url, json=json, timeout=timeout)
    return requests.post(url, json=json, timeout=timeout)


def _max_model_timeout(config: LLMConfig) -> float:
    """Return the longest per-model timeout across all configured models."""
    candidates = []
    if config.primary_model is not None:
        candidates.append(config.primary_model)
    candidates.extend(config.fallback_models or [])
    if config.specialized_models:
        candidates.extend(config.specialized_models.values())
    timeouts = [
        getattr(m, "timeout", 120)
        for m in candidates
        if m is not None
    ]
    return float(max(timeouts)) if timeouts else 300.0


def _augment_no_proxy(existing: str) -> str:
    """Return a NO_PROXY value that includes ``localhost`` and
    ``127.0.0.1`` (plus the operational-only :data:`_NO_PROXY_ONLY`
    entries) UNION-ed with whatever the operator already set.
    Order-preserving (operator entries first); de-duplicated."""
    return _union_no_proxy(existing, _LOCAL_BYPASS + _NO_PROXY_ONLY)


def augment_child_no_proxy(value: str) -> str:
    """Append the operational-only NO_PROXY entries (IMDS) to a child
    process's NO_PROXY value.

    For consumers that hand a child the OPERATOR's proxy env (e.g.
    ``cc_subprocess_env`` restoring ``operator_proxy_env()``): children
    that legitimately resolve their own credential chain would
    otherwise send their link-local IMDS probes through the operator
    proxy and be denied. Adds ONLY :data:`_NO_PROXY_ONLY` — loopback
    entries are the caller's decision — and never widens the
    chokepoint bypass (:func:`url_is_loopback` is unaffected).
    Order-preserving (existing entries first); de-duplicated."""
    return _union_no_proxy(value, _NO_PROXY_ONLY)


def _union_no_proxy(existing: str, additions: tuple[str, ...]) -> str:
    parts = [p.strip() for p in (existing or "").split(",") if p.strip()]
    seen = {p.lower() for p in parts}
    for entry in additions:
        if entry.lower() not in seen:
            parts.append(entry)
            seen.add(entry.lower())
    return ",".join(parts)


def enable_llm_egress(config: LLMConfig) -> None:
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

    Thread-safe: the enable transition is serialised by a module lock
    so concurrent first-callers cannot snapshot each other's loopback
    rewrite as the operator proxy env.
    """
    with _STATE_LOCK:
        _enable_llm_egress_locked(config)


def _enable_llm_egress_locked(config: LLMConfig) -> None:
    """Body of :func:`enable_llm_egress`; caller holds ``_STATE_LOCK``."""
    global _enabled, _original_proxy_env

    allowlist = derive_allowlist(config)
    # Drop loopback hosts from the proxy allowlist — they bypass the
    # proxy entirely via NO_PROXY (set below). Adding them to the
    # allowlist would let an attacker register a localhost service
    # and have it reachable via the chokepoint, defeating the
    # isolation the chokepoint exists to provide.
    remote_hosts = {h for h in allowlist if not _is_loopback(h)}

    if not remote_hosts:
        # Nothing to chokepoint — Ollama-only, autodetect-empty, or
        # CC-only setups. No proxy bring-up, no HTTPS_PROXY mutation.
        #
        # But the Ollama-only case is exactly the one that breaks on
        # mandatory-proxy hosts without NO_PROXY hygiene: the SDK's
        # httpx (trust_env=True) routes localhost:11434 through the
        # corporate proxy and every call fails. Pre-fix this early
        # return skipped the augmentation below for precisely the
        # config that needed it. Augment NO_PROXY (and ONLY NO_PROXY)
        # when the config references a loopback host and the operator
        # has a proxy set; truly-empty configs stay mutation-free.
        if allowlist and any(_is_loopback(h) for h in allowlist) and any(
            os.environ.get(v) for v in
            ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy")
        ):
            # Snapshot the operator's proxy env BEFORE this mutation
            # too — operator_proxy_env() must hand trusted
            # subprocesses the operator's NO_PROXY, not our augmented
            # one (pre-fix this path mutated without snapshotting, so
            # the snapshot taken later — or never — reflected our own
            # edit).
            if _original_proxy_env is None:
                _original_proxy_env = {
                    k: v for k in _PROXY_VAR_NAMES
                    if (v := os.environ.get(k)) is not None
                }
            existing = (os.environ.get("NO_PROXY")
                        or os.environ.get("no_proxy") or "")
            new_no_proxy = _augment_no_proxy(existing)
            os.environ["NO_PROXY"] = new_no_proxy
            os.environ["no_proxy"] = new_no_proxy
            logger.debug(
                "LLM egress: loopback-only config on proxied host — "
                "NO_PROXY augmented to %r (no chokepoint brought up)",
                new_no_proxy,
            )
        return

    # Step 1: bring up / extend the in-process proxy. MUST happen
    # before we mutate HTTPS_PROXY so upstream-chain autodetect sees
    # the operator's value (if any), not our self-pointer.
    #
    # Widen the proxy's per-tunnel idle timeout to the longest
    # per-model timeout in this config.  Thinking models (Gemini 2.5,
    # Claude with extended thinking) can be silent for minutes while
    # processing large prompts — the default 300s idle kills the
    # tunnel before the model responds.
    from core.sandbox.proxy import get_proxy
    max_model_timeout = _max_model_timeout(config)
    proxy = get_proxy(list(remote_hosts), idle_timeout=max_model_timeout)

    # Step 2: only mutate env on the first call. Subsequent
    # LLMClient constructors just union the allowlist via get_proxy
    # above; HTTPS_PROXY is already pointing where we want.
    if _enabled:
        return

    # Step 3: point HTTPS_PROXY at our in-process proxy so httpx-based
    # SDKs route through it. Honour http (not https) — the in-process
    # proxy is plain-HTTP-on-loopback (CONNECT to upstream is what
    # carries the TLS). Snapshot the operator's values first so
    # operator_proxy_env() can hand trusted subprocesses the real
    # route instead of our loopback pointer.
    #
    # HTTP_PROXY is pointed at the chokepoint too: a plain ``http://``
    # remote endpoint consults HTTP_PROXY, so leaving it unset let
    # exactly those calls connect DIRECT and bypass the hostname
    # allowlist entirely. The chokepoint is CONNECT-only, so
    # non-loopback plain-http calls now fail CLOSED at the proxy (400)
    # instead of escaping it — loopback endpoints (Ollama, local
    # vLLM/LiteLLM) are unaffected via the NO_PROXY augmentation in
    # Step 4.
    if _original_proxy_env is None:
        _original_proxy_env = {
            k: v for k in _PROXY_VAR_NAMES
            if (v := os.environ.get(k)) is not None
        }
    os.environ["HTTPS_PROXY"] = f"http://127.0.0.1:{proxy.port}"
    os.environ["https_proxy"] = os.environ["HTTPS_PROXY"]
    os.environ["HTTP_PROXY"] = os.environ["HTTPS_PROXY"]
    os.environ["http_proxy"] = os.environ["HTTPS_PROXY"]

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


def enable_llm_egress_or_degrade(config: LLMConfig) -> None:
    """:func:`enable_llm_egress` with the documented failure policy.

    Success is identical to calling :func:`enable_llm_egress`
    directly. On ANY bring-up failure (proxy bind, listener thread,
    allowlist derivation):

    * strict — ``RAPTOR_LLM_EGRESS_STRICT`` truthy — raise
      :class:`LLMEgressBringupError`: the run aborts rather than
      proceeding with direct, un-allowlisted outbound.
    * default — fail open, loudly: a WARNING log, an unconditional
      stderr notice (once per process) that bypasses any raised log
      floor (quiet CLI modes raise the floor past WARNING, which
      made the downgrade invisible exactly where it matters), and an
      ``egress_degraded`` record on the run's ``llm-telemetry.jsonl``
      so the downgrade is visible in run artifacts, not just
      scrollback.
    """
    try:
        enable_llm_egress(config)
    except Exception as exc:  # noqa: BLE001 — single policy boundary for any bring-up fault
        _handle_bringup_failure(exc)


def _handle_bringup_failure(exc: Exception) -> None:
    """Apply the strict-abort / loud-fail-open policy for *exc*."""
    global _degraded_notice_printed
    from core.config import env_flag
    from core.security.log_sanitisation import escape_nonprintable

    # Bring-up errors can carry env-derived text (proxy URLs, hostnames
    # from models config) — render inert and bound before any surface.
    detail = escape_nonprintable(str(exc))[:200]
    if env_flag(EGRESS_STRICT_ENV, False):
        raise LLMEgressBringupError(
            f"LLM egress proxy bring-up failed ({detail}) and "
            f"{EGRESS_STRICT_ENV} is set — aborting instead of "
            "falling back to direct, un-allowlisted outbound"
        ) from exc
    message = (
        f"LLM egress proxy bring-up failed ({detail}) — falling back "
        "to direct outbound. Allowlist enforcement disabled for this "
        f"run. Set {EGRESS_STRICT_ENV}=1 to abort instead."
    )
    logger.warning("%s", message)
    with _STATE_LOCK:
        first_notice = not _degraded_notice_printed
        _degraded_notice_printed = True
    if first_notice:
        # Operator surface, independent of logging configuration.
        print(f"WARNING: {message}", file=sys.stderr)
    from . import telemetry
    telemetry.emit(
        event="egress_degraded",
        call_class="egress",
        error=detail,
    )


def _handle_extra_host_registration_failure(
    exc: Exception, hosts: Iterable[str],
) -> None:
    """Strict-abort / loud policy for a failure AFTER successful
    bring-up: the chokepoint is live and allowlist enforcement remains
    active — only *hosts* failed to join the proxy allowlist, so the
    caller's own lanes to them fail closed at the chokepoint. Never
    claims an egress downgrade: outbound stays captured."""
    global _extra_host_notice_printed
    from core.config import env_flag
    from core.security.log_sanitisation import escape_nonprintable

    # Failure text and host names are env/config-derived — render
    # inert and bound before any surface.
    detail = escape_nonprintable(str(exc))[:200]
    affected = escape_nonprintable(
        ", ".join(sorted({h for h in hosts if h})))[:200] or "<none>"
    if env_flag(EGRESS_STRICT_ENV, False):
        raise LLMEgressBringupError(
            f"LLM egress chokepoint is active, but extra-host "
            f"registration failed ({detail}); affected hosts: "
            f"{affected}. {EGRESS_STRICT_ENV} is set — aborting"
        ) from exc
    message = (
        f"LLM egress chokepoint is active; allowlist enforcement "
        f"remains enabled. Extra-host registration failed ({detail}), "
        f"so caller lanes to these hosts fail closed at the "
        f"chokepoint: {affected}. Set {EGRESS_STRICT_ENV}=1 to abort "
        "instead."
    )
    logger.warning("%s", message)
    with _STATE_LOCK:
        first_notice = not _extra_host_notice_printed
        _extra_host_notice_printed = True
    if first_notice:
        # Operator surface, independent of logging configuration.
        print(f"WARNING: {message}", file=sys.stderr)
    from . import telemetry
    telemetry.emit(
        event="egress_extra_hosts_failed",
        call_class="egress",
        error=detail,
        hosts=affected,
    )


class _SingleModelView:
    """Duck-typed single-model stand-in for ``LLMConfig`` — exactly the
    three attributes :func:`derive_allowlist` and
    :func:`_max_model_timeout` read."""

    __slots__ = ("fallback_models", "primary_model", "specialized_models")

    def __init__(self, model: ModelConfig) -> None:
        self.primary_model = model
        self.fallback_models: list[ModelConfig] = []
        self.specialized_models: dict[str, ModelConfig] = {}


def enable_llm_egress_for_model(
    model: ModelConfig,
    extra_hosts: Iterable[str] = (),
) -> None:
    """Chokepoint entry for consumers that build ONE provider directly
    via ``create_provider`` instead of constructing ``LLMClient``
    (cve-diff's ``ResilientLLMClient``). Wraps *model* in a
    single-model view of ``LLMConfig`` and applies the same bring-up
    failure policy as :func:`enable_llm_egress_or_degrade` (strict
    abort / loud fail-open).

    ``extra_hosts`` are hostnames the CALLING PACKAGE's own direct
    HTTP lanes contact: enabling the chokepoint points ``HTTPS_PROXY``
    at the in-process proxy, which captures every proxy-env-honouring
    transport in the process — so the caller's non-LLM fetch hosts
    must join the proxy allowlist or those lanes fail closed at the
    chokepoint. They are registered only when the chokepoint has
    actually captured the proxy env (empty / loopback-only model
    configs stay mutation-free and need no allowlist widening);
    loopback entries are dropped, same as the model allowlist.

    A failure AFTER successful bring-up (extra-host registration) is
    handled separately: the chokepoint stays live with allowlist
    enforcement active, and the strict/loud policy reports exactly
    that — the caller's lanes to the affected hosts fail closed at
    the chokepoint; nothing falls back to direct outbound.
    """
    view = cast("LLMConfig", _SingleModelView(model))
    try:
        enable_llm_egress(view)
    except Exception as exc:  # noqa: BLE001 — single policy boundary for any bring-up fault
        _handle_bringup_failure(exc)
        return
    try:
        _register_extra_hosts(extra_hosts)
    except Exception as exc:  # noqa: BLE001 — same policy boundary, post-bring-up leg
        # Bring-up SUCCEEDED: the chokepoint is live and keeps
        # enforcing the model allowlist — nothing falls back to direct
        # outbound on this leg. Only the caller's extra fetch hosts
        # failed to join the allowlist, so those lanes fail closed at
        # the chokepoint. The degraded-bring-up handler's "falling
        # back to direct outbound" message would be the opposite of
        # the truth here.
        _handle_extra_host_registration_failure(exc, extra_hosts)


def _register_extra_hosts(hosts: Iterable[str]) -> None:
    """Union non-loopback *hosts* onto the in-process proxy allowlist,
    but only when the chokepoint has captured the proxy env — without
    the env capture the caller's lanes still take their operator-default
    route, and widening the allowlist would grant reach for nothing."""
    remote = sorted({h for h in hosts if h and not _is_loopback(h)})
    if not remote:
        return
    with _STATE_LOCK:
        if not _enabled:
            return
        from core.sandbox.proxy import get_proxy
        get_proxy(remote)


def _reset_for_tests() -> None:
    """Test-only helper: reset the module-level idempotency flag.
    Does NOT clear env vars or the singleton proxy — those are
    process-wide concerns the test fixture handles separately."""
    global _enabled, _original_proxy_env, _degraded_notice_printed, \
        _extra_host_notice_printed
    with _STATE_LOCK:
        _enabled = False
        _original_proxy_env = None
        _degraded_notice_printed = False
        _extra_host_notice_printed = False



def register_web_target(url: str) -> None:
    """Admit a web target to the active transport proxy before preflight."""
    from urllib.parse import urlsplit

    from core.http.hosts import canonical_transport_host

    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or "*" in parsed.hostname:
        raise ValueError("web target must be an HTTP(S) URL with an exact host")
    host = canonical_transport_host(parsed.hostname)
    if not host:
        raise ValueError("web target has an invalid host")
    with _STATE_LOCK:
        if _enabled:
            from core.sandbox.proxy import get_proxy
            get_proxy([host])


__all__ = [
    "EGRESS_STRICT_ENV",
    "LLMEgressBringupError",
    "augment_child_no_proxy",
    "derive_allowlist",
    "enable_llm_egress",
    "enable_llm_egress_for_model",
    "enable_llm_egress_or_degrade",
    "loopback_safe_get",
    "operator_proxy_env",
    "register_web_target",
    "url_is_loopback",
]

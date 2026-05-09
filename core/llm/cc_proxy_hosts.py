"""Sandbox policy for cc_dispatch sites — proxy-hosts allowlist
and readable-paths set.

Resolution layers (priority high → low):

  1. ``~/.config/raptor/cc-dispatch-proxy-hosts.json`` — operator
     override for corporate gateways, custom endpoints, or any
     topology not covered by env-var heuristics.
  2. Calibrated profile — when ``raptor-sandbox-calibrate`` has
     produced a fingerprint for the current Claude Code binary +
     env, prefer the auto-discovered values. Cache lives at
     ``~/.cache/raptor/sandbox-profiles/`` keyed by
     ``(sha256(realpath(claude_bin)), env_signature)``. The
     calibration probe is ``claude --version`` — captures
     filesystem reach reliably; proxy hostnames are populated only
     when a future probe variant exercises an actual API call.
     Empty values from the cache fall through to the next layer.
  3. Provider env vars — ``CLAUDE_CODE_USE_BEDROCK`` / ``USE_VERTEX``
     / ``USE_FOUNDRY``: each declares an alternative LLM-provider
     topology that needs different hostnames than the Anthropic API.
  4. Default — ``["api.anthropic.com"]`` for the standard Anthropic
     API; default readable-paths set covering the documented
     Claude Code install layout (``~/.local/bin``, ``~/.claude``,
     etc.).

The egress proxy itself enforces ``deny by default`` regardless of
what this module returns. If a future Claude Code version adds an
essential endpoint not in the resolved allowlist, cc_dispatch fails
visibly (not silently — the proxy denies, Claude Code can't reach
the new endpoint, the run errors out). Operators discover the gap
and update either via the override config, by re-running calibration
(``raptor-sandbox-calibrate --bin claude --force``), or by waiting
for a RAPTOR release that adds the host to the hardcoded fallback.

Threat model: calibration is a portability/drift-detection tool,
NOT a security feature. The probe runs the binary once with a
permissive policy — by the time we observe its behaviour, the
binary has already executed. Defense against malicious binary
updates lives upstream (signed installers, package-hash
verification). The static fallback layers are operator-trusted by
construction.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse


logger = logging.getLogger(__name__)


_OVERRIDE_CONFIG_PATH = Path.home() / ".config" / "raptor" / "cc-dispatch-proxy-hosts.json"


# Env vars that change which LLM provider Claude Code talks to. Used
# both for the env-var heuristics in the static fallback AND for the
# calibrate cache-key (``env_signature``) so a binary used with vs
# without ``CLAUDE_CODE_USE_BEDROCK`` produces distinct profiles.
_PROVIDER_ENV_KEYS: tuple[str, ...] = (
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "ANTHROPIC_BASE_URL",
    "AZURE_OPENAI_ENDPOINT",
    "AWS_REGION",
    "AWS_DEFAULT_REGION",
    "CLOUD_ML_REGION",
    "VERTEX_LOCATION",
)


# Default readable_paths set — what Claude Code legitimately needs
# to authenticate + load itself. Probe-derived in the original
# threat-model session; calibration would refine these per
# operator's actual install layout, but the default stays correct
# for the vanilla `npm install -g claude-code` install path.
def _default_readable_paths() -> list[str]:
    home = Path.home()
    return [
        str(home / ".local" / "bin"),
        str(home / ".local" / "share" / "claude"),
        str(home / ".claude"),
        str(home / ".claude.json"),
    ]


# Opt-in env var: when set to "1" AND an Anthropic API key is
# available, calibration uses a real ``claude -p`` probe that
# networks. The default ``--version`` probe captures filesystem
# reach but produces empty proxy_hosts — operators who want the
# calibrated proxy_hosts to actually populate (and catch new
# Anthropic endpoints / Bedrock regions / Foundry deployments
# the static fallback doesn't know about) flip this on.
#
# Why opt-in: ``claude -p`` consumes tokens. Even at the
# ``--max-budget-usd 0.01`` cap below, an operator running RAPTOR
# in CI without expecting API charges shouldn't be billed silently.
# The cache amortises the cost — once-per-(binary-sha + env-sig)
# is typically once per Claude Code self-update cycle (weeks).
_NETWORK_PROBE_OPT_IN_ENV = "RAPTOR_CC_CALIBRATE_NETWORK_PROBE"


def _network_probe_enabled() -> bool:
    """True when the operator opted in to the network-engaging
    probe AND an Anthropic API key is set.

    Without an API key the network probe would just hit the proxy
    once and fail auth — the proxy_hosts capture still works
    (the kext logs the CONNECT regardless), but the operator
    might not realise they need the key to keep tokens flowing.
    Falling back to ``--version`` in that case avoids the
    surprise.
    """
    if os.environ.get(_NETWORK_PROBE_OPT_IN_ENV) != "1":
        return False
    # Either ANTHROPIC_API_KEY (direct) or the alternative-provider
    # vars suffice — Bedrock / Vertex / Foundry have their own auth
    # paths and ``claude -p`` reaches them when configured.
    if os.environ.get("ANTHROPIC_API_KEY"):
        return True
    if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
        return True
    if os.environ.get("CLAUDE_CODE_USE_VERTEX"):
        return True
    if os.environ.get("CLAUDE_CODE_USE_FOUNDRY"):
        return True
    return False


def _cc_probe_args() -> tuple[str, ...]:
    """Argv for the calibration probe. Network-engaging variant
    when opted in; ``--version`` otherwise.

    The network probe argv:
      * ``-p "READY"`` — minimal prompt; our controlled string so
        no prompt-injection vector (see THREAT_MODEL.md).
      * ``--max-budget-usd 0.01`` — hard cap. A broken/looping
        probe can't drain the operator's account.
      * ``--max-turns 1`` — single tool-use round; rules out
        runaway agentic loops.
    """
    if _network_probe_enabled():
        return ("-p", "READY", "--max-budget-usd", "0.01",
                "--max-turns", "1")
    return ("--version",)


def _load_override_config() -> Optional[list[str]]:
    """Load the operator's override list, or None if not configured.

    Schema:
        {"proxy_hosts": ["api.example.com", "..."]}

    Future fields can be added (commit history will record schema
    evolution). Unknown fields are tolerated.
    """
    if not _OVERRIDE_CONFIG_PATH.exists():
        return None
    try:
        data = json.loads(_OVERRIDE_CONFIG_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    hosts = data.get("proxy_hosts") if isinstance(data, dict) else None
    if not isinstance(hosts, list):
        return None
    # Sanitise: strip non-string entries, dedupe, preserve order
    seen: set[str] = set()
    result: list[str] = []
    for h in hosts:
        if isinstance(h, str) and h and h not in seen:
            seen.add(h)
            result.append(h)
    return result or None


def _bedrock_hosts() -> list[str]:
    region = (
        os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    return [
        # LLM endpoint, region-pinned
        f"bedrock-runtime.{region}.amazonaws.com",
        # AWS STS for credential refresh; required by AWS SDK auth flow
        "sts.amazonaws.com",
    ]


def _vertex_hosts() -> list[str]:
    location = (
        os.environ.get("CLOUD_ML_REGION")
        or os.environ.get("VERTEX_LOCATION")
        or "us-central1"
    )
    return [
        # Global Vertex endpoint
        "aiplatform.googleapis.com",
        # Regional Vertex endpoint (Claude SDK uses this for regional models)
        f"aiplatform.{location}.rep.googleapis.com",
        # Google OAuth token refresh
        "oauth2.googleapis.com",
    ]


def _foundry_hosts() -> Optional[list[str]]:
    """Azure OpenAI / Foundry hosts. Endpoint is per-deployment so we
    derive it from the operator-supplied URL env var. Returns None
    when the URL is missing or unparseable — caller should treat as
    misconfigured and fall back."""
    endpoint = (
        os.environ.get("ANTHROPIC_BASE_URL")
        or os.environ.get("AZURE_OPENAI_ENDPOINT")
    )
    if not endpoint:
        return None
    host = urlparse(endpoint).hostname
    if not host:
        return None
    return [
        host,
        # Azure AD token refresh
        "login.microsoftonline.com",
    ]


# Per-process memoisation: calibration loads a cached profile (or
# re-runs the probe on cache miss / binary mutation). For dispatch
# patterns where cc_dispatch is called many times in a single RAPTOR
# session — agentic_passes' /understand prepass + /validate postpass
# fire dozens of cc_dispatch invocations — re-stat'ing the binary +
# re-reading the cache file every call adds avoidable overhead.
# Memoise the result per claude_bin path; invalidate by clearing
# the dict (mostly used in tests). Production callers don't need
# to invalidate during normal operation — sha256 verification on
# load handles binary self-update.
_CALIBRATED_CACHE: dict[str, "object"] = {}


def _resolve_claude_bin() -> Optional[str]:
    """Locate the Claude Code binary on PATH. Returns None when
    not found (calibration disabled for that run; static fallback
    layers still apply).
    """
    return shutil.which("claude")


def _calibrated_profile(claude_bin: Optional[str] = None):
    """Load (or trigger calibration of) a SandboxProfile for the
    target Claude Code binary + provider env. Returns None when
    calibration is unavailable (binary missing, observe-mode
    prerequisites missing, exception during probe).

    Args:
        claude_bin: explicit binary path. When None, falls back to
            PATH lookup via ``shutil.which("claude")``. cc_dispatch
            sites pass the same path they'll spawn, so calibration
            fingerprints EXACTLY what's about to run rather than
            "whatever happens to be on PATH" (which can differ on
            multi-version installs).

    Memoised per-process by binary path. The memoised entry is
    keyed on the resolved binary path; if Claude Code self-updates
    mid-session, the resolved path bumps and the memo misses,
    triggering a fresh load (which the calibrate cache handles
    via sha256 self-verification).
    """
    if claude_bin is None:
        claude_bin = _resolve_claude_bin()
    if claude_bin is None:
        return None
    if claude_bin in _CALIBRATED_CACHE:
        return _CALIBRATED_CACHE[claude_bin]

    try:
        from core.sandbox.calibrate import load_or_calibrate
    except ImportError:
        # Calibrate module isn't available on this build (older
        # checkouts, minimal containers). Disable calibration
        # gracefully — static layers carry the policy.
        _CALIBRATED_CACHE[claude_bin] = None
        return None

    try:
        # Probe args + cache-key env are derived together so the
        # cached profile invalidates cleanly when the operator
        # toggles the network-probe opt-in. Without including the
        # opt-in env var in the cache key, a profile calibrated
        # under ``--version`` (empty proxy_hosts) would be served
        # to a caller that just enabled network probing — and the
        # caller would never see the discovered hosts.
        probe_args = _cc_probe_args()
        env_keys = _PROVIDER_ENV_KEYS + (_NETWORK_PROBE_OPT_IN_ENV,)
        # Network probe wall-time empirically: ~110s on Claude Code
        # 2.1.138 with cold cache (auth + model-list + actual prompt
        # + streaming response + MCP setup + telemetry). 150s gives
        # headroom without unbounded hang risk; the AuditBudget cap
        # bounds record volume independently. The probe runs ONCE
        # per (binary-sha + env-sig) and the result is cached, so the
        # one-time cost amortises across every cc_dispatch call until
        # the binary self-updates.
        # ``--version`` probe finishes in <1s; 20s is generous.
        timeout = 150 if _network_probe_enabled() else 20
        profile = load_or_calibrate(
            claude_bin,
            probe_args=probe_args,
            env_keys=env_keys,
            timeout=timeout,
        )
    except (FileNotFoundError, RuntimeError, OSError) as exc:
        # Probe failed: ptrace blocked (Yama scope 3),
        # libseccomp absent on minimal containers, or the
        # binary was deleted between which() and probe. Log at
        # debug — calibration is opt-in / advisory, the static
        # fallback stays in place.
        logger.debug(
            "cc_proxy_hosts: calibration of %s failed (%s); "
            "falling back to static policy",
            claude_bin, exc,
        )
        _CALIBRATED_CACHE[claude_bin] = None
        return None

    _CALIBRATED_CACHE[claude_bin] = profile
    return profile


def _calibrated_proxy_hosts(
    claude_bin: Optional[str] = None,
) -> Optional[list[str]]:
    """Calibrated layer of proxy_hosts_for_cc_dispatch's resolution
    chain. Returns None when no calibrated profile exists OR the
    profile carries an empty proxy_hosts list (the default
    ``--version`` probe doesn't network, so this is the common
    case until a network-engaging probe variant lands)."""
    profile = _calibrated_profile(claude_bin)
    if profile is None or not profile.proxy_hosts:
        return None
    return list(profile.proxy_hosts)


def _calibrated_readable_paths(
    claude_bin: Optional[str] = None,
) -> Optional[list[str]]:
    """Calibrated layer of readable_paths_for_cc_dispatch's
    resolution chain. Returns the union of paths_read + paths_stat
    (probes that *check for* a file via stat() before deciding to
    open it still need read access in the Landlock policy — the
    sandbox blocks both reads and stats on paths outside the
    allowlist)."""
    profile = _calibrated_profile(claude_bin)
    if profile is None:
        return None
    union = list(dict.fromkeys(
        list(profile.paths_read) + list(profile.paths_stat),
    ))
    if not union:
        return None
    return union


def proxy_hosts_for_cc_dispatch(
    claude_bin: Optional[str] = None,
) -> list[str]:
    """Return the egress proxy hostname allowlist for a cc_dispatch
    invocation, given the current process env + operator config.

    Args:
        claude_bin: explicit Claude Code binary path. When provided,
            calibration fingerprints exactly that binary; when None,
            falls back to PATH lookup. cc_dispatch sites should
            pass the same value they'll spawn so the policy matches.

    Priority: override > calibrated profile > provider env vars >
    default Anthropic.
    """
    override = _load_override_config()
    if override is not None:
        return override

    calibrated = _calibrated_proxy_hosts(claude_bin)
    if calibrated is not None:
        return calibrated

    if os.environ.get("CLAUDE_CODE_USE_BEDROCK"):
        return _bedrock_hosts()
    if os.environ.get("CLAUDE_CODE_USE_VERTEX"):
        return _vertex_hosts()
    if os.environ.get("CLAUDE_CODE_USE_FOUNDRY"):
        foundry = _foundry_hosts()
        if foundry is not None:
            return foundry
        # Operator declared FOUNDRY but didn't set the endpoint URL —
        # fall through to Anthropic default rather than failing closed.
        # The actual LLM call to the Foundry endpoint will fail at the
        # proxy with a clear "host not in allowlist" log, which is
        # better diagnostics than silently allowing a different host.

    return list(_DEFAULT_ANTHROPIC_HOSTS)


# Static fallback for the standard Anthropic API path. Empirically
# derived from a real ``claude -p READY`` calibration probe against
# Claude Code 2.1.138 (see RAPTOR_CC_CALIBRATE_NETWORK_PROBE):
#   - api.anthropic.com         — load-bearing LLM endpoint
#   - mcp-proxy.anthropic.com   — MCP server proxy; gracefully
#                                  degrades when blocked but
#                                  functionality is lost
#   - downloads.claude.ai       — Claude Code self-update +
#                                  model-asset download
#
# ``http-intake.logs.us5.datadoghq.com`` is intentionally absent —
# Datadog telemetry is denied by RAPTOR policy. The proxy logs the
# CONNECT and Claude Code degrades gracefully without telemetry.
#
# Pre-2026-05-09 this list was just ``["api.anthropic.com"]``;
# Claude Code's reach has grown over versions and the calibration
# probe surfaced the gap. Operators who want the auto-discovered
# allowlist (catches future endpoint additions before they break
# in production) flip ``RAPTOR_CC_CALIBRATE_NETWORK_PROBE=1``.
_DEFAULT_ANTHROPIC_HOSTS: tuple[str, ...] = (
    "api.anthropic.com",
    "mcp-proxy.anthropic.com",
    "downloads.claude.ai",
)


def readable_paths_for_cc_dispatch(
    claude_bin: Optional[str] = None,
) -> list[str]:
    """Return the Landlock readable-paths set for a cc_dispatch
    invocation.

    Args:
        claude_bin: same semantics as
            ``proxy_hosts_for_cc_dispatch``. Calibration runs against
            this exact binary; static fallback engages on miss.

    Priority: calibrated profile > default install layout. Every
    path-using cc_dispatch site (cc_dispatch.invoke_cc_simple +
    agentic_passes' /understand prepass + /validate postpass)
    routes through this so per-binary calibration takes effect
    everywhere the policy matters.
    """
    calibrated = _calibrated_readable_paths(claude_bin)
    if calibrated is not None:
        return calibrated
    return _default_readable_paths()


def _reset_calibrate_cache_for_tests() -> None:
    """Clear the per-process memo. Public so tests can isolate
    runs without monkeypatching the dict directly."""
    _CALIBRATED_CACHE.clear()

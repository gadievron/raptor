"""Pre-flight probe for the claudecode transport.

Answers two questions the claudecode fallback otherwise guesses at:

1. **Liveness** — will a bare ``claude -p`` call actually complete on
   this install? Before this probe, ``raptor-resolve-mode`` committed
   to orchestrator mode whenever ``claude`` was on PATH; a
   misconfigured backend (Bedrock role without the model mapping, no
   proxy route) then hung every dispatch to the transport timeout.

2. **Model identity** — WHICH model does the CLI session resolve to?
   The transport deliberately omits ``--model`` (the
   ``session-default`` sentinel), so the true model is only knowable
   from a real call's result envelope (``modelUsage``). Operators and
   the scorecard want the real name, not the sentinel; worker-count
   heuristics can key on it later.

The probe is one cheap call (single-token-ish output, tight budget
cap) and the result is cached on disk keyed by the backend-selection
signature, so repeated resolve-mode invocations don't re-bill.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import time
from pathlib import Path

logger = logging.getLogger(__name__)

# RAPTOR_CC_PROBE_CACHE overrides the on-disk probe-cache location so
# tests and sandboxed runs can isolate it: the cached model identity
# feeds every LLMConfig construction via _resolve_claudecode_model, so
# a warm operator cache must be pinnable away from hermetic runs.
_CACHE_PATH = Path(
    os.environ.get("RAPTOR_CC_PROBE_CACHE")
    or Path.home() / ".raptor" / "cache" / "cc-probe.json"
)
_CACHE_TTL_S = 24 * 3600
_PROBE_TIMEOUT_S = 120
_PROBE_BUDGET_USD = "0.25"
_PROBE_PROMPT = "Reply with exactly: OK"

# Env vars that change which backend/model a bare ``claude -p``
# resolves — OR whether it can reach that backend at all (proxy
# route). The probe cache must not survive a change to any of them:
# a cached "alive" verdict under the old proxy env would keep
# vouching for a transport the new env may have broken (and vice
# versa — a fixed proxy shouldn't wait out a stale "dead" TTL).
_SIGNATURE_ENV = (
    "CLAUDE_CODE_USE_BEDROCK",
    "CLAUDE_CODE_USE_VERTEX",
    "CLAUDE_CODE_USE_FOUNDRY",
    "CLAUDE_CODE_USE_MANTLE",
    "ANTHROPIC_MODEL",
    "ANTHROPIC_BASE_URL",
    "AWS_PROFILE",
    "AWS_REGION",
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "no_proxy",
)


def _backend_signature(claude_bin: str) -> str:
    """Hash of everything that could change the resolved model."""
    from core.hash import sha256_string
    parts = [claude_bin]
    try:
        st = os.stat(claude_bin)
        parts.append(f"{st.st_mtime_ns}:{st.st_size}")
    except OSError:
        parts.append("unstat-able")
    for var in _SIGNATURE_ENV:
        parts.append(f"{var}={os.environ.get(var, '')}")
    settings = Path.home() / ".claude" / "settings.json"
    try:
        parts.append(f"settings:{settings.stat().st_mtime_ns}")
    except OSError:
        parts.append("settings:absent")
    return sha256_string("\0".join(parts))


def extract_model_from_envelope(envelope: dict) -> str | None:
    """Pick the main model out of a ``claude -p`` result envelope.

    ``modelUsage`` lists EVERY model that contributed to the turn —
    the reasoning model plus, sometimes, a smaller helper for
    tool-call summarisation. The main model is the one that produced
    the most output tokens; on a trivial probe prompt there is
    usually exactly one entry.
    """
    usage = envelope.get("modelUsage")
    if not isinstance(usage, dict) or not usage:
        return None

    def _out_tokens(entry) -> int:
        if isinstance(entry, dict):
            for key in ("outputTokens", "output_tokens"):
                val = entry.get(key)
                if isinstance(val, (int, float)):
                    return int(val)
        return 0

    return max(usage, key=lambda k: (_out_tokens(usage[k]), k))


def _read_cache(signature: str) -> str | None:
    try:
        data = json.loads(_CACHE_PATH.read_text())
    except (OSError, ValueError):
        return None
    if data.get("signature") != signature:
        return None
    if time.time() - data.get("timestamp", 0) > _CACHE_TTL_S:
        return None
    model = data.get("model")
    return model if isinstance(model, str) and model else None


def _write_cache(signature: str, model: str) -> None:
    try:
        _CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
        _CACHE_PATH.write_text(json.dumps({
            "signature": signature,
            "model": model,
            "timestamp": time.time(),
        }))
    except OSError:
        logger.debug("cc-probe: cache write failed", exc_info=True)


def cached_cc_session_model(claude_bin: str | None = None) -> str | None:
    """Cache-only read of the probe result — never bills, never blocks.

    For callers on the config-construction path (``LLMConfig`` builds
    happen inside orchestrator workers, CLI shims, tests) that want
    the backend-resolved model identity when it is already known but
    must not run a live ``claude -p`` call to learn it. The live
    probe stays in ``raptor-resolve-mode``, which runs before any
    orchestrator commits to the transport and warms this cache.
    """
    resolved_bin = claude_bin or shutil.which("claude")
    if not resolved_bin:
        return None
    return _read_cache(_backend_signature(resolved_bin))


def probe_cc_session_model(
    claude_bin: str | None = None,
    *,
    timeout_s: int = _PROBE_TIMEOUT_S,
    use_cache: bool = True,
) -> str | None:
    """Run (or recall) the pre-flight probe.

    Returns the backend-resolved model id (e.g.
    ``anthropic.claude-mythos-5``) on success, ``None`` when the CLI
    is missing, times out, exits non-zero, or produces no parseable
    envelope — i.e. ``None`` means "do not trust the claudecode
    transport on this install right now".
    """
    resolved_bin = claude_bin or shutil.which("claude")
    if not resolved_bin:
        return None

    signature = _backend_signature(resolved_bin)
    if use_cache:
        cached = _read_cache(signature)
        if cached is not None:
            return cached

    from core.llm.cc_adapter import cc_subprocess_env, neutral_cwd
    cmd = [
        resolved_bin, "-p",
        "--no-session-persistence",
        "--allowed-tools", "",
        "--max-budget-usd", _PROBE_BUDGET_USD,
        "--output-format", "json",
        "--strict-mcp-config", "--mcp-config", '{"mcpServers": {}}',
    ]
    try:
        proc = subprocess.run(
            cmd,
            input=_PROBE_PROMPT,
            env=cc_subprocess_env(),
            cwd=neutral_cwd(),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as e:
        logger.info("cc-probe: claude -p probe failed: %s", e)
        return None
    if proc.returncode != 0:
        logger.info(
            "cc-probe: claude -p exited %d during probe", proc.returncode,
        )
        return None

    model: str | None = None
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            envelope = json.loads(line)
        except ValueError:
            continue
        if isinstance(envelope, dict):
            found = extract_model_from_envelope(envelope)
            if found:
                model = found
    if model is None:
        logger.info("cc-probe: no modelUsage in probe envelope")
        return None

    if use_cache:
        _write_cache(signature, model)
    return model

"""Process-wide API-key + rate-limit status surface.

Surfaces two signals the user wants visible during long runs:

  * **API key presence** — which env vars are set? Missing keys silently
    cap throughput (GitHub 60/h unauth, NVD 5/30s unkeyed). Pre-flight
    banner makes it obvious before the run starts; users who care about
    speed will set the keys.

  * **Rate-limit events** — when an outbound HTTP call returns 429 / 403
    / 503, that's load shedding from a remote service. Counted per
    service so the end-of-run summary can say "GitHub 429: 12 events".

Callers register events; the CLI reads counts at the end. Thread-safe
because GitHub-client retry paths fire from worker processes.
"""
from __future__ import annotations

import os
import sys
import threading
from collections import defaultdict
from dataclasses import dataclass

_lock = threading.Lock()
_events: dict[str, dict[int, int]] = defaultdict(lambda: defaultdict(int))
# Per-function cache hit/miss counters. Populated by github_client (and
# any other callers wired via record_cache_hit / record_cache_miss).
# Per-process — under ProcessPoolExecutor each worker has its own
# functools.lru_cache and its own counters; the bench summary reports
# what each worker saw.
_cache_events: dict[str, dict[str, int]] = defaultdict(
    lambda: {"hits": 0, "misses": 0}
)


@dataclass(frozen=True)
class ApiKeySpec:
    name: str             # human label
    env_var: str          # env var to check
    when_missing: str     # one-line user-facing hint when unset
    optional: bool = False  # if True, "missing" is not a warning


_KEYS: tuple[ApiKeySpec, ...] = (
    ApiKeySpec(
        name="GitHub",
        env_var="GITHUB_TOKEN",
        when_missing="GitHub API limited to 60 req/h (vs 5000/h authed) — bench will hit 429s",
    ),
    ApiKeySpec(
        name="NVD",
        env_var="NVD_API_KEY",
        when_missing="NVD limited to 5 req/30s (vs 50/30s with key) — slower under -w 4",
        optional=True,
    ),
)


# LLM-auth status is rendered separately because cve-diff is now
# model-agnostic. We read the canonical env-var list from
# ``core.config.RaptorConfig.LLM_API_KEY_VARS`` so adding a new
# provider upstream automatically shows up in cve-diff's banner.
def _llm_provider_env_vars() -> tuple[str, ...]:
    """Pull the LLM-provider env-var list from the central config.

    Lazy/import-at-call-time so we don't fail to load
    ``api_status`` when ``core.config`` happens to be importable
    only in certain test scaffolds. On any failure, fall through
    to an empty list (banner just shows "no env vars configured").
    """
    try:
        from core.config import RaptorConfig
        return tuple(RaptorConfig.LLM_API_KEY_VARS)
    except Exception:
        return ()


def record_rate_limit(service: str, status: int) -> None:
    """Called by HTTP clients on 429/403/503 etc. ``service`` is a short
    label like ``"github"`` or ``"nvd"``; ``status`` is the HTTP code.
    Per-(service, status) counter; thread-safe."""
    with _lock:
        _events[service][status] += 1


def rate_limit_events() -> dict[str, dict[int, int]]:
    """Snapshot of accumulated rate-limit counts. Returns a deep copy
    so callers can iterate without holding the lock."""
    with _lock:
        return {svc: dict(counts) for svc, counts in _events.items()}


def reset_rate_limit_events() -> None:
    """Test/CLI helper — drop the accumulated counters."""
    with _lock:
        _events.clear()


def api_key_status() -> list[tuple[ApiKeySpec, bool]]:
    """Return [(spec, present), ...] in declaration order."""
    return [(s, bool(os.environ.get(s.env_var))) for s in _KEYS]


def llm_auth_status() -> tuple[bool, list[str], bool]:
    """Resolve the LLM-auth picture for startup-banner rendering.

    Returns ``(any_auth, configured_env_vars, via_dispatcher)``.
    ``configured_env_vars`` is the subset of
    ``RaptorConfig.LLM_API_KEY_VARS`` that's currently set in env.
    ``via_dispatcher`` reflects ``RAPTOR_LLM_SOCKET``.
    """
    via_dispatcher = bool(os.environ.get("RAPTOR_LLM_SOCKET"))
    configured = [v for v in _llm_provider_env_vars()
                  if os.environ.get(v)]
    # Claude Code OAuth fallback always authenticates Anthropic
    # models when the binary is on PATH; we treat that as
    # operator-facing "always available" rather than probing PATH
    # at startup.
    any_auth = via_dispatcher or bool(configured) or True  # CC fallback
    return any_auth, configured, via_dispatcher


def render_startup_banner() -> str:
    """Multi-line banner for the start of a `run` or `bench`.

    Lists each API key as set / missing with a hint when missing.
    LLM auth is reported separately because cve-diff is model-
    agnostic: any of the supported providers (or the credential-
    isolation dispatcher, or Claude Code OAuth) is a valid auth
    path. Always rendered."""
    lines = ["API keys:"]
    for spec, present in api_key_status():
        if present:
            lines.append(f"  ✓ {spec.name:<10} ({spec.env_var}) set")
        else:
            tag = "—" if spec.optional else "✗"
            lines.append(
                f"  {tag} {spec.name:<10} ({spec.env_var}) NOT set "
                f"— {spec.when_missing}"
            )

    # LLM auth — model-agnostic; show every configured env var plus
    # the dispatcher route. Operator with no provider key + no
    # dispatcher still has the Claude Code OAuth fallback for
    # Anthropic models, so the worst-case is "limited to claude-*".
    _, configured_vars, via_dispatcher = llm_auth_status()
    lines.append("LLM auth:")
    if via_dispatcher:
        lines.append(
            "  ✓ credential-isolation dispatcher "
            "(RAPTOR_LLM_SOCKET set — provider keys handled by "
            "dispatcher, not in worker env)"
        )
    if configured_vars:
        lines.append(
            f"  ✓ provider env vars set: {', '.join(configured_vars)}"
        )
    if not via_dispatcher and not configured_vars:
        lines.append(
            "  — no LLM provider env var and no dispatcher; cve-diff "
            "will fall back to Claude Code OAuth for Anthropic models. "
            "Set ANTHROPIC_API_KEY (cheapest), GEMINI_API_KEY, or any "
            "supported provider key to use --model with that family."
        )
    return "\n".join(lines)


def render_rate_limit_summary() -> str:
    """Multi-line summary of rate-limit events seen during the run.

    Empty string if no events. Otherwise one line per (service, status)
    so the user can tell which service shed load and how often."""
    snap = rate_limit_events()
    if not snap:
        return ""
    lines = ["Rate-limit events (HTTP 429 / 403 / 503):"]
    for svc in sorted(snap):
        for status in sorted(snap[svc]):
            lines.append(f"  {svc:<8}  http {status}: {snap[svc][status]} event(s)")
    return "\n".join(lines)


def print_to_stderr(text: str) -> None:
    """Convenience: emit ``text`` to stderr if non-empty."""
    if text:
        print(text, file=sys.stderr)


# --- cache hit/miss tracking (Action C) ---

def record_cache_hit(name: str) -> None:
    """Record a cache hit for ``name`` (e.g. ``"github_client.get_commit"``).
    Thread-safe; called from any worker."""
    with _lock:
        _cache_events[name]["hits"] += 1


def record_cache_miss(name: str) -> None:
    """Record a cache miss for ``name``. Thread-safe."""
    with _lock:
        _cache_events[name]["misses"] += 1


def cache_stats() -> dict[str, dict[str, int]]:
    """Snapshot of cache hit/miss counts. Deep copy so callers can
    iterate / mutate without holding the lock."""
    with _lock:
        return {name: dict(counts) for name, counts in _cache_events.items()}


def reset_cache_stats() -> None:
    """Test/CLI helper — drop the accumulated counters."""
    with _lock:
        _cache_events.clear()


def render_cache_summary() -> str:
    """Multi-line summary of cache hit/miss ratios per function.

    Empty string if no events. Otherwise one line per function with
    hits, misses, and a hit-ratio percentage so the user can see how
    much the in-process lru_cache saved them on the bench."""
    snap = cache_stats()
    if not snap:
        return ""
    lines = ["Cache hits / misses (per-process lru_cache):"]
    for name in sorted(snap):
        hits = snap[name]["hits"]
        misses = snap[name]["misses"]
        total = hits + misses
        ratio = (100.0 * hits / total) if total > 0 else 0.0
        lines.append(
            f"  {name:<32}  hits={hits:>5}  misses={misses:>5}  "
            f"hit_ratio={ratio:.1f}%"
        )
    return "\n".join(lines)

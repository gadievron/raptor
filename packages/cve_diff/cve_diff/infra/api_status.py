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
        name="Anthropic",
        env_var="ANTHROPIC_API_KEY",
        when_missing="agent runs will fail at first LLM call",
    ),
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


def render_startup_banner() -> str:
    """Multi-line banner for the start of a `run` or `bench`.

    Lists each API key as set / missing with a hint when missing. Always
    rendered (this addresses the user's "always, as part of the system"
    request — the cost is a few lines of stderr at startup)."""
    lines = ["API keys:"]
    for spec, present in api_key_status():
        if present:
            lines.append(f"  ✓ {spec.name:<10} ({spec.env_var}) set")
        else:
            tag = "—" if spec.optional else "✗"
            lines.append(f"  {tag} {spec.name:<10} ({spec.env_var}) NOT set — {spec.when_missing}")
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

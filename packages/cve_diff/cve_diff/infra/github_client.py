"""
Thin GitHub REST client for runtime repo-metadata and /languages lookups.

Wired by `discovery/repo_metadata.py` (pre-clone writeup-fork rejection) and
`diffing/shape_dynamic.py` (language-driven shape classification). Both
callers already tolerate ``None`` on any failure, so this module's only job is
to return ``dict | None`` per request and never raise for transport issues.

Transport: ``core.http.EgressClient`` (sandbox-aware, hostname-allowlisted to
``api.github.com``). Pre-rewire this module called ``requests.get`` directly,
which bypassed the egress proxy. Now every outbound request goes through
the same chokepoint as the rest of RAPTOR — refer to ``core/http/`` for the
backoff schedule, retry policy, and size caps.

Budget (caller-side, on top of the transport's own retry/backoff):
- 50 req/h unauth (GitHub's real cap is 60/h; leave headroom).
- 5000 req/h authed.
- 10s per-attempt timeout (``timeout=`` kwarg on ``get_json``) — matches the
  pre-rewire ``requests.get(timeout=10)`` semantics. ``total_timeout`` is
  left at its default so the retry loop has room to back off + retry once.
- ``retries=1`` so a 5xx hiccup gets one retry, then surfaces.
- Per-slug memoization with ``functools.lru_cache`` so a bench run hits each
  slug at most once per endpoint for the lifetime of the process.
"""

from __future__ import annotations

import functools
import os
import sys
import threading
from typing import Any, Callable, Optional


class _CacheInfo:
    """Minimal stand-in for ``functools.lru_cache``'s ``CacheInfo`` so
    callers using ``cache_info()`` (e.g. ``get_commit``'s hit/miss
    telemetry) keep working after the lru_cache → _cache_unless_none swap."""
    __slots__ = ("hits", "misses", "currsize")

    def __init__(self, hits: int, misses: int, currsize: int):
        self.hits = hits
        self.misses = misses
        self.currsize = currsize


def _cache_unless_none(func: Callable) -> Callable:
    """Memoise the function but DO NOT cache None results.

    `functools.lru_cache` caches every return value forever — including
    `None` from a transient 429/auth failure. After the rate limit
    refills, the cache still returns the poisoned `None` for the lifetime
    of the process. This wrapper stores only non-None hits and re-calls
    on cache miss for None.
    """
    cache: dict = {}
    cache_lock = threading.Lock()
    stats = {"hits": 0, "misses": 0}

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        key = args + tuple(sorted(kwargs.items()))
        with cache_lock:
            if key in cache:
                stats["hits"] += 1
                return cache[key]
            stats["misses"] += 1
        result = func(*args, **kwargs)
        if result is not None:
            with cache_lock:
                cache[key] = result
        return result

    def cache_clear() -> None:
        with cache_lock:
            cache.clear()
            stats["hits"] = 0
            stats["misses"] = 0

    def cache_info() -> _CacheInfo:
        with cache_lock:
            return _CacheInfo(stats["hits"], stats["misses"], len(cache))

    wrapper.cache_clear = cache_clear  # type: ignore[attr-defined]
    wrapper.cache_info = cache_info  # type: ignore[attr-defined]
    return wrapper

from core.http import HttpError
from core.http.egress_backend import EgressClient

from cve_diff.infra.rate_limit import TokenBucket

_UNAUTH_CAPACITY = 50
_AUTH_CAPACITY = 5000
_ONE_HOUR = 3600.0
_TIMEOUT_S = 10
_USER_AGENT = "cve-diff/0.1"
_GITHUB_HOSTS = frozenset({"api.github.com"})

_warned_token_missing = False
_warned_rate_limited = False
_warn_lock = threading.Lock()


def _token() -> str | None:
    tok = os.environ.get("GITHUB_TOKEN")
    return tok if tok else None


def warn_if_token_missing(echo=None) -> None:
    """Print a one-time stderr warning if GITHUB_TOKEN is unset.

    ``echo`` is injectable for tests; defaults to ``typer.echo(..., err=True)``
    if typer is importable, otherwise plain ``print(..., file=sys.stderr)``.
    """
    global _warned_token_missing
    with _warn_lock:
        if _warned_token_missing or _token() is not None:
            return
        _warned_token_missing = True

    msg = (
        "warn: GITHUB_TOKEN not set — GitHub API limited to 60 req/h unauth.\n"
        "      metadata scorer will SKIP for most candidates; wrong-repo\n"
        "      leakage may stay visible. set GITHUB_TOKEN to run with full\n"
        "      discrimination."
    )
    if echo is not None:
        echo(msg)
        return
    try:
        import typer
        typer.echo(msg, err=True)
    except ImportError:
        print(msg, file=sys.stderr)


def _warn_rate_limited(status: int) -> None:
    # Always count the event (per-status) for end-of-run summary.
    from cve_diff.infra import api_status
    api_status.record_rate_limit("github", status)
    # First-event warning to stderr (rest are silently counted).
    global _warned_rate_limited
    with _warn_lock:
        if _warned_rate_limited:
            return
        _warned_rate_limited = True
    print(
        f"warn: GitHub API returned {status} — further metadata calls will be skipped "
        f"this session. set/refresh GITHUB_TOKEN to recover.",
        file=sys.stderr,
    )


@functools.lru_cache(maxsize=1)
def _bucket() -> TokenBucket:
    capacity = _AUTH_CAPACITY if _token() else _UNAUTH_CAPACITY
    return TokenBucket(capacity=capacity, refill_per_second=capacity / _ONE_HOUR)


@functools.lru_cache(maxsize=1)
def _client() -> EgressClient:
    """Process-wide HTTP client pinned to ``api.github.com``.

    Cached so we reuse one urllib3 connection pool across the whole run —
    repeated calls to the same host avoid per-request TCP+TLS setup.
    EgressClient routes via ``core.sandbox.proxy``: hostname allowlist
    enforced on every CONNECT, anything outside ``_GITHUB_HOSTS`` is
    refused at the proxy layer.
    """
    return EgressClient(allowed_hosts=_GITHUB_HOSTS, user_agent=_USER_AGENT)


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get(url: str) -> Optional[dict[str, Any]]:
    """GET ``url`` against the GitHub API. Returns JSON dict or None.

    Returns None on any error (network, timeout, non-2xx). On 401/403/429
    we also log a single line and bump the api_status counter; the rest
    of the run keeps returning None for those statuses.

    Retry policy: ``retries=1`` lets EgressClient retry once on transient
    5xx / network errors. 4xx surfaces immediately as ``HttpError`` and
    we translate to None.
    """
    if not _bucket().try_acquire():
        return None
    try:
        data = _client().get_json(
            url,
            timeout=_TIMEOUT_S,
            headers=_headers(),
            retries=1,
        )
    except HttpError as e:
        if e.status in (401, 403, 429):
            _warn_rate_limited(e.status)
        return None
    return data if isinstance(data, dict) else None


@_cache_unless_none
def get_repo(slug: str) -> Optional[dict[str, Any]]:
    """``GET /repos/{slug}`` — fork/archived/stars/created_at/language/size."""
    if not slug or "/" not in slug:
        return None
    return _get(f"https://api.github.com/repos/{slug}")


@_cache_unless_none
def get_languages(slug: str) -> Optional[dict[str, Any]]:
    """``GET /repos/{slug}/languages`` — used by shape_dynamic."""
    if not slug or "/" not in slug:
        return None
    return _get(f"https://api.github.com/repos/{slug}/languages")


@_cache_unless_none
def commit_exists(slug: str, sha: str) -> Optional[bool]:
    """Return True if ``sha`` resolves in ``slug``, False on 404, None on skip.

    Used for commit-graph membership checks: if a fix_commit doesn't resolve
    in a candidate repo, that repo can't be the upstream (forks share SHAs
    with parents, so a 404 means the candidate is unrelated to the real
    upstream, not merely a fork).

    ``None`` is returned for auth failures / rate limits / network errors —
    the caller treats this as "can't tell" and applies no penalty.
    """
    if not slug or "/" not in slug or not sha:
        return None
    if not _bucket().try_acquire():
        return None
    try:
        _client().get_json(
            f"https://api.github.com/repos/{slug}/commits/{sha}",
            timeout=_TIMEOUT_S,
            headers=_headers(),
            retries=1,
        )
        return True
    except HttpError as e:
        if e.status in (404, 422):
            return False
        if e.status in (401, 403, 429):
            _warn_rate_limited(e.status)
        return None


@_cache_unless_none
def _get_commit_cached(slug: str, sha: str) -> Optional[dict[str, Any]]:
    """Inner cached implementation of ``get_commit``. Wrapped by the
    public ``get_commit`` so we can record hit/miss counters via
    ``api_status`` without losing lru_cache semantics."""
    if not slug or "/" not in slug or not sha:
        return None
    return _get(f"https://api.github.com/repos/{slug}/commits/{sha}")


def get_commit(slug: str, sha: str) -> Optional[dict[str, Any]]:
    """``GET /repos/{slug}/commits/{sha}`` — full commit body (files + parents).

    Memoized via ``_get_commit_cached`` so `get_commit_files` and the
    parallel ``extract_via_api`` cross-check share one HTTP round-trip.
    Hit/miss counters are recorded into ``api_status`` so the bench
    summary can show per-process cache effectiveness.

    Telemetry caveat: under ``ProcessPoolExecutor`` (bench's
    ``-w 4``) each worker has its own per-process ``functools.lru_cache``
    and counter — totals are aggregated across workers but per-worker
    counts can race. Within a single process there's also a small
    window between the two ``cache_info()`` reads where another thread
    could populate the cache; the resulting hit/miss attribution is
    still approximately correct over many calls and never worse than
    "miscounted by one" per race. The counters are informational
    (bench summary, not correctness-critical), so we accept the
    looseness rather than thread per-call locking.
    """
    info_before = _get_commit_cached.cache_info()
    result = _get_commit_cached(slug, sha)
    info_after = _get_commit_cached.cache_info()
    # Avoid the api_status import at module-load time (avoids a circular
    # path during startup; api_status is part of the same package).
    from cve_diff.infra import api_status
    if info_after.hits > info_before.hits:
        api_status.record_cache_hit("github_client.get_commit")
    else:
        api_status.record_cache_miss("github_client.get_commit")
    return result


def _files_from_commit(data: Optional[dict[str, Any]]) -> Optional[list[str]]:
    if data is None:
        return None
    files = data.get("files")
    if files is None:
        return []
    if not isinstance(files, list):
        return None
    out: list[str] = []
    for entry in files:
        if isinstance(entry, dict):
            name = entry.get("filename")
            if isinstance(name, str) and name:
                out.append(name)
    return out


def get_commit_files(slug: str, sha: str) -> Optional[list[str]]:
    """Return the list of changed filenames in ``sha``, or None on skip.

    Backs `commit_shape_score` — classifying the fix commit's actual diff by
    shape catches OSV's release-bump pattern (`ranges.events.fixed` points
    at a pom.xml / VERSION / gradle.properties bump rather than the code
    fix).

    ``None`` on auth failure / rate limit / 404 / network error. An empty
    list is returned as-is when GitHub reports no file changes; the scorer
    treats that as skip-worthy (rare but uninformative).
    """
    return _files_from_commit(get_commit(slug, sha))


def get_parent_commit_files(slug: str, sha: str) -> Optional[list[str]]:
    """Return the changed-files list of ``sha``'s first parent, or None.

    Backs `parent_chain_score`. First fetches the candidate commit (memoized
    with `get_commit`), extracts ``parents[0].sha``, then fetches the parent
    commit to pull its files. Returns None on any fetch failure, on a root
    commit (no parents), or on a merge commit whose mainline parent isn't
    resolvable — all treated as "can't tell" skips upstream.
    """
    commit = get_commit(slug, sha)
    if commit is None:
        return None
    parents = commit.get("parents") or []
    if not parents or not isinstance(parents, list):
        return None
    first = parents[0]
    if not isinstance(first, dict):
        return None
    parent_sha = first.get("sha")
    if not isinstance(parent_sha, str) or not parent_sha:
        return None
    return _files_from_commit(get_commit(slug, parent_sha))


def reset_for_tests() -> None:
    """Flush memoization + warning state. Tests only."""
    global _warned_token_missing, _warned_rate_limited
    # ``hasattr`` guard: tests may monkeypatch ``_client`` to a plain
    # function or stub that doesn't expose ``cache_clear``.
    for fn in (
        get_repo, get_languages, commit_exists,
        _get_commit_cached, _bucket, _client,
    ):
        if hasattr(fn, "cache_clear"):
            fn.cache_clear()
    _warned_token_missing = False
    _warned_rate_limited = False

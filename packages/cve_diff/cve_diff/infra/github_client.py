"""
Thin GitHub REST client for runtime repo-metadata and /languages lookups.

Wired by `discovery/repo_metadata.py` (pre-clone writeup-fork rejection) and
`diffing/shape_dynamic.py` (language-driven shape classification). Both
callers already tolerate ``None`` on any failure, so this module's only job is
to return ``dict | None`` per request and never raise for transport issues.

Budget:
- 50 req/h unauth (GitHub's real cap is 60/h; leave headroom).
- 5000 req/h authed.
- One retry on 5xx / timeout; no retry on 4xx.
- 10s per-request timeout.
- Per-slug memoization with ``functools.lru_cache`` so a bench run hits each
  slug at most once per endpoint for the lifetime of the process.
"""

from __future__ import annotations

import functools
import os
import sys
import threading
from typing import Any, Optional

import requests

from cve_diff.infra.rate_limit import TokenBucket

_UNAUTH_CAPACITY = 50
_AUTH_CAPACITY = 5000
_ONE_HOUR = 3600.0
_TIMEOUT_S = 10.0
_USER_AGENT = "cve-diff/0.1"

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


def _headers() -> dict[str, str]:
    h = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": _USER_AGENT,
    }
    tok = _token()
    if tok:
        h["Authorization"] = f"Bearer {tok}"
    return h


def _get(url: str) -> Optional[dict[str, Any]]:
    """GET ``url`` against the GitHub API. Returns JSON dict or None.

    One retry on 5xx/timeout. 4xx is a definitive None. On 401/403/429 we
    log a single line and then keep returning None for the rest of the run.
    """
    if not _bucket().try_acquire():
        return None

    for attempt in (1, 2):
        try:
            resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT_S)
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 1:
                continue
            return None

        status = resp.status_code
        if status == 200:
            try:
                data = resp.json()
            except ValueError:
                return None
            return data if isinstance(data, dict) else None
        if status in (401, 403, 429):
            _warn_rate_limited(status)
            return None
        if status >= 500 and attempt == 1:
            continue
        return None
    return None


@functools.lru_cache(maxsize=4096)
def get_repo(slug: str) -> Optional[dict[str, Any]]:
    """``GET /repos/{slug}`` — fork/archived/stars/created_at/language/size."""
    if not slug or "/" not in slug:
        return None
    return _get(f"https://api.github.com/repos/{slug}")


@functools.lru_cache(maxsize=4096)
def get_languages(slug: str) -> Optional[dict[str, Any]]:
    """``GET /repos/{slug}/languages`` — used by shape_dynamic."""
    if not slug or "/" not in slug:
        return None
    return _get(f"https://api.github.com/repos/{slug}/languages")


@functools.lru_cache(maxsize=8192)
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

    url = f"https://api.github.com/repos/{slug}/commits/{sha}"
    for attempt in (1, 2):
        try:
            resp = requests.get(url, headers=_headers(), timeout=_TIMEOUT_S)
        except (requests.Timeout, requests.ConnectionError):
            if attempt == 1:
                continue
            return None
        status = resp.status_code
        if status == 200:
            return True
        if status in (404, 422):
            return False
        if status in (401, 403, 429):
            _warn_rate_limited(status)
            return None
        if status >= 500 and attempt == 1:
            continue
        return None
    return None


@functools.lru_cache(maxsize=8192)
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
    get_repo.cache_clear()
    get_languages.cache_clear()
    commit_exists.cache_clear()
    _get_commit_cached.cache_clear()
    _bucket.cache_clear()
    _warned_token_missing = False
    _warned_rate_limited = False

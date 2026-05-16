"""Distro security-tracker fetcher with disk cache.

Three trackers fetched in parallel: Debian, Ubuntu, Red Hat. Per-CVE,
per-distro cache lives under ``~/.cache/cve-diff/distro/`` so a Debian
404 doesn't block re-trying Ubuntu, and a successful run isn't re-hit
on bench reruns.

Each per-distro fetch returns a dict with the same shape::

    {
        "status": "fixed|open|not-affected|unknown" | None,
        "fix_version": "<package version string>" | None,
        "references": ["<url>", ...],
    }

…or an error dict::

    {"error": "<short message>"}

Candidate ``(slug, sha)`` extraction is the caller's responsibility —
this module returns reference URLs untouched.
"""

from __future__ import annotations

import functools
import json
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from core.http import HttpError, Response
from core.http.urllib_backend import UrllibClient
from core.json.cache import JsonCache

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "cve-diff" / "distro"
_TIMEOUT_S = 10
_MAX_BYTES = 256 * 1024
_USER_AGENT = "cve-diff-agent/0.1"
_CACHE_TTL = 86400 * 7  # 7 days — distro advisory data changes slowly

_DEBIAN_URL = "https://security-tracker.debian.org/tracker/{cve_id}"
_UBUNTU_URL = "https://ubuntu.com/security/cves.json?q={cve_id}"
_REDHAT_URL = "https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}.json"

_HREF_RE = re.compile(r'href="([^"]+)"', re.IGNORECASE)


@dataclass
class DistroFetcher:
    cache_enabled: bool = True
    cache_dir: Path = field(default_factory=lambda: DEFAULT_CACHE_DIR)
    _mem: dict[tuple[str, str], dict[str, Any]] = field(default_factory=dict)
    _disk: JsonCache | None = field(default=None, repr=False)
    # `_mem_lock` serialises access to the in-memory cache. Pre-fix
    # the `if key in self._mem ... self._mem[key] = result` sequence
    # had a TOCTOU window: two parallel fetch_all callers (the bench
    # runner uses ProcessPoolExecutor for cves but the per-CVE
    # fetch_all spawns its own ThreadPoolExecutor for the 3 distros,
    # and a shared DistroFetcher across operator-driven repeats can
    # see two threads land on the same key at the same time) each
    # passed the `not in` check, each fetched independently, each
    # wrote to `self._mem[key]`. Result: wasted upstream traffic
    # AND, on dict resize, a non-atomic write that crashed in
    # CPython >=3.12's hardened dict implementation.
    _mem_lock: Any = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.cache_enabled and self._disk is None:
            self._disk = JsonCache(self.cache_dir)
        if self._mem_lock is None:
            import threading
            self._mem_lock = threading.Lock()

    def fetch_all(self, cve_id: str) -> dict[str, dict[str, Any]]:
        """Fan out to 3 distros in parallel, return per-distro results."""
        if not _is_cve_id(cve_id):
            return {d: {"error": "invalid cve_id"} for d in ("debian", "ubuntu", "redhat")}
        with ThreadPoolExecutor(max_workers=3) as pool:
            futures = {
                "debian": pool.submit(self._cached, "debian", cve_id, _fetch_debian),
                "ubuntu": pool.submit(self._cached, "ubuntu", cve_id, _fetch_ubuntu),
                "redhat": pool.submit(self._cached, "redhat", cve_id, _fetch_redhat),
            }
            return {name: fut.result() for name, fut in futures.items()}

    def _cached(self, distro: str, cve_id: str, fetcher) -> dict[str, Any]:
        key = (distro, cve_id)
        # Fast-path read under lock. We don't hold the lock across the
        # network fetch — that would serialise the parallel-distro
        # fan-out for nothing. Two parallel callers MAY duplicate the
        # fetch in the worst case, but only one of their writes
        # survives (last-writer-wins) and `_mem` mutation is now
        # atomic. The duplication is acceptable cost for not
        # serialising the network round-trips.
        with self._mem_lock:
            if key in self._mem:
                return self._mem[key]
        if self.cache_enabled and self._disk is not None:
            hit = self._disk.get(f"{distro}/{cve_id}", ttl_seconds=_CACHE_TTL)
            if isinstance(hit, dict):
                with self._mem_lock:
                    self._mem[key] = hit
                return hit
        result = fetcher(cve_id)
        err = result.get("error", "")
        cacheable = (
            "error" not in result
            or (err.startswith("http ") and not err.startswith("http 5"))
        )
        if cacheable:
            if self.cache_enabled and self._disk is not None:
                self._disk.put(f"{distro}/{cve_id}", result, ttl_seconds=_CACHE_TTL)
        with self._mem_lock:
            self._mem[key] = result
        return result


@functools.lru_cache(maxsize=1)
def _client() -> UrllibClient:
    return UrllibClient(user_agent=_USER_AGENT)


def _is_cve_id(cve_id: str) -> bool:
    # `re.fullmatch` (not `re.match` + `^...$`) and `re.ASCII` so:
    #   * `$` doesn't match before a trailing newline. Pre-fix
    #     `re.match("^CVE-...$", "CVE-2023-1234\n")` accepted the
    #     trailing newline, and the cve_id then flowed into the
    #     URL templates (`_DEBIAN_URL.format(cve_id=cve_id)`) and
    #     the cache key (`f"{distro}/{cve_id}"`). The newline in
    #     a URL splits the HTTP request into two — CRLF / header
    #     injection — and corrupts the cache filename.
    #   * `\d` matches only ASCII digits. Without `re.ASCII`,
    #     `\d` admits Arabic-Indic / Devanagari / fullwidth digit
    #     chars; the CVE-id then propagates as a unicode-mixed
    #     string into URL formatting where some HTTP clients
    #     idna-encode it weirdly, producing wrong cache keys.
    return bool(
        re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve_id or "", re.ASCII)
    )


def _get_response(url: str) -> Response | dict[str, Any]:
    """GET ``url`` via ``UrllibClient``. Returns ``Response`` on success
    or ``{"error": "..."}`` on any failure."""
    try:
        return _client().request("GET", url, timeout=_TIMEOUT_S, retries=0)
    except HttpError as exc:
        if exc.status:
            return {"error": f"http {exc.status}"}
        return {"error": f"network: {str(exc)[:200]}"}


def _http_or_error(url: str) -> tuple[Response | None, dict[str, Any] | None]:
    """Return ``(resp, None)`` on a 200; ``(None, error_dict)`` otherwise."""
    result = _get_response(url)
    if isinstance(result, dict):
        return None, result
    if result.status != 200:
        return None, {"error": f"http {result.status}"}
    return result, None


def _fetch_debian(cve_id: str) -> dict[str, Any]:
    """Scrape Debian security-tracker HTML — extract anchor URLs."""
    resp, err = _http_or_error(_DEBIAN_URL.format(cve_id=cve_id))
    if err:
        return err
    body = resp.body.decode("utf-8", errors="replace")[:_MAX_BYTES]
    refs: list[str] = []
    for href in _HREF_RE.findall(body):
        if (href.startswith("http://") or href.startswith("https://")) and href not in refs:
            refs.append(href)
    status = "fixed" if "fixed" in body.lower() else None
    return {"status": status, "fix_version": None, "references": refs[:50]}


def _fetch_ubuntu(cve_id: str) -> dict[str, Any]:
    """Ubuntu CVE search API — returns JSON with cves[].references + notes."""
    resp, err = _http_or_error(_UBUNTU_URL.format(cve_id=cve_id))
    if err:
        return err
    try:
        data = resp.json()
    except Exception as exc:
        return {"error": f"non-json response: {type(exc).__name__}"}
    if not isinstance(data, dict):
        return {"error": f"non-dict response: {type(data).__name__}"}
    cves = data.get("cves") or []
    match = next((c for c in cves if (c.get("id") or "").upper() == cve_id.upper()), None)
    if match is None:
        return {"error": "http 404"}
    refs = [r for r in (match.get("references") or [])
            if isinstance(r, str) and r.startswith(("http://", "https://"))]
    status = match.get("status") or None
    fix_version = None
    pkgs = match.get("packages") or []
    if pkgs and isinstance(pkgs[0], dict):
        statuses = pkgs[0].get("statuses") or []
        if statuses and isinstance(statuses[0], dict):
            fix_version = statuses[0].get("description")
    return {"status": status, "fix_version": fix_version, "references": refs[:50]}


def _fetch_redhat(cve_id: str) -> dict[str, Any]:
    """Red Hat hydra security-data API — returns JSON with references[]."""
    resp, err = _http_or_error(_REDHAT_URL.format(cve_id=cve_id))
    if err:
        return err
    try:
        data = resp.json()
    except Exception as exc:
        return {"error": f"non-json response: {type(exc).__name__}"}
    if not isinstance(data, dict):
        return {"error": f"non-dict response: {type(data).__name__}"}
    refs = list(data.get("references") or [])
    affected = data.get("affected_release") or []
    fix_version = affected[0].get("package") if affected and isinstance(affected[0], dict) else None
    status = "fixed" if affected else None
    return {"status": status, "fix_version": fix_version, "references": refs[:50]}

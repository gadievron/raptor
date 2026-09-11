"""OSV.dev API client.

Two endpoints are exposed:

  - :meth:`OsvClient.get_vuln` — ``GET /v1/vulns/<id>``: fetch one record.
    The native shape of OSV's "look up by ID (including CVE/GHSA aliases —
    OSV resolves aliases automatically)".
  - :meth:`OsvClient.query_batch` — ``POST /v1/querybatch``: bulk lookup
    by ``(name, ecosystem, version)``. Returns ID lists; consumers hydrate
    via :meth:`get_vuln`.

The legacy ``POST /v1/query`` endpoint is **not** exposed. cve-diff used
it as a 404-fallback for ``GET /vulns/<id>`` but the call shape it sent
(``{"queries": [...]}``) was the querybatch shape, not the query shape,
so the fallback returned ``None`` deterministically — dead code that
this rewrite drops.

HTTP transport is :class:`core.http.HttpClient` (mandatory). Optional
per-vuln caching is via :class:`core.json.JsonCache` and shared
``ttl_seconds``. ``offline=True`` skips network entirely; cache hits
flow through, misses return ``None``/empty.
"""

from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING

from core.http import HttpClient, HttpError

from .parser import parse_record

if TYPE_CHECKING:
    from core.json import JsonCache
    from .types import OsvRecord
    from collections.abc import Sequence

log = logging.getLogger(__name__)

OSV_BASE_URL = "https://api.osv.dev/v1"
DEFAULT_TTL_SECONDS = 24 * 3600

# querybatch pages are 1000 ids each; 20 pages = 20k advisories for a
# single (package, version) query. Beyond that the slot is demoted to
# the None error sentinel — refusing is honest, truncating is not.
_MAX_QUERY_PAGES = 20


class OsvClient:
    """Thin client over the OSV.dev v1 API. Construct one per run."""

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache | None = None,
        *,
        offline: bool = False,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
    ) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline
        self._ttl = ttl_seconds

    def get_vuln(self, vuln_id: str) -> OsvRecord | None:
        """Return a parsed :class:`OsvRecord` or ``None`` on 404 / error / parse failure."""
        record = self._cached_get_vuln(vuln_id)
        if record is None:
            return None
        try:
            return parse_record(record)
        except ValueError as exc:
            log.debug("osv: skipping malformed record %s: %s", vuln_id, exc)
            return None

    def query_batch(
        self,
        queries: Sequence[dict[str, Any]],
    ) -> list[list[str] | None]:
        """Bulk lookup. Returns one slot per query.

        Each query is the OSV query body shape, e.g.::

            {"package": {"name": "lodash", "ecosystem": "npm"}, "version": "4.17.20"}

        Slot semantics distinguish "OSV knows of no advisories" from
        "the lookup did not happen":

          - ``list[str]`` — the query succeeded; the list (possibly
            empty) is OSV's authoritative answer for that slot.
          - ``None`` — the lookup failed (network error, malformed
            response shape, offline). Callers MUST NOT cache or treat
            ``None`` slots as "no advisories"; caching a transient
            failure as an authoritative empty answer silently blinds
            every scan until the cache entry expires.

        Partial answers are still more useful than hard failure for
        security gates that aggregate across many deps, so errors are
        absorbed per-batch rather than raised.
        """
        if not queries:
            return []
        if self._offline:
            return [None for _ in queries]
        body = {"queries": list(queries)}
        try:
            data = self._http.post_json(
                f"{OSV_BASE_URL}/querybatch", body,
            )
        except HttpError as exc:
            log.warning("osv: querybatch failed: %s", exc)
            return [None for _ in queries]

        results = data.get("results") if isinstance(data, dict) else None
        if not isinstance(results, list) or len(results) != len(queries):
            log.warning(
                "osv: querybatch returned malformed shape "
                "(got %d slots vs %d queries)",
                len(results) if isinstance(results, list) else -1,
                len(queries),
            )
            return [None for _ in queries]

        out: list[list[str] | None] = []
        pending: list[tuple[int, str]] = []  # (query index, next_page_token)
        for i, slot in enumerate(results):
            if not isinstance(slot, dict):
                # Malformed slot = "the lookup did not happen", per the
                # slot contract above — never an authoritative empty
                # answer that callers would cache as "no advisories".
                out.append(None)
                continue
            out.append(self._slot_ids(slot))
            token = slot.get("next_page_token")
            if isinstance(token, str) and token:
                pending.append((i, token))

        # Per-slot pagination: OSV truncates large answers and hands
        # back a next_page_token per slot. A page-1-only ID list is not
        # authoritative — returning it as complete silently hides every
        # advisory beyond the first page — so follow continuations, and
        # demote a slot to None (lookup failed) when its continuation
        # fails or exceeds the page cap.
        pages_followed = 0
        while pending:
            if pages_followed >= _MAX_QUERY_PAGES:
                for i, _token in pending:
                    out[i] = None
                break
            pages_followed += 1
            cont_queries = [
                {**dict(queries[i]), "page_token": token}
                for i, token in pending
            ]
            try:
                data = self._http.post_json(
                    f"{OSV_BASE_URL}/querybatch", {"queries": cont_queries},
                )
            except HttpError as exc:
                log.warning("osv: querybatch continuation failed: %s", exc)
                data = None
            cont_results = data.get("results") if isinstance(data, dict) else None
            if not isinstance(cont_results, list) or len(cont_results) != len(pending):
                for i, _token in pending:
                    out[i] = None
                break
            next_pending: list[tuple[int, str]] = []
            for (i, _token), slot in zip(pending, cont_results):
                if not isinstance(slot, dict):
                    out[i] = None
                    continue
                ids = out[i]
                if isinstance(ids, list):
                    ids.extend(self._slot_ids(slot))
                token = slot.get("next_page_token")
                if isinstance(token, str) and token:
                    next_pending.append((i, token))
            pending = next_pending
        return out

    @staticmethod
    def _slot_ids(slot: dict[str, Any]) -> list[str]:
        """Extract string vuln IDs from one querybatch result slot."""
        return [
            v["id"]
            for v in slot.get("vulns") or []
            if isinstance(v, dict) and isinstance(v.get("id"), str)
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cached_get_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        cache_key = f"osv/vulns/{_safe_id(vuln_id)}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if isinstance(cached, dict):
                return cached
        if self._offline:
            return None
        # Percent-encode `vuln_id` before interpolating into the
        # URL. Pre-fix the raw `vuln_id` flowed straight into the
        # path segment — for IDs containing `/` (rare but real
        # in some ecosystem prefixes), `?` (would split into
        # query string), `#` (fragment), spaces, or control
        # bytes (worst case), the resulting URL was either
        # malformed (server returned 400) or resolved to the
        # wrong endpoint silently. `_safe_id` already sanitises
        # for the CACHE KEY but the URL path needed proper
        # percent-encoding via `urllib.parse.quote(..., safe="")`
        # so even `/` gets encoded as %2F.
        from urllib.parse import quote
        encoded_id = quote(vuln_id, safe="")
        try:
            data = self._http.get_json(f"{OSV_BASE_URL}/vulns/{encoded_id}")
        except HttpError as exc:
            if exc.status == 404:
                return None
            log.warning("osv: get_vuln(%s) failed: %s", vuln_id, exc)
            return None
        if not isinstance(data, dict):
            return None
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data


def _safe_id(s: str) -> str:
    """Make a vuln ID safe for path-segment caching."""
    return s.replace("/", "_").replace("\\", "_")

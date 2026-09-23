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


class OsvLookupError(Exception):
    """A per-vuln lookup failed for a NON-definitive reason.

    Raised (opt-in, see :meth:`OsvClient.get_vuln`) for network
    failures, non-404 HTTP errors, malformed response bodies, and
    offline cache misses — everything where "OSV has no record" would
    be the wrong conclusion. A definitive 404 stays ``None``: that IS
    OSV's authoritative "no such record".

    Never cached: only successful record fetches enter the cache, so a
    transient outage can't be replayed as an authoritative answer.
    """


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

    def get_vuln(
        self, vuln_id: str, *, raise_on_transient: bool = False,
    ) -> OsvRecord | None:
        """Return a parsed :class:`OsvRecord` or ``None`` on 404 / error / parse failure.

        With ``raise_on_transient=True``, non-definitive failures
        (network error, non-404 HTTP status, malformed body, offline
        cache miss) raise :class:`OsvLookupError` instead of degrading
        to ``None`` — callers minting verdicts must not read a
        transient outage as "OSV has no record". The default keeps the
        historical swallow-to-``None`` shape for aggregating callers.
        """
        try:
            record = self._cached_get_vuln(vuln_id)
        except OsvLookupError:
            if raise_on_transient:
                raise
            return None
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
        """Extract string vuln IDs from one querybatch result slot.

        Empty ids are dropped: they are server-minted junk, and the
        hydration loop would only feed them back to the per-vuln
        endpoint (where the degenerate-id gate refuses them). A truthy
        non-list ``vulns`` is equally junk — never iterated.
        """
        vulns = slot.get("vulns")
        if not isinstance(vulns, list):
            return []
        return [
            v["id"]
            for v in vulns
            if isinstance(v, dict) and isinstance(v.get("id"), str)
            and v["id"]
        ]

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _cached_get_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """Raw record dict, ``None`` for a definitive 404, or
        :class:`OsvLookupError` for any non-definitive failure."""
        # Shape-gate the id BEFORE it joins a cache key or URL. Ids
        # arrive from server-controlled querybatch output, not just
        # operator input (the epss/vulnrichment clients carry the same
        # validate-first discipline for the same reason); '' / '.' /
        # '..' would raise ValueError out of the cache-key layer —
        # escaping the OsvLookupError-only catches upstream and
        # killing the scan on one hostile slot.
        if not vuln_id or vuln_id in (".", ".."):
            msg = f"osv: refusing degenerate vuln id {vuln_id!r}"
            raise OsvLookupError(msg)
        cache_key = f"osv/vulns/{_encode_id(vuln_id)}"
        if self._cache is not None:
            cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
            if isinstance(cached, dict):
                return cached
        if self._offline:
            msg = f"osv: offline and no cached record for {vuln_id}"
            raise OsvLookupError(msg)
        # Percent-encode `vuln_id` before interpolating into the
        # URL. Pre-fix the raw `vuln_id` flowed straight into the
        # path segment — for IDs containing `/` (rare but real
        # in some ecosystem prefixes), `?` (would split into
        # query string), `#` (fragment), spaces, or control
        # bytes (worst case), the resulting URL was either
        # malformed (server returned 400) or resolved to the
        # wrong endpoint silently. The same injective encoding
        # keys the cache above, so URL identity and cache identity
        # cannot diverge.
        encoded_id = _encode_id(vuln_id)
        try:
            data = self._http.get_json(f"{OSV_BASE_URL}/vulns/{encoded_id}")
        except HttpError as exc:
            if exc.status == 404:
                # Definitive: OSV authoritatively has no such record.
                return None
            log.warning("osv: get_vuln(%s) failed: %s", vuln_id, exc)
            msg = f"osv: get_vuln({vuln_id}) failed: {exc}"
            raise OsvLookupError(msg) from exc
        if not isinstance(data, dict):
            # A 200 whose body isn't a record object (proxy/CDN error
            # page shaped as JSON) — not OSV saying "no record".
            msg = f"osv: get_vuln({vuln_id}) returned a non-object body"
            raise OsvLookupError(msg)
        if self._cache is not None:
            self._cache.put(cache_key, data, ttl_seconds=self._ttl)
        return data


def _encode_id(s: str) -> str:
    """Injective, path-safe encoding of a vuln ID for the cache key.

    The previous ``/`` / ``\\`` → ``_`` replacement was lossy:
    ``GHSA-a/b`` and ``GHSA-a_b`` shared one cache file, letting a
    crafted id shadow another id's cached record for the TTL.
    Percent-encoding every reserved byte (``safe=""``) is injective —
    JsonCache documents exactly this responsibility for callers that
    interpolate externally-sourced names into key segments. Keys for
    ids containing ``/`` change spelling once; the old entries simply
    expire unread.
    """
    from urllib.parse import quote

    return quote(s, safe="")

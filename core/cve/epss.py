"""FIRST.org EPSS — exploit-prediction scores per CVE.

EPSS publishes a daily probability that a CVE will be exploited in the
wild within the next 30 days. We fetch scores per-CVE on demand and
cache them for 24 hours.

The endpoint accepts comma-separated CVE lists; we batch up to 100 IDs
per request to keep URL length comfortable. Responses look like:

    {
      "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97559", "percentile": "0.99971"},
        ...
      ]
    }

EPSS coverage is incomplete — many advisories don't carry a CVE alias,
and many CVEs have no EPSS score yet. ``score(cve)`` returns ``None`` in
those cases; callers should treat ``None`` as "no signal", not "low risk".

Originally written for ``packages/sca`` — lifted to ``core/cve`` so other
consumers (``/agentic`` finding ranking, ``/validate`` Stage D severity,
``/exploit`` prioritisation, SARIF report badges) can layer EPSS scores
on top of any CVE-tagged finding without depending on SCA-specific code.
"""

from __future__ import annotations

import logging
import math
import re

from core.http import HttpClient, HttpError
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from core.json import JsonCache
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

EPSS_URL = "https://api.first.org/data/v1/epss"
_DEFAULT_TTL = 24 * 3600
_BATCH_SIZE = 100

# Strict ASCII CVE-id shape (kept in sync with the sibling
# ``core.cve.vulnrichment`` validator). Ids are interpolated into
# cache keys ("epss/<id>") and the batch URL, so a degenerate id
# ("..", "a//b") would otherwise raise out of the cache-key layer
# and lose the whole batch — the docstring contract is that
# unresolvable ids are simply absent from the returned dict.
# ``re.ASCII`` pins ``\d`` to 0-9.
_CVE_ID_RE = re.compile(r"\ACVE-\d{4}-\d{4,}\Z", re.ASCII)


class EpssClient:
    """Per-CVE EPSS lookup with caching.

    Caller-supplied ``HttpClient`` (so tests inject a stub) and
    ``JsonCache`` (for the 24h per-CVE persistence). ``offline=True``
    suppresses the network — fresh-cache hits still flow through;
    everything else returns nothing.
    """

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache,
        *,
        offline: bool = False,
        ttl_seconds: int = _DEFAULT_TTL,
    ) -> None:
        self._http = http
        self._cache = cache
        self._offline = offline
        self._ttl = ttl_seconds

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scores(self, cves: Iterable[str]) -> dict[str, float]:
        """Return ``{cve: probability}`` for any IDs we can resolve.

        Missing IDs (no EPSS coverage, network failure, etc.) are simply
        absent from the dict. Callers should not assume completeness.
        """
        # Normalise + dedup + validate. Malformed ids are skipped (they
        # end up absent from the result, per the contract above) so one
        # bad id from a hostile / buggy feed can't sink its batchmates.
        clean = sorted({
            c.upper() for c in cves
            if isinstance(c, str) and _CVE_ID_RE.fullmatch(c.upper())
        })
        result: dict[str, float] = {}
        uncached: list[str] = []
        for cve in clean:
            cached = self._cache.get(self._key(cve), ttl_seconds=self._ttl)
            if cached is None:
                uncached.append(cve)
                continue
            score = _coerce_score(cached)
            if score is not None:
                result[cve] = score

        if uncached and not self._offline:
            for chunk in _chunked(uncached, _BATCH_SIZE):
                fetched = self._fetch_chunk(chunk)
                if fetched is None:
                    continue
                # Cache every requested CVE — even ones without coverage,
                # using a sentinel so we don't refetch a known no-data row.
                for cve in chunk:
                    score = fetched.get(cve)
                    self._cache.put(
                        self._key(cve),
                        score if score is not None else _NO_SCORE_SENTINEL,
                        ttl_seconds=self._ttl,
                    )
                    if score is not None:
                        result[cve] = score
        return result

    def score(self, cve: str) -> float | None:
        """Convenience: single-CVE lookup."""
        return self.scores([cve]).get(cve.upper())

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fetch_chunk(self, cves: list[str]) -> dict[str, float] | None:
        url = f"{EPSS_URL}?cve={','.join(cves)}"
        try:
            payload = self._http.get_json(url)
        except HttpError as e:
            logger.warning(
                "core.cve.epss: chunk fetch failed (%s); leaving CVEs unresolved", e,
            )
            return None
        return _parse_response(payload)

    @staticmethod
    def _key(cve: str) -> str:
        return f"epss/{cve}"


# Marker stored when EPSS has no coverage for a CVE so we don't refetch.
_NO_SCORE_SENTINEL = -1.0


def _coerce_score(value: object) -> float | None:
    if isinstance(value, (int, float)):
        v = float(value)
        if v == _NO_SCORE_SENTINEL:
            return None
        # A cache written before ingest validation existed (or edited
        # on disk) can hold an out-of-range value; degrade to "no
        # signal" rather than serving poison to risk ranking.
        if not _valid_score(v):
            return None
        return v
    return None


def _valid_score(score: float) -> bool:
    """EPSS is a probability: finite and within [0, 1] inclusive.

    Float-parseable poison from a hostile / corrupted feed ("NaN",
    "inf", "1e999", negative or >1 values) otherwise flows into
    findings: ``nan`` serialises as a bare non-JSON token that makes
    the whole findings.json unparseable for strict consumers, and
    ``inf`` pins the risk estimate to its ceiling. The range check
    also retires the ``_NO_SCORE_SENTINEL`` (-1.0) collision — a
    valid feed row can never mint the sentinel.
    """
    return math.isfinite(score) and 0.0 <= score <= 1.0


def _parse_response(payload: object) -> dict[str, float]:
    if not isinstance(payload, dict):
        return {}
    data = payload.get("data")
    if not isinstance(data, list):
        return {}
    out: dict[str, float] = {}
    rejected = 0
    for entry in data:
        if not isinstance(entry, dict):
            continue
        cve = entry.get("cve")
        score = entry.get("epss")
        if not isinstance(cve, str):
            continue
        try:
            score_f = float(score)            # type: ignore[arg-type]
        except (TypeError, ValueError):
            continue
        if not _valid_score(score_f):
            # Reject per-row (see _valid_score) — the id degrades to
            # "no signal" like any other unresolvable row instead of
            # poisoning findings.json for the whole scan.
            rejected += 1
            continue
        out[cve.upper()] = score_f
    if rejected:
        logger.warning(
            "core.cve.epss: rejected %d feed score(s) outside the "
            "valid probability range (non-finite or not in [0, 1]); "
            "affected CVEs left unresolved", rejected,
        )
    return out


def _chunked(items: list[str], size: int):
    for i in range(0, len(items), size):
        yield items[i:i + size]


__all__ = ["EPSS_URL", "EpssClient"]

"""CISA Vulnrichment SSVC lookup.

The Vulnrichment project (``github.com/cisagov/vulnrichment``,
CC0 1.0 public domain) publishes CISA's enrichment of CVE records
via the ADP (Authorized Data Publisher) container in CVE-JSON-5
format. The most operationally-useful field is the SSVC decision —
specifically ``Exploitation`` which takes one of three values:

  * ``none``    — no known exploitation activity
  * ``poc``     — proof-of-concept code is publicly available
  * ``active``  — actively exploited in the wild

This is a cross-ecosystem exploitation signal — unlike KEV (biased
to Windows / network / web), EPSS (sparse on library-level CVEs),
or ExploitDB / Metasploit (skewed to "interesting target"
exploits), Vulnrichment SSVC scores ~60% of CVEs in cold-start
ecosystems where the existing signal sources return nothing.
Coverage measured 2026-05-21:

  * Cargo:     57% of corpus CVEs have an SSVC decision
  * NuGet:     63%
  * Packagist: 68%

Vulnrichment is one ~120 MB git repo with ~120K per-CVE JSON
files. Rather than pulling the whole repo at runtime, we fetch
per-CVE on-demand from ``raw.githubusercontent.com`` and cache
each result locally. With the typical scan touching 5-30 unique
CVEs and an aggressive 7-day TTL, a warm cache makes the lookup
free; a cold cache costs ~50 ms per CVE in parallel-friendly
HTTPS GETs through the existing in-process egress proxy.

Failure modes:
  * Network down + cold cache → ``lookup()`` returns ``None``;
    callers degrade gracefully (Vulnrichment is a bonus signal
    layered atop any underlying CVE match).
  * CVE has no Vulnrichment file (not yet enriched by CISA) →
    404 from the upstream → ``lookup()`` returns ``None``. Same
    behaviour as "this CVE isn't in the catalogue yet".

Sibling to ``core.cve.kev`` and ``core.cve.epss`` — same
caller-injected ``HttpClient`` / ``JsonCache`` pattern so tests
inject stubs without monkey-patching the network layer.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from core.http import HttpClient, HttpError
from core.json import JsonCache

logger = logging.getLogger(__name__)


# ``HEAD`` resolves to the repo's default branch at request time
# (CISA publishes to ``develop``, not ``main``); raw.githubusercontent
# honours it, so a future default-branch rename can't 404 us.
_REPO_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/HEAD"
)
_DEFAULT_TTL = 7 * 24 * 3600   # SSVC drifts slowly; weekly refresh is fine
_CACHE_KEY_PREFIX = "vulnrichment"
_NEGATIVE_TTL = 24 * 3600      # 404s cache for 1 day so we re-probe


@dataclass(frozen=True)
class SSVCDecision:
    """CISA SSVC decision points extracted from one Vulnrichment
    entry. ``exploitation`` is the load-bearing field — the other
    two are kept as evidence for explainable risk-ranking and for
    callers wanting to surface the full SSVC context (e.g.
    ``/validate`` reports)."""

    exploitation: str           # "none" / "poc" / "active"
    automatable: Optional[str]  # "yes" / "no" / None when unset
    technical_impact: Optional[str]  # "total" / "partial" / None

    @property
    def has_exploit(self) -> bool:
        """True when CISA records a public PoC OR active
        exploitation. The two flavours of "weaponised" — the
        risk formula treats ``active`` like KEV and ``poc`` like
        ExploitEvidence so the multiplier composition stays
        consistent with the existing signal-tier model."""
        return self.exploitation in ("poc", "active")

    @property
    def is_active(self) -> bool:
        """True when CISA records active in-the-wild exploitation.
        KEV-equivalent signal, with broader coverage."""
        return self.exploitation == "active"


class VulnrichmentClient:
    """Lazy, per-CVE on-demand Vulnrichment SSVC lookup.

    Each CVE is fetched once, cached via the shared ``JsonCache``,
    and served from the in-memory dict on subsequent calls within
    the same run. Stub-friendly: callers inject the ``HttpClient``
    + ``JsonCache`` so tests can drive the lookup without going
    through the proxy + network.
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
        self._memo: dict = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, cve_id: str) -> Optional[SSVCDecision]:
        """Return the SSVC decision for ``cve_id`` or ``None``.

        Returns ``None`` when:
          * ``cve_id`` is malformed (not ``CVE-YYYY-NNNN`` shape)
          * CISA hasn't enriched this CVE yet (upstream 404)
          * Network unavailable AND cold cache
          * Vulnrichment entry exists but lacks an SSVC decision
            (CISA's enrichment is staged — some entries carry
            only CVSS / CWE without an SSVC scorecard yet)

        Result is memoised per-process and cached on disk for
        ``ttl_seconds`` (default 7 days). 404s are cached for 1
        day so the CISA backfill window — when an entry can flip
        from "not enriched" to "enriched" — is re-probed within
        a useful timeframe.
        """
        if not cve_id:
            return None
        key = cve_id.upper()
        if key in self._memo:
            return self._memo[key]

        record = self._fetch_record(key)
        decision = _decode_ssvc(record) if record is not None else None
        self._memo[key] = decision
        return decision

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _fetch_record(self, cve_id: str) -> Optional[dict]:
        """Disk-cached fetch of one Vulnrichment entry. Returns
        the decoded JSON document, ``None`` on miss / failure.

        Cache shape distinguishes three states so we don't
        re-probe the upstream needlessly:
          * ``None`` cache entry: never fetched / TTL expired
          * ``{"_status": "missing"}``: 404 seen at upstream
            (cached for the shorter ``_NEGATIVE_TTL`` so a
            backfill from CISA gets picked up in ≤1 day)
          * dict: the actual CVE-JSON-5 record
        """
        cache_key = f"{_CACHE_KEY_PREFIX}/{cve_id}"
        cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
        if isinstance(cached, dict):
            if cached.get("_status") == "missing":
                return None
            return cached

        if self._offline:
            return None

        url = _url_for_cve(cve_id)
        if url is None:
            return None

        try:
            record = self._http.get_json(url)
        except HttpError as e:
            # 404 is the common case (CVE not yet enriched).
            # Cache a negative marker so the next call within
            # the 1-day window doesn't re-probe and waste an
            # HTTP request. ``HttpError`` carries the status code
            # as a structured field; fall back to substring match
            # on the message for stubs that don't propagate it.
            status = getattr(e, "status", None)
            msg = str(e).lower()
            is_404 = status == 404 or "404" in msg or "not found" in msg
            if is_404:
                self._cache.put(
                    cache_key, {"_status": "missing"},
                    ttl_seconds=_NEGATIVE_TTL,
                )
                return None
            # Other errors (transport, 5xx) — don't cache so the
            # next call gets a fresh try.
            logger.debug(
                "core.cve.vulnrichment: fetch failed for %s: %s",
                cve_id, e,
            )
            return None
        if not isinstance(record, dict):
            return None
        self._cache.put(cache_key, record, ttl_seconds=self._ttl)
        return record


def _url_for_cve(cve_id: str) -> Optional[str]:
    """Build the ``raw.githubusercontent.com`` URL for a CVE's
    Vulnrichment entry. Returns ``None`` for malformed inputs.

    Vulnrichment shards CVEs into ``<year>/<NNNxxx>/`` buckets
    where ``NNN`` is ``floor(number / 1000)``. CVEs below 1000
    live in ``0xxx``. Example:

      ``CVE-2024-12345`` → ``2024/12xxx/CVE-2024-12345.json``
      ``CVE-2024-500``   → ``2024/0xxx/CVE-2024-500.json``
    """
    parts = cve_id.upper().split("-")
    if len(parts) != 3 or parts[0] != "CVE":
        return None
    year_str, num_str = parts[1], parts[2]
    if not (year_str.isdigit() and num_str.isdigit()):
        return None
    bucket = int(num_str) // 1000
    bucket_dir = f"{bucket}xxx" if bucket > 0 else "0xxx"
    return (
        f"{_REPO_RAW_BASE}/{year_str}/{bucket_dir}/"
        f"CVE-{year_str}-{num_str}.json"
    )


def _decode_ssvc(record: object) -> Optional[SSVCDecision]:
    """Pluck SSVC fields out of a CVE-JSON-5 record's CISA-ADP
    container. Returns ``None`` when the record doesn't carry an
    SSVC scorecard (CISA's enrichment is staged — some entries
    have only CVSS / CWE).

    Format (CVE-JSON-5):
      record["containers"]["adp"][i]["providerMetadata"]["shortName"] = "CISA-ADP"
      record["containers"]["adp"][i]["metrics"][j]["other"]["content"]["options"]
        is a list of `{"Exploitation": ..., "Automatable": ..., "Technical Impact": ...}`

    Tolerates schema variation defensively — any unexpected
    shape returns ``None`` rather than raising. SSVC option
    spellings normalised to lowercase so the risk formula's
    string comparisons don't trip on input-case drift.
    """
    if not isinstance(record, dict):
        return None
    containers = record.get("containers")
    if not isinstance(containers, dict):
        return None
    adp = containers.get("adp")
    if not isinstance(adp, list):
        return None
    for entry in adp:
        if not isinstance(entry, dict):
            continue
        provider = (
            (entry.get("providerMetadata") or {}).get("shortName") or ""
        )
        if "CISA-ADP" not in provider:
            continue
        for metric in entry.get("metrics") or []:
            if not isinstance(metric, dict):
                continue
            content = (metric.get("other") or {}).get("content") or {}
            options = content.get("options")
            if not isinstance(options, list):
                continue
            exploitation = None
            automatable = None
            technical_impact = None
            for opt in options:
                if not isinstance(opt, dict):
                    continue
                if "Exploitation" in opt:
                    exploitation = str(opt["Exploitation"]).lower()
                if "Automatable" in opt:
                    automatable = str(opt["Automatable"]).lower()
                if "Technical Impact" in opt:
                    technical_impact = (
                        str(opt["Technical Impact"]).lower()
                    )
            if exploitation in ("none", "poc", "active"):
                return SSVCDecision(
                    exploitation=exploitation,
                    automatable=automatable,
                    technical_impact=technical_impact,
                )
    return None


__all__ = ["SSVCDecision", "VulnrichmentClient"]

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

Scans outside that envelope — container-image scans carry 10^4+
distro CVE findings — must not loop :meth:`~VulnrichmentClient.lookup`
per finding: use :meth:`~VulnrichmentClient.lookup_many`, which
resolves cache hits for free and runs the remaining fetches on a
bounded thread pool under a caller-set network budget. The upstream
publishes no bulk artifact (no releases; only the per-CVE files in
the git tree), so budgeted parallel per-CVE GETs are the fetch shape.

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
import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from core.http import HttpClient, HttpError
from core.json import JsonCache

if TYPE_CHECKING:
    from collections.abc import Iterable

logger = logging.getLogger(__name__)

# Strict ASCII CVE-id shape, checked BEFORE any use of the id.
# ``str.isdigit()`` alone is not enough: Unicode digits (e.g. a
# superscript "²") pass ``isdigit()`` but crash ``int()``, and
# path-degenerate ids ("..", "a//b") reach the cache-key layer and
# raise there — both violating the "malformed → None" contract.
# ``re.ASCII`` pins ``\d`` to 0-9. CVE numbers are 4+ digits
# (zero-padded below 1000), matching the official id format.
_CVE_ID_RE = re.compile(r"\ACVE-\d{4}-\d{4,}\Z", re.ASCII)


# ``HEAD`` resolves to the repo's default branch at request time
# (CISA publishes to ``develop``, not ``main``); raw.githubusercontent
# honours it, so a future default-branch rename can't 404 us.
_REPO_RAW_BASE = (
    "https://raw.githubusercontent.com/cisagov/vulnrichment/HEAD"
)
_DEFAULT_TTL = 7 * 24 * 3600   # SSVC drifts slowly; weekly refresh is fine
_CACHE_KEY_PREFIX = "vulnrichment"
_NEGATIVE_TTL = 24 * 3600      # 404s cache for 1 day so we re-probe

# Sentinel distinguishing "record decoded to no SSVC signal" (a valid
# outcome, memoisable) from "the decoder itself failed on this record"
# (per-id degrade + cache eviction; see ``_decode_guarded``).
_DECODE_FAILED = object()


@dataclass(frozen=True)
class SSVCDecision:
    """CISA SSVC decision points extracted from one Vulnrichment
    entry. ``exploitation`` is the load-bearing field — the other
    two are kept as evidence for explainable risk-ranking and for
    callers wanting to surface the full SSVC context (e.g.
    ``/validate`` reports)."""

    exploitation: str           # "none" / "poc" / "active"
    automatable: str | None  # "yes" / "no" / None when unset
    technical_impact: str | None  # "total" / "partial" / None

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
        self._memo: dict[str, SSVCDecision | None] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def lookup(self, cve_id: str) -> SSVCDecision | None:
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
        # Validate before the memo/cache/URL layers see the id — a
        # degenerate id must return None, never raise out of them.
        if _CVE_ID_RE.fullmatch(key) is None:
            return None
        if key in self._memo:
            return self._memo[key]

        hit, record = self._cached_record(key)
        if hit:
            decision = self._decode_guarded(key, record)
            if decision is not _DECODE_FAILED:
                self._memo[key] = decision
                return decision
            # Poisoned cache entry (written before the validate-
            # before-cache gate, or by decoder drift): already
            # evicted by _decode_guarded — fall through to a fresh
            # fetch instead of serving the poison for its TTL.
        if self._offline:
            self._memo[key] = None
            return None
        record = self._fetch_remote(key)
        decision = self._decode_guarded(key, record)
        if decision is _DECODE_FAILED:
            decision = None
        self._memo[key] = decision
        return decision

    def lookup_many(
        self,
        cve_ids: Iterable[str],
        *,
        fetch_budget: int | None = None,
        max_workers: int = 8,
    ) -> dict[str, SSVCDecision]:
        """Batched SSVC lookup for a whole scan's CVE set.

        Same per-id contract as :meth:`lookup`, minus the redundant
        entries: the returned dict carries only ids that resolved to
        an actual :class:`SSVCDecision` — malformed ids, upstream
        404s, scorecard-less records, and offline cache misses are
        simply absent, and callers treat absence as "no signal".

        Purpose: the per-CVE on-demand design assumes a scan touching
        5-30 unique CVEs; container-image scans carry 10^4+ distro CVE
        findings, and calling :meth:`lookup` once per finding turns
        into hours of serial HTTPS GETs. This entry point makes the
        cold-cache cost bounded and parallel:

        * ``fetch_budget`` caps the number of NETWORK fetches (memo /
          disk-cache hits are always resolved and never consume
          budget, so repeat scans progressively warm the cache past
          the budget line). Input order is the fetch-priority order —
          the first ``fetch_budget`` uncached ids are fetched, the
          rest are skipped with ONE summary log line. ``None`` means
          unbounded.
        * Uncached fetches run on a bounded thread pool
          (``max_workers``); the injected ``HttpClient`` and
          ``JsonCache`` are shared across threads exactly as the SCA
          registry-enrichment passes already share them.

        Skipped and failed ids are NOT memoised, so a later direct
        :meth:`lookup` (or the next run's budget) still gets its
        chance to fetch them.
        """
        ordered: list[str] = []
        seen: set[str] = set()
        for cid in cve_ids:
            if not isinstance(cid, str):
                continue
            key = cid.upper()
            if key in seen or _CVE_ID_RE.fullmatch(key) is None:
                continue
            seen.add(key)
            ordered.append(key)

        out: dict[str, SSVCDecision] = {}
        uncached: list[str] = []
        for key in ordered:
            if key in self._memo:
                memoed = self._memo[key]
                if memoed is not None:
                    out[key] = memoed
                continue
            hit, record = self._cached_record(key)
            if hit:
                decision = self._decode_guarded(key, record)
                if decision is _DECODE_FAILED:
                    # Poisoned entry evicted — requeue for a fresh
                    # fetch under the normal budget rules.
                    uncached.append(key)
                    continue
                self._memo[key] = decision
                if decision is not None:
                    out[key] = decision
                continue
            uncached.append(key)

        if self._offline or not uncached:
            return out

        skipped = 0
        if fetch_budget is not None and len(uncached) > fetch_budget:
            skipped = len(uncached) - fetch_budget
            uncached = uncached[:fetch_budget]

        def _fetch_one(key: str) -> tuple[str, SSVCDecision | None]:
            try:
                record = self._fetch_remote(key)
            except Exception as e:  # noqa: BLE001 — degrade per id, never
                # let one hostile / malformed response sink the batch
                # (HttpError is already absorbed inside _fetch_remote;
                # this catches transport-layer surprises).
                logger.debug(
                    "core.cve.vulnrichment: lookup failed for %s: %s",
                    key, e,
                )
                return key, None
            decision = self._decode_guarded(key, record)
            return key, None if decision is _DECODE_FAILED else decision

        # Same small-input cutoff as the SCA license-enrichment pass:
        # below a handful of ids the pool spin-up costs more than the
        # sequential walk.
        if len(uncached) <= 4 or max_workers <= 1:
            fetched = [_fetch_one(k) for k in uncached]
        else:
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(
                max_workers=min(max_workers, len(uncached)),
                thread_name_prefix="cve-vulnrichment",
            ) as pool:
                fetched = list(pool.map(_fetch_one, uncached))

        # Memo writes happen on the calling thread — workers only
        # touch the (thread-safe) JsonCache and HttpClient.
        for key, decision in fetched:
            self._memo[key] = decision
            if decision is not None:
                out[key] = decision

        if skipped:
            logger.info(
                "core.cve.vulnrichment: SSVC fetch budget reached — "
                "fetched %d uncached CVE(s), skipped %d (budget %d); "
                "skipped ids degrade to no-signal and are retried by "
                "later runs against the warmed cache",
                len(uncached), skipped, fetch_budget,
            )
        return out

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _decode_guarded(self, cve_id: str, record: dict | None) -> SSVCDecision | None | object:
        """Per-id decode boundary. Returns the decision (or ``None``
        for a signal-less record) — or the ``_DECODE_FAILED`` sentinel
        when :func:`_decode_ssvc` raised on this record.

        ``_decode_ssvc`` is itself written to tolerate any shape, so a
        raise here means decoder drift or a record class it has never
        seen — exactly the case that must degrade ONE id (structured,
        log-visible) rather than sink a scan. On failure the disk
        entry is evicted so an already-poisoned cache (written before
        the validate-before-cache gate below) isn't served for the
        rest of its 7-day TTL.
        """
        if record is None:
            return None
        try:
            return _decode_ssvc(record)
        except Exception as e:  # noqa: BLE001 — decode failure degrades
            # per id; the record shape is upstream-controlled.
            logger.warning(
                "core.cve.vulnrichment: undecodable record for %s "
                "(%s: %s) — degrading to no-signal and evicting the "
                "cached entry",
                cve_id, type(e).__name__, e,
            )
            self._cache.invalidate(f"{_CACHE_KEY_PREFIX}/{cve_id}")
            return _DECODE_FAILED

    def _cached_record(self, cve_id: str) -> tuple[bool, dict | None]:
        """Disk-cache read half of :meth:`_fetch_record`.

        Returns ``(hit, record)`` — ``(True, None)`` is a cached
        negative marker (upstream 404 within its TTL), distinct from
        ``(False, None)`` = never fetched / expired. Split out so
        :meth:`lookup_many` can resolve cache hits without spending
        its network budget on them.
        """
        cache_key = f"{_CACHE_KEY_PREFIX}/{cve_id}"
        cached = self._cache.get(cache_key, ttl_seconds=self._ttl)
        if isinstance(cached, dict):
            if cached.get("_status") == "missing":
                return True, None
            return True, cached
        return False, None

    def _fetch_remote(self, cve_id: str) -> dict | None:
        """Network half of :meth:`_fetch_record`: one upstream GET
        plus the positive / negative cache writes. Thread-safe — the
        injected ``JsonCache`` locks internally and the ``HttpClient``
        backends are shared across worker threads by the existing SCA
        enrichment passes."""
        cache_key = f"{_CACHE_KEY_PREFIX}/{cve_id}"
        url = _url_for_cve(cve_id)
        if url is None:
            return None

        try:
            record = self._http.get_json(url)
        except HttpError as e:
            # 404 is the common case (CVE not yet enriched); 410 is
            # equally authoritative. Cache a negative marker so the
            # next call within the 1-day window doesn't re-probe and
            # waste an HTTP request. ONLY the structured status
            # decides: the message embeds the request URL (which
            # embeds the CVE id — thousands of ids contain "404") and
            # status-less transport errors ("name or service not
            # found") are transient, so any substring fallback turns
            # blips into a day of cached "CISA hasn't enriched this".
            status = getattr(e, "status", None)
            is_missing = (
                status in (404, 410)
                and not getattr(e, "circuit_break", False)
            )
            if is_missing:
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
        # Validate decodability BEFORE the positive cache write: a
        # record the decoder cannot walk must never become a sticky
        # 7-day entry (it would replay the failure — offline runs
        # included — until the TTL expired).
        try:
            _decode_ssvc(record)
        except Exception as e:  # noqa: BLE001 — upstream-controlled shape
            logger.warning(
                "core.cve.vulnrichment: undecodable record for %s "
                "(%s: %s) — not caching; id degrades to no-signal",
                cve_id, type(e).__name__, e,
            )
            return None
        self._cache.put(cache_key, record, ttl_seconds=self._ttl)
        return record


def _url_for_cve(cve_id: str) -> str | None:
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


def _decode_ssvc(record: object) -> SSVCDecision | None:
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
        # ``or {}`` is not shape tolerance: a truthy non-dict (e.g.
        # ``"providerMetadata": "CISA-ADP"``) survives it and crashes
        # the attribute walk. isinstance-gate every lane instead.
        provider_meta = entry.get("providerMetadata")
        if not isinstance(provider_meta, dict):
            continue
        provider = provider_meta.get("shortName")
        if not isinstance(provider, str) or "CISA-ADP" not in provider:
            continue
        metrics = entry.get("metrics")
        if not isinstance(metrics, list):
            continue
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            other = metric.get("other")
            if not isinstance(other, dict):
                continue
            content = other.get("content")
            if not isinstance(content, dict):
                continue
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

"""OSV.dev client — batch vulnerability lookups for ``Dependency`` rows.

OSV is the canonical aggregator across npm / PyPI / Maven / Cargo / Go /
RubyGems / NuGet / Packagist; one client serves every ecosystem.

This module wraps :mod:`packages.osv` (shared OSV.dev wire-format client
+ parser) with SCA-specific concerns: ``Dependency`` ↔ query-dict
mapping, ``Advisory`` domain types, per-query caching keyed off
``Dependency.key()``, chunking at 500-per-call, and offline-DB fallback.
HTTP transport and OSV record parsing live in :mod:`packages.osv`.

Two-pass lookup (unchanged behaviour, internals delegated):

1. ``POST /v1/querybatch`` with up to 1000 ``(name, ecosystem, version)``
   tuples per call → list of vuln IDs per query slot.
2. ``GET /v1/vulns/<id>`` for each unique ID → full advisory JSON we
   translate to ``Advisory`` records.

Caching:

- Per-query (``queries/<eco>-<name>-<ver>``) ID-list cache lives here
  (Dependency-keyed, separate ``query_ttl``).
- Per-vuln (``osv/vulns/<id>``) record cache lives in the shared
  client (uses our cache + ``vuln_ttl``).

Both default to 24-hour TTL; ``--no-cache`` callers bypass via
``ttl_seconds=0``. Offline mode (``offline=True``) skips the network on
both passes — fresh-cache hits still flow through, stale entries are
treated as misses, and missing IDs are silently dropped (operator was
warned at the gate level).

Failure modes:

- Network down: each HTTP error is logged once and converted to an empty
  result for the affected slice; a partial answer is more useful than a
  hard failure for the security gate.
- Single corrupt OSV record: skip with ``debug``-level log; the rest of
  the batch is unaffected.

This module deliberately does **not** know about KEV / EPSS / CVSS
overrides — the ``findings`` layer combines those signals with the
Advisory list.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from packages.cvss.calculator import compute_score_safe  # type: ignore[import-not-found]
from packages.osv import OsvClient as _SharedOsvClient
from packages.osv import OsvRecord, parse_record as _shared_parse_record
from packages.osv.client import OSV_BASE_URL

from core.json import JsonCache
from core.http import HttpClient
from .models import (
    AffectedRange,
    Advisory,
    CVSSScore,
    Dependency,
)

logger = logging.getLogger(__name__)

# Test-compat re-exports — derived from the shared package's base URL so
# they stay in lockstep. Existing tests monkeypatch / format these
# constants directly; preserving them keeps the test surface stable.
OSV_QUERY_BATCH_URL = f"{OSV_BASE_URL}/querybatch"
OSV_VULN_URL_TEMPLATE = f"{OSV_BASE_URL}/vulns/{{}}"

# OSV's ``querybatch`` accepts up to 1000 queries per request. We chunk
# defensively at 500 — leaves headroom in case the limit drops.
_BATCH_CHUNK_SIZE = 500

# Default TTLs (seconds) for OSV cache entries.
_DEFAULT_QUERY_TTL = 24 * 3600
_DEFAULT_VULN_TTL = 24 * 3600

# OSV severity types we care about, in preference order.
_CVSS_TYPES = ("CVSS_V3", "CVSS_V31")

# OSV ecosystem identifiers diverge from RAPTOR's internal names in
# one place: Rust. OSV uses ``crates.io`` (the registry domain) and
# rejects ``Cargo`` with HTTP 400 "Invalid ecosystem", silently zeroing
# every Rust dep's CVE lookup. Internal naming stays ``Cargo`` (matches
# ``Cargo.lock`` / PURL type ``cargo`` / rust-lang/cargo upstream); we
# translate at the OSV query boundary only.
_OSV_ECOSYSTEM_OVERRIDES = {"Cargo": "crates.io"}


def _to_osv_ecosystem(ecosystem: str) -> str:
    return _OSV_ECOSYSTEM_OVERRIDES.get(ecosystem, ecosystem)


@dataclass(frozen=True)
class OsvResult:
    """A single dep's match result.

    ``advisories`` is the post-processed list — empty when no advisories
    apply or when offline mode + cache miss combined to drop the lookup.
    """

    dep_key: str          # ``Dependency.key()`` — "ecosystem:name@version"
    advisories: List[Advisory]


class OsvClient:
    """Thin OSV.dev client with caching.

    Construct one per ``raptor-sca`` run and pass to ``query_batch``. Wraps
    :class:`packages.osv.OsvClient` with the SCA-specific per-query
    cache layer (``Dependency.key()`` keyed), chunking, and offline-DB
    fallback.
    """

    def __init__(
        self,
        http: HttpClient,
        cache: JsonCache,
        *,
        offline: bool = False,
        query_ttl: int = _DEFAULT_QUERY_TTL,
        vuln_ttl: int = _DEFAULT_VULN_TTL,
        offline_db=None,
    ) -> None:
        self._cache = cache
        self._offline = offline
        self._query_ttl = query_ttl
        # Shared client owns per-vuln caching + HTTP transport. We pass
        # the same cache + the vuln TTL through; per-query caching stays
        # in this class because the key shape (``Dependency.key()``) is
        # SCA-specific.
        self._inner = _SharedOsvClient(
            http=http,
            cache=cache,
            offline=offline,
            ttl_seconds=vuln_ttl,
        )
        # Optional ``OsvOfflineDB`` — when supplied AND ``offline=True``,
        # cache misses route to the offline DB instead of failing silently.
        self._offline_db = offline_db

    def query_batch(self, deps: Sequence[Dependency]) -> List[OsvResult]:
        """Look up advisories for every dep that has a known version.

        Deps with ``version=None`` (unpinned manifest entries) are
        skipped — OSV's match semantics need a concrete version.
        """
        unique_keys: Dict[str, Dependency] = {}
        for d in deps:
            if d.version is None:
                continue
            unique_keys.setdefault(d.key(), d)

        # Pass 1: per-query ID lookup (cache + remote via shared client).
        dep_to_ids: Dict[str, List[str]] = {}
        uncached: List[Dependency] = []
        for key, dep in unique_keys.items():
            cached = self._cache.get(
                self._query_key(dep), ttl_seconds=self._query_ttl,
            )
            if cached is not None and isinstance(cached, list):
                dep_to_ids[key] = [str(i) for i in cached]
            else:
                uncached.append(dep)

        if uncached and not self._offline:
            # OSV's ``/querybatch`` rejects the WHOLE batch (HTTP 400
            # "Invalid ecosystem") if any single query carries an
            # ecosystem OSV doesn't index. Most multi-manifest scans
            # surface deps from ecosystems OSV doesn't have an index
            # for (``GitHub`` from .gitmodules / FetchContent rows,
            # ``Debian`` from apt-cached Dockerfile installs, etc.) —
            # without filtering, ONE such dep makes the entire batch
            # return empty, and every legitimate PyPI / npm / Maven
            # dep silently misses every advisory. Pre-filter against
            # the known list so unsupported deps fall through to the
            # OSS-Fuzz fallback (pass 1.5) and the offline-DB path
            # without poisoning the primary batch.
            from .ecosystems import KNOWN_ECOSYSTEMS
            _OSV_QUERYABLE = {
                e for e in KNOWN_ECOSYSTEMS
                # OSS-Fuzz is queried only via the dedicated fallback
                # path (different candidate-name mapping), not the
                # primary batch.
                if e != "OSS-Fuzz"
            }
            queryable = [d for d in uncached
                         if d.ecosystem in _OSV_QUERYABLE]
            non_queryable = [d for d in uncached
                             if d.ecosystem not in _OSV_QUERYABLE]
            # Build all chunk-payloads up front so the parallel
            # dispatch below has a flat list to map over.
            chunk_payloads: List[Tuple[List["Dependency"], List[Dict]]] = []
            for chunk in _chunked(queryable, _BATCH_CHUNK_SIZE):
                queries = [
                    {
                        "package": {
                            "name": d.name,
                            "ecosystem": _to_osv_ecosystem(d.ecosystem),
                        },
                        "version": d.version,
                    }
                    for d in chunk
                ]
                chunk_payloads.append((list(chunk), queries))

            # Parallel /querybatch dispatch. Each batch hits OSV with
            # ~500 deps; sequential traversal of N chunks costs the
            # sum of per-batch RTTs, which dominates large scans
            # (strapi-3: 3326 deps = 7 chunks × ~1s each = 7s pre-fix).
            # OSV publishes a soft rate limit but doesn't enforce
            # bursts of small numbers; capping workers at 4 keeps us
            # well below any per-IP threshold while parallelising the
            # critical-path RTT. The per-host circuit breaker
            # (core/http/urllib_backend) catches any genuine 429
            # storm and fails subsequent calls fast.
            #
            # ``self._inner.query_batch`` failures are absorbed
            # already by the inner client (returns ``[[]]`` per
            # query on HTTP error), so we don't need a try/except
            # in the worker — propagated exceptions are programmer
            # errors, not transient.
            def _query_one_chunk(
                payload: Tuple[List["Dependency"], List[Dict]],
            ) -> Tuple[List["Dependency"], List[List[str]]]:
                chunk, queries = payload
                results = self._inner.query_batch(queries)
                return chunk, results

            if len(chunk_payloads) >= 2:
                from concurrent.futures import ThreadPoolExecutor
                max_workers = min(4, len(chunk_payloads))
                with ThreadPoolExecutor(
                    max_workers=max_workers,
                    thread_name_prefix="sca-osv-batch",
                ) as pool:
                    chunk_results = list(pool.map(
                        _query_one_chunk, chunk_payloads,
                    ))
            else:
                # 0 or 1 chunks — no parallelism benefit; avoid the
                # ThreadPoolExecutor overhead.
                chunk_results = [
                    _query_one_chunk(p) for p in chunk_payloads
                ]

            for chunk, results in chunk_results:
                for dep, ids in zip(chunk, results):
                    self._cache.put(
                        self._query_key(dep), ids,
                        ttl_seconds=self._query_ttl,
                    )
                    dep_to_ids[dep.key()] = ids
            # Empty-ID rows for non-queryable ecosystems so the OSS-Fuzz
            # fallback (next pass) sees them as "primary returned
            # nothing" and engages the retry path. Without this, those
            # deps would be missing from `dep_to_ids` and the fallback
            # logic that walks unique_keys would still hit them — but
            # cache them with empty so a re-run doesn't hammer.
            for d in non_queryable:
                self._cache.put(
                    self._query_key(d), [],
                    ttl_seconds=self._query_ttl,
                )
                dep_to_ids[d.key()] = []

        # Pass 1.5: OSS-Fuzz fallback for C/C++ deps. OSV's
        # ``vcpkg`` and ``ConanCenter`` ecosystems are sparse;
        # ``ecosystem="GitHub"`` (gitmodules + CMake FetchContent) has
        # no OSV index at all. OSS-Fuzz indexes ~700 widely-used
        # C/C++ projects under the ``OSS-Fuzz`` ecosystem, keyed by
        # OSS-Fuzz project name (typically the upstream package
        # name). For any dep above where the primary query came back
        # empty, retry with an OSS-Fuzz candidate name.
        #
        # Cached separately (different query_key) so primary +
        # fallback get independent TTL handling. IDs from both
        # passes merge into ``dep_to_ids`` before pass 2's vuln
        # hydration.
        self._osssfuzz_fallback(unique_keys, dep_to_ids)

        # Offline-DB fallback: when ``offline=True`` and an OsvOfflineDB
        # is wired in, query it directly for any dep that didn't get a
        # hit from the per-query JSON cache. This bypasses the dep_to_ids
        # → vuln_records hydration path because the offline DB returns
        # full ``Advisory`` objects in one shot.
        offline_db_advisories: Dict[str, List[Advisory]] = {}
        if self._offline and self._offline_db is not None and uncached:
            for dep in uncached:
                try:
                    advs = self._offline_db.query(
                        dep.ecosystem, dep.name, dep.version,
                    )
                except Exception as e:                  # noqa: BLE001
                    logger.warning(
                        "sca.osv: offline DB query failed for %s: %s",
                        dep.key(), e,
                    )
                    advs = []
                offline_db_advisories[dep.key()] = advs

        # Pass 2: hydrate unique vuln IDs via shared client.
        all_ids = sorted({i for ids in dep_to_ids.values() for i in ids})
        vuln_records: Dict[str, Advisory] = {}
        for vid in all_ids:
            record = self._inner.get_vuln(vid)
            if record is None:
                continue
            try:
                vuln_records[vid] = _record_to_advisory(record)
            except Exception as e:                # noqa: BLE001 — best-effort
                logger.debug(
                    "sca.osv: skipping malformed advisory %s: %s", vid, e,
                )

        # Project back to per-dep results, preserving input order.
        out: List[OsvResult] = []
        seen_keys: set[str] = set()
        for d in deps:
            if d.version is None or d.key() in seen_keys:
                continue
            seen_keys.add(d.key())
            ids = dep_to_ids.get(d.key(), [])
            advisories = [vuln_records[i] for i in ids if i in vuln_records]
            # Merge offline-DB hits, deduping on osv_id.
            already_have = {a.osv_id for a in advisories}
            for adv in offline_db_advisories.get(d.key(), []):
                if adv.osv_id not in already_have:
                    advisories.append(adv)
                    already_have.add(adv.osv_id)
            out.append(OsvResult(
                dep_key=d.key(), advisories=advisories,
            ))
        return out

    # ------------------------------------------------------------------
    # Internals — keys
    # ------------------------------------------------------------------

    @staticmethod
    def _query_key(dep: Dependency) -> str:
        # Path-segment safe; cache.JsonCache sanitises further.
        eco = dep.ecosystem.replace("/", "_")
        name = dep.name.replace("/", "_")
        ver = (dep.version or "*").replace("/", "_")
        return f"queries/{eco}/{name}/{ver}"

    @staticmethod
    def _osssfuzz_query_key(dep: Dependency, candidate: str) -> str:
        """Cache key for the OSS-Fuzz fallback query.

        Distinct from ``_query_key`` so primary + fallback have
        independent TTL handling. Same candidate name across
        different deps shares the same cache entry — OSS-Fuzz
        ecosystem + name + version is the canonical key.
        """
        name = candidate.replace("/", "_")
        ver = (dep.version or "*").replace("/", "_")
        return f"queries/OSS-Fuzz/{name}/{ver}"

    def _osssfuzz_fallback(
        self,
        unique_keys: Dict[str, Dependency],
        dep_to_ids: Dict[str, List[str]],
    ) -> None:
        """Mutate ``dep_to_ids`` in place with OSS-Fuzz query results
        for C/C++ deps that came back empty from the primary query.

        Two-pass: cache first, then a single batch HTTP query for
        the remainder. Each candidate name produces one OSS-Fuzz
        query. When multiple deps share the same candidate name +
        version (rare; happens when the same dep is declared in
        both vcpkg.json and a sibling Conan file), the cache
        deduplicates.

        Adds, never removes — a dep that already has primary IDs
        is skipped entirely. Merging at the dep_to_ids level is
        deduplication-safe because pass 2 below builds
        ``all_ids = sorted(set(...))`` before hydration.
        """
        if self._offline:
            # The offline DB doesn't index OSS-Fuzz separately from
            # the per-ecosystem JSON files. Skip the fallback rather
            # than emit misleading offline-mode "no advisories" rows.
            return

        # Build candidate work: only deps with empty primary results
        # AND a non-empty OSS-Fuzz candidate list.
        work: List[Tuple[Dependency, str]] = []
        for key, dep in unique_keys.items():
            if dep_to_ids.get(key):
                continue
            for candidate in _oss_fuzz_candidates(dep):
                work.append((dep, candidate))

        if not work:
            return

        # Cache pass.
        uncached: List[Tuple[Dependency, str]] = []
        for dep, candidate in work:
            cached = self._cache.get(
                self._osssfuzz_query_key(dep, candidate),
                ttl_seconds=self._query_ttl,
            )
            if cached is not None and isinstance(cached, list):
                ids = [str(i) for i in cached]
                if ids:
                    dep_to_ids.setdefault(dep.key(), []).extend(ids)
            else:
                uncached.append((dep, candidate))

        if not uncached:
            return

        # Batch HTTP pass — same chunk size as primary.
        for chunk in _chunked(uncached, _BATCH_CHUNK_SIZE):
            queries = [
                {
                    "package": {"name": candidate, "ecosystem": "OSS-Fuzz"},
                    "version": dep.version,
                }
                for dep, candidate in chunk
            ]
            results = self._inner.query_batch(queries)
            for (dep, candidate), ids in zip(chunk, results):
                self._cache.put(
                    self._osssfuzz_query_key(dep, candidate), ids,
                    ttl_seconds=self._query_ttl,
                )
                if ids:
                    dep_to_ids.setdefault(dep.key(), []).extend(ids)


# ---------------------------------------------------------------------------
# OSV record → Advisory translation
# ---------------------------------------------------------------------------

def _oss_fuzz_candidates(dep: Dependency) -> List[str]:
    """Return OSS-Fuzz package-name candidates for a C/C++ dep.

    OSS-Fuzz package names typically match the upstream library
    name. We pick a single best-effort candidate per dep; if the
    OSS-Fuzz project name differs (rare, but happens — e.g.
    ``boringssl`` vs ``boringssl-with-bazel``), the query simply
    returns no advisories and SCA falls through.

    Mapping:
      * ``vcpkg`` / ``ConanCenter`` ecosystems: dep.name as-is.
        OSS-Fuzz coverage typically uses the upstream library
        name and so do these registries.
      * ``GitHub`` ecosystem (.gitmodules / FetchContent rows):
        repo basename, e.g. ``"openssl/openssl"`` →
        ``"openssl"``. This matches the OSS-Fuzz project name
        for most projects that are hosted at
        ``github.com/<name>/<name>`` (the common convention for
        single-project orgs).
      * Other ecosystems: empty list (no fallback).

    Single-element list rather than multi-candidate to avoid
    explosive query growth. Misses are tolerated; the fallback
    is best-effort by design.
    """
    eco = dep.ecosystem
    if eco in ("vcpkg", "ConanCenter"):
        # Conan-style names sometimes carry a "/" separator
        # ("openssl/3.0.0" → name "openssl", version "3.0.0") but
        # the parser already splits these. Strip defensively in
        # case a future caller passes the unstripped form.
        return [dep.name.split("/", 1)[0]] if dep.name else []
    if eco == "GitHub":
        # ``dep.name`` is "owner/repo"; OSS-Fuzz uses the repo
        # basename for projects hosted at github.com/X/X.
        if "/" in dep.name:
            _, repo = dep.name.split("/", 1)
            return [repo] if repo else []
        return [dep.name] if dep.name else []
    return []


def parse_osv_record(record: Dict[str, Any]) -> Advisory:
    """Translate an OSV vulnerability record into our ``Advisory``.

    Wire-format parsing is delegated to :func:`packages.osv.parse_record`;
    this function adds SCA's domain mapping (CVSS computation, fixed-
    version collection, ``ecosystem_specific`` extraction).

    Fields beyond what's promoted to ``Advisory`` are reachable via the
    underlying ``OsvRecord.raw`` dict if a future caller needs them.
    """
    return _record_to_advisory(_shared_parse_record(record))


def _record_to_advisory(rec: OsvRecord) -> Advisory:
    affected = _affected_from_record(rec)
    fixed_versions = _collect_fixed_versions(affected)
    severity = _highest_cvss_v3(rec)
    refs = [r.url for r in rec.references]

    # Stash anything else under ecosystem_specific for downstream access
    # (Go function-level reachability uses ``ecosystem_specific.imports``).
    # First non-None block wins, matching prior behaviour.
    ecosystem_specific: Optional[Dict[str, Any]] = None
    for blk in rec.affected:
        if blk.ecosystem_specific is not None:
            ecosystem_specific = blk.ecosystem_specific
            break

    # RUSTSEC (and a small number of other ecos) carry an
    # ``informational`` flag on ``affected[].database_specific``
    # marking the advisory as a soundness / quality concern
    # rather than a security vulnerability. Surface it onto the
    # Advisory so calibration consumers can skip these from
    # exploitation ground-truth (treating them as exploited would
    # inflate the signal set with non-security records). First
    # non-empty value across affected blocks wins.
    informational: Optional[str] = None
    for blk in rec.affected:
        ds = blk.database_specific
        if isinstance(ds, dict):
            v = ds.get("informational")
            if isinstance(v, str) and v.strip():
                informational = v.strip()
                break

    return Advisory(
        osv_id=rec.id,
        aliases=list(rec.aliases),
        summary=rec.summary,
        details=rec.details,
        affected=affected,
        severity=severity,
        fixed_versions=fixed_versions,
        references=refs,
        published=rec.published,
        modified=rec.modified,
        ecosystem_specific=ecosystem_specific,
        informational=informational,
    )


def _affected_from_record(rec: OsvRecord) -> List[AffectedRange]:
    out: List[AffectedRange] = []
    for blk in rec.affected:
        for r in blk.ranges:
            out.append(AffectedRange(
                type=r.type,        # type: ignore[arg-type]
                events=[dict(ev) for ev in r.events],
                repo=r.repo,
            ))
    return out


def _collect_fixed_versions(affected: List[AffectedRange]) -> List[str]:
    fixed: List[str] = []
    for r in affected:
        for ev in r.events:
            if "fixed" in ev:
                fixed.append(ev["fixed"])
    # De-duplicate while preserving order.
    seen: set[str] = set()
    deduped: List[str] = []
    for v in fixed:
        if v not in seen:
            seen.add(v)
            deduped.append(v)
    return deduped


def _highest_cvss_v3(rec: OsvRecord) -> Optional[CVSSScore]:
    """Pick the highest CVSS v3.x entry; compute numeric score from vector.

    ``packages.cvss.calculator`` accepts vectors with optional temporal
    or environmental extensions (e.g. Log4Shell's ``…/A:H/E:H``); we
    pass them through verbatim and the base-only score is returned.
    """
    best: Optional[Tuple[float, str, str]] = None
    for entry in rec.severity:
        if entry.type not in _CVSS_TYPES:
            continue
        score, severity_label = compute_score_safe(entry.score)
        if score is None or severity_label is None:
            continue
        if best is None or score > best[0]:
            best = (score, entry.score, severity_label.lower())
    if best is None:
        return None
    score, vector, severity_label = best
    valid_levels = {"none", "low", "medium", "high", "critical"}
    if severity_label not in valid_levels:
        severity_label = _bucket_score(score)
    return CVSSScore(score=score, vector=vector, severity=severity_label)  # type: ignore[arg-type]


def _bucket_score(score: float) -> str:
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def _chunked(items: Sequence[Any], size: int) -> Iterable[Sequence[Any]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


__all__ = ["OsvClient", "OsvResult", "parse_osv_record"]

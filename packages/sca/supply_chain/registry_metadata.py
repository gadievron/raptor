"""Registry-metadata supply-chain detectors.

Five detectors that all share the per-package metadata fetched from
the upstream registry -- bundled here so we make one HTTP call per dep
across the suite:

  - ``recent_publish`` -- package first published < 30 days ago.
  - ``version_publish`` -- latest *version* published within N days
    (configurable, default 7) on a package that had been dormant.
  - ``maintainer_change`` -- maintainer list changed between the
    two most recent versions (npm exposes per-version maintainers),
    or a maintainer ``joined_at`` is within 14 days (future enriched
    feeds).
  - ``maintainer_account_change`` -- a maintainer's email changed
    within 14 days of a new release (the Axios npm pattern, March 2026).
  - ``low_bus_factor`` -- single maintainer on a package (PyPI author
    or npm maintainers list of length 1).

Each emits a ``RegistryMetaFinding`` row consumed by ``__init__.py``'s
orchestrator.  A final severity-escalation pass adjusts severity based
on co-occurrence: recent-publish alone is ``info``, combined with
maintainer-change is ``medium``, combined with maintainer-change +
dormant is ``high``.
"""

from __future__ import annotations

import logging
import threading as _threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from ..models import Confidence, Dependency

logger = logging.getLogger(__name__)


_RECENT_PUBLISH_DAYS = 30
_VERSION_PUBLISH_DAYS = 7
_MAINTAINER_CHANGE_DAYS = 14
_DORMANT_DAYS = 365


@dataclass
class RegistryMetaFinding:
    """One detector hit from the registry-metadata bundle."""

    kind: str                                # "recent_publish" |
                                              # "version_publish" |
                                              # "maintainer_change" |
                                              # "maintainer_account_change" |
                                              # "low_bus_factor" |
                                              # "payload_size_spike"
    dependency: Dependency
    detail: str
    evidence: Dict[str, Any]
    severity: str
    confidence: Confidence


def scan_deps(
    deps: Iterable[Dependency],
    *,
    pypi_client=None,
    npm_client=None,
    now: Optional[datetime] = None,
    recent_publish_days: int = _RECENT_PUBLISH_DAYS,
    version_publish_days: int = _VERSION_PUBLISH_DAYS,
    dormant_days: int = _DORMANT_DAYS,
) -> List[RegistryMetaFinding]:
    """Run all registry-metadata detectors over direct deps only.

    ``pypi_client`` and ``npm_client`` are the canonical
    ``packages/sca/registries/{pypi,npm}.py`` clients -- passed in so
    callers can wire ``offline``, ``cache``, etc. consistently with the
    rest of the run.
    """
    now = now or datetime.now(timezone.utc)
    # Dedup by (ecosystem, name): monorepos with many package.json
    # workspaces (Grafana, NX, Lerna) repeat the same direct-dep
    # declaration across multiple manifests. Without dedup the
    # ThreadPoolExecutor below launches one worker per occurrence,
    # all of which miss the cache concurrently and fire the same
    # HTTP request in parallel — a thundering-herd race observed
    # on Grafana's 50+ workspace manifests during the May 2026
    # 200-project sweep (single name produced 8 simultaneous 404s).
    # Findings are emitted per-Dependency anyway: an upstream
    # consumer that wants per-manifest evidence walks the orig
    # ``deps`` list, not this one.
    direct_deps_all = [d for d in deps if d.direct]
    if not direct_deps_all:
        return []
    seen_keys: set = set()
    direct_deps: List[Dependency] = []
    for d in direct_deps_all:
        key = (d.ecosystem, d.name)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        direct_deps.append(d)

    def _scan_one(dep: Dependency) -> List[RegistryMetaFinding]:
        meta = _fetch(dep, pypi_client=pypi_client, npm_client=npm_client)
        if meta is None:
            return []
        dep_findings: List[RegistryMetaFinding] = []
        dep_findings.extend(_recent_publish_check(dep, meta, now,
                                                   threshold=recent_publish_days))
        dep_findings.extend(_version_publish_check(dep, meta, now,
                                                    threshold=version_publish_days,
                                                    dormant_threshold=dormant_days))
        dep_findings.extend(_maintainer_change_check(dep, meta, now))
        dep_findings.extend(_maintainer_account_change_check(dep, meta, now))
        dep_findings.extend(_low_bus_factor_check(dep, meta))
        dep_findings.extend(_payload_size_check(dep, meta))
        # Severity escalation based on co-occurrence for this dep.
        _escalate_severity(dep_findings, meta)
        return dep_findings

    # Parallelise per-dep — each ``_fetch`` is HTTP- or cache-bound
    # and independent of every other dep. With 700+ direct deps in a
    # multi-manifest app (saleor-style) the sequential loop spent
    # ~2.7s; the thread pool brings it under ~0.5s. Worker count
    # matches the pattern used elsewhere in SCA (transitive cascade,
    # OSV); higher concurrency makes negligible additional dent
    # because the JsonCache memo dominates after the first pass and
    # the HTTP-side concurrency is already capped by the egress
    # proxy's tunnel ceiling.
    out: List[RegistryMetaFinding] = []
    if len(direct_deps) <= 4:
        # Below the worker-count threshold the executor's spin-up
        # overhead exceeds the sequential cost. Walk straight.
        for dep in direct_deps:
            out.extend(_scan_one(dep))
        return out
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8,
                             thread_name_prefix="sca-registry-meta") as pool:
        for findings in pool.map(_scan_one, direct_deps):
            out.extend(findings)
    return out


# ---------------------------------------------------------------------------
# Per-ecosystem metadata adapter
# ---------------------------------------------------------------------------

@dataclass
class _Meta:
    """Normalised view of a package's registry metadata."""

    first_publish: Optional[datetime] = None
    latest_publish: Optional[datetime] = None
    second_latest_publish: Optional[datetime] = None
    maintainers: List[Dict[str, Any]] = field(default_factory=list)
    # ``[{name, email, joined_at?, last_email_change?}, ...]``
    previous_maintainers: List[Dict[str, Any]] = field(default_factory=list)
    # maintainer list from the second-most-recent version (npm only)
    is_dormant: bool = False
    # True when the gap between latest and second-latest publish exceeds
    # _DORMANT_DAYS.
    version_sizes: Dict[str, int] = field(default_factory=dict)
    # Per-version unpacked tarball size in bytes. npm-only — populated
    # from ``versions[v].dist.unpackedSize``. Used by the payload-size-
    # spike detector to compare a freshly-installed version against
    # the immediately-prior version's footprint.
    version_chronology: List[str] = field(default_factory=list)
    # Versions in publish-order (oldest → newest). Enables finding the
    # version PUBLISHED IMMEDIATELY BEFORE the dep's installed version
    # without re-walking the raw timestamps dict.


# Process-lifetime memo of the *extracted* ``_Meta`` keyed on
# ``(ecosystem, name)``. The underlying ``JsonCache`` already
# memoises the raw registry JSON; this layer caches the post-parse
# shape so repeat consumers (typosquat, sentinel-names, version-
# publish-recency, maintainer-change, low-bus-factor — five
# detectors per dep) don't re-walk the same raw JSON 5× to
# recompute identical ``first_publish`` / ``latest_publish`` /
# ``maintainers`` / ``previous_maintainers`` values.
#
# pre-fix profile: ``_from_pypi`` consumed ~3.5s of a saleor scan
# (548 calls × 6.4ms each — full ISO-8601 walk of every release's
# files, plus maintainer aggregation). Each unique (ecosystem,
# name) gets parsed once; subsequent ``_fetch`` calls in the same
# run are dict lookups.
#
# Lock: ``scan_deps`` parallelises ``_fetch`` across 8 worker
# threads (commit ac4932bf), so the memo is touched concurrently.
# We use a threading.Lock to keep the read-then-store atomic;
# duplicate parses from a check-then-set race are rare and
# harmless (whichever thread wins the store overwrites with an
# identical value).
_META_CACHE: Dict[tuple, Optional["_Meta"]] = {}
_META_CACHE_LOCK = _threading.Lock()
_META_CACHE_SENTINEL = object()


def _fetch(
    dep: Dependency, *, pypi_client, npm_client,
) -> Optional[_Meta]:
    key = (dep.ecosystem, dep.name)
    with _META_CACHE_LOCK:
        cached = _META_CACHE.get(key, _META_CACHE_SENTINEL)
    if cached is not _META_CACHE_SENTINEL:
        return cached  # type: ignore[return-value]

    meta: Optional[_Meta] = None
    if dep.ecosystem == "PyPI" and pypi_client is not None:
        try:
            raw = pypi_client.get_metadata(dep.name)
        except Exception:  # noqa: BLE001
            logger.debug("registry_metadata: PyPI fetch error for %r",
                         dep.name, exc_info=True)
            raw = None
        meta = _from_pypi(raw) if raw else None
    elif dep.ecosystem == "npm" and npm_client is not None:
        try:
            raw = npm_client.get_metadata(dep.name)
        except Exception:  # noqa: BLE001
            logger.debug("registry_metadata: npm fetch error for %r",
                         dep.name, exc_info=True)
            raw = None
        meta = _from_npm(raw) if raw else None
    # Other ecosystems: no metadata source wired in this layer yet.
    with _META_CACHE_LOCK:
        _META_CACHE[key] = meta
    return meta


def _reset_meta_cache_for_tests() -> None:
    """Clear the per-run memo. Tests that exercise the parse path
    repeatedly need to evict between cases."""
    with _META_CACHE_LOCK:
        _META_CACHE.clear()


# Recognised PEP-621 / PEP-639 metadata keys that can leak into a
# package's ``author`` field via malformed pyproject.toml at publish
# time. We strip any of these (and everything after them) from
# author / maintainer strings before treating the remainder as a
# real person.
_PEP621_TRAILER_KEYS = (
    "License-Expression",
    "License-File",
    "License",
    "Author-email",
    "Maintainer-email",
)


def _strip_pep621_trailer(name: str) -> str:
    """Strip a recognised PEP-621/PEP-639 key plus its value off the
    end of a free-text author/maintainer string.

    Example: ``"Microsoft Corporation License-Expression: Apache-2.0"``
    → ``"Microsoft Corporation"``. The PyPI 1.58.0 JSON for playwright
    shipped exactly this shape, which without the strip registered
    as a single-maintainer with an unhelpful name.
    """
    for key in _PEP621_TRAILER_KEYS:
        # Look for the key followed by ``:`` somewhere in the
        # string; everything from that key onward is metadata, not
        # name. Whitespace-tolerant — ``License-Expression:`` and
        # ``License-Expression :`` and ``License-Expression\t:`` all
        # match.
        idx = name.find(key)
        if idx == -1:
            continue
        # Require ``:`` after the key (with optional whitespace).
        # Otherwise we'd wrongly strip a real name like
        # ``License Co.`` that happens to contain ``License``.
        after_key = name[idx + len(key):]
        stripped = after_key.lstrip()
        if stripped.startswith(":"):
            return name[:idx].rstrip()
    return name.strip()


def _from_pypi(raw: dict) -> _Meta:
    """Normalise PyPI's JSON shape.

    PyPI publish timestamps live under ``releases[<ver>][i].upload_time_iso_8601``.
    Maintainer info isn't published as structured data -- only the
    project-page listing of authors. We surface ``info.author`` /
    ``info.maintainer`` as a best-effort single entry.
    """
    info = raw.get("info") or {}
    releases = raw.get("releases") or {}
    # Collect per-version first-publish timestamps.
    version_timestamps: List[datetime] = []
    if isinstance(releases, dict):
        for files in releases.values():
            if not isinstance(files, list):
                continue
            earliest_for_ver: Optional[datetime] = None
            for f in files:
                if not isinstance(f, dict):
                    continue
                ts = _parse_iso(f.get("upload_time_iso_8601"))
                if ts:
                    if earliest_for_ver is None or ts < earliest_for_ver:
                        earliest_for_ver = ts
            if earliest_for_ver is not None:
                version_timestamps.append(earliest_for_ver)
    version_timestamps.sort()
    maintainers: List[Dict[str, Any]] = []
    for field_name in ("maintainer", "author"):
        n = info.get(field_name)
        if not (isinstance(n, str) and n.strip()):
            continue
        email_field = f"{field_name}_email"
        emails_raw = (info.get(email_field) or "").strip()
        # PyPI convention: ``author`` / ``maintainer`` is a free-text
        # field that's comma-separated when there are multiple people.
        # Same goes for the parallel ``*_email`` fields. Split both,
        # zip into individual records — without this, a project with
        # 7 listed authors registers as a single-maintainer
        # low_bus_factor. (npm exposes maintainers as a structured
        # array; this is a PyPI-only quirk.)
        names = [s.strip() for s in n.split(",") if s.strip()]
        # Defensive: some packages malform their pyproject.toml so
        # that PEP-621 / PEP-639 metadata trailers leak into the
        # ``author`` field at publish time. PyPI 1.58.0 returns
        # playwright's author as ``"Microsoft Corporation
        # License-Expression: Apache-2.0"`` for exactly this
        # reason. Strip the recognised trailing keys before
        # treating the remainder as a real name.
        names = [_strip_pep621_trailer(s) for s in names]
        names = [s for s in names if s]
        email_list = [s.strip() for s in emails_raw.split(",") if s.strip()]
        for i, person in enumerate(names):
            maintainers.append({
                "name": person,
                "email": email_list[i] if i < len(email_list) else None,
            })
    first_pub = version_timestamps[0] if version_timestamps else None
    latest_pub = version_timestamps[-1] if version_timestamps else None
    second_latest = (version_timestamps[-2]
                     if len(version_timestamps) >= 2 else None)
    is_dormant = False
    if latest_pub and second_latest:
        is_dormant = (latest_pub - second_latest).days >= _DORMANT_DAYS
    return _Meta(
        first_publish=first_pub,
        latest_publish=latest_pub,
        second_latest_publish=second_latest,
        maintainers=maintainers,
        is_dormant=is_dormant,
    )


def _from_npm(raw: dict) -> _Meta:
    """Normalise npm registry shape.

    npm publishes per-version timestamps under ``time.<ver>``. The full
    maintainer list is in ``maintainers``.  Per-version metadata is in
    ``versions.<ver>._npmUser`` and ``versions.<ver>.maintainers``.
    """
    times = raw.get("time") or {}
    # Collect per-version timestamps (excluding created/modified meta-keys).
    version_entries: List[tuple] = []  # (datetime, version_key)
    if isinstance(times, dict):
        for k, v in times.items():
            if k in ("created", "modified"):
                continue
            if isinstance(v, str):
                ts = _parse_iso(v)
                if ts:
                    version_entries.append((ts, k))
    version_entries.sort(key=lambda x: x[0])
    first_pub = version_entries[0][0] if version_entries else None
    latest_pub = version_entries[-1][0] if version_entries else None
    second_latest_pub = (version_entries[-2][0]
                         if len(version_entries) >= 2 else None)
    second_latest_ver = (version_entries[-2][1]
                         if len(version_entries) >= 2 else None)
    is_dormant = False
    if latest_pub and second_latest_pub:
        is_dormant = (latest_pub - second_latest_pub).days >= _DORMANT_DAYS

    # Top-level maintainers (current).
    raw_maint = raw.get("maintainers") or []
    maintainers: List[Dict[str, Any]] = []
    if isinstance(raw_maint, list):
        for m in raw_maint:
            if isinstance(m, dict):
                maintainers.append({
                    "name": m.get("name", ""),
                    "email": m.get("email", ""),
                })

    # Per-version maintainer comparison: extract maintainer list from
    # the second-most-recent version to detect maintainer additions.
    previous_maintainers: List[Dict[str, Any]] = []
    versions_obj = raw.get("versions") or {}
    if isinstance(versions_obj, dict) and second_latest_ver:
        prev_ver_data = versions_obj.get(second_latest_ver)
        if isinstance(prev_ver_data, dict):
            prev_maint_raw = prev_ver_data.get("maintainers") or []
            if isinstance(prev_maint_raw, list):
                for m in prev_maint_raw:
                    if isinstance(m, dict):
                        previous_maintainers.append({
                            "name": m.get("name", ""),
                            "email": m.get("email", ""),
                        })

    # Per-version unpacked tarball sizes. Populated only when the
    # registry document carries ``dist.unpackedSize`` (set by npm
    # publish in v6+); legacy packages without it leave the map
    # empty and the payload-size detector skips them. Don't fall
    # back to ``dist.size`` (compressed tarball) — that's not
    # directly comparable to the unpacked-bytes value.
    version_sizes: Dict[str, int] = {}
    if isinstance(versions_obj, dict):
        for ver, ver_data in versions_obj.items():
            if not isinstance(ver_data, dict):
                continue
            dist = ver_data.get("dist")
            if not isinstance(dist, dict):
                continue
            sz = dist.get("unpackedSize")
            if isinstance(sz, int) and sz > 0:
                version_sizes[ver] = sz

    return _Meta(
        first_publish=first_pub,
        latest_publish=latest_pub,
        second_latest_publish=second_latest_pub,
        maintainers=maintainers,
        previous_maintainers=previous_maintainers,
        is_dormant=is_dormant,
        version_sizes=version_sizes,
        version_chronology=[v for _, v in version_entries],
    )


# ---------------------------------------------------------------------------
# Detector: recent_publish (package first published recently)
# ---------------------------------------------------------------------------

def _recent_publish_check(
    dep: Dependency, meta: _Meta, now: datetime,
    *, threshold: int = _RECENT_PUBLISH_DAYS,
) -> List[RegistryMetaFinding]:
    if meta.first_publish is None:
        return []
    age_days = (now - meta.first_publish).days
    if age_days >= threshold:
        return []
    detail = (
        f"package {dep.ecosystem}:{dep.name} was first published "
        f"{age_days} days ago -- under the {threshold}-day "
        f"threshold for recent-publish review"
    )
    return [RegistryMetaFinding(
        kind="recent_publish",
        dependency=dep,
        detail=detail,
        evidence={"first_publish": meta.first_publish.isoformat(),
                  "age_days": age_days},
        severity="info",
        confidence=Confidence("high",
                               reason="registry publish timestamp"),
    )]


# ---------------------------------------------------------------------------
# Detector: version_publish (latest version published recently,
#   especially on a dormant package)
# ---------------------------------------------------------------------------

def _version_publish_check(
    dep: Dependency, meta: _Meta, now: datetime,
    *, threshold: int = _VERSION_PUBLISH_DAYS,
    dormant_threshold: int = _DORMANT_DAYS,
) -> List[RegistryMetaFinding]:
    """Flag when the latest version was published within ``threshold`` days.

    Fresh publishes on dormant packages are particularly suspicious --
    the severity is elevated when the package had no releases for over
    ``dormant_threshold`` days before this one.
    """
    if meta.latest_publish is None:
        return []
    age_days = (now - meta.latest_publish).days
    if age_days >= threshold:
        return []
    # Routine publishes on actively-maintained packages are not a
    # supply-chain signal — they're just normal release cadence
    # (anthropic, openai, claude-code etc. publish daily). The
    # interesting case is a fresh publish on a previously-dormant
    # package, which is the classic account-takeover pattern.
    # Without this filter the report drowns in Info-level entries
    # for every actively-maintained dep.
    if not meta.is_dormant:
        return []
    sev = "medium"                          # only fires when dormant now
    dormant_detail = ""
    if meta.second_latest_publish is not None:
        gap = (meta.latest_publish - meta.second_latest_publish).days
        dormant_detail = (
            f" (package was dormant for {gap} days before this release)"
        )
    detail = (
        f"latest version of {dep.ecosystem}:{dep.name} was published "
        f"{age_days} days ago{dormant_detail}"
    )
    evidence: Dict[str, Any] = {
        "latest_publish": meta.latest_publish.isoformat(),
        "version_age_days": age_days,
        "dormant": True,                    # only dormant fires now
    }
    if meta.second_latest_publish is not None:
        evidence["second_latest_publish"] = (
            meta.second_latest_publish.isoformat()
        )
    return [RegistryMetaFinding(
        kind="version_publish",
        dependency=dep,
        detail=detail,
        evidence=evidence,
        severity=sev,
        confidence=Confidence("high",
                               reason="registry publish timestamp"),
    )]


# ---------------------------------------------------------------------------
# Detector: maintainer_change (recent maintainer addition)
# ---------------------------------------------------------------------------

def _maintainer_change_check(
    dep: Dependency, meta: _Meta, now: datetime,
) -> List[RegistryMetaFinding]:
    """Detect maintainer-list changes between versions.

    Two strategies:
    1. **Per-version comparison** (npm): compare the maintainer list on
       the latest version against the previous version's list.  New names
       appearing are flagged.
    2. **joined_at enrichment** (future feeds): when per-maintainer
       ``joined_at`` is present, flag additions within
       ``_MAINTAINER_CHANGE_DAYS``.
    """
    findings: List[RegistryMetaFinding] = []

    # Strategy 1: per-version comparison.
    if meta.previous_maintainers:
        prev_names = {m.get("name", "").lower()
                      for m in meta.previous_maintainers if m.get("name")}
        new_maintainers = [
            m for m in meta.maintainers
            if m.get("name") and m["name"].lower() not in prev_names
        ]
        if new_maintainers:
            findings.append(RegistryMetaFinding(
                kind="maintainer_change",
                dependency=dep,
                detail=(
                    f"{len(new_maintainers)} new maintainer(s) added to "
                    f"{dep.ecosystem}:{dep.name} between the two most "
                    f"recent versions: "
                    f"{', '.join(m['name'] for m in new_maintainers)}"
                ),
                evidence={"new_maintainers": [
                    {k: v for k, v in m.items() if k != "email"}
                    for m in new_maintainers
                ]},
                severity="low",
                confidence=Confidence(
                    "medium",
                    reason="maintainer list changed between versions",
                ),
            ))

    # Strategy 2: joined_at enrichment (fires only when data present).
    cutoff = now - timedelta(days=_MAINTAINER_CHANGE_DAYS)
    recent: List[Dict[str, Any]] = []
    for m in meta.maintainers:
        joined = m.get("joined_at")
        if isinstance(joined, str):
            ts = _parse_iso(joined)
            if ts and ts >= cutoff:
                recent.append(m)
    if recent:
        findings.append(RegistryMetaFinding(
            kind="maintainer_change",
            dependency=dep,
            detail=(f"{len(recent)} maintainer(s) added to "
                    f"{dep.ecosystem}:{dep.name} in the last "
                    f"{_MAINTAINER_CHANGE_DAYS} days"),
            evidence={"recent_maintainers": [
                {k: v for k, v in m.items() if k != "email"}
                for m in recent
            ]},
            severity="low",
            confidence=Confidence(
                "medium",
                reason="registry maintainer-add timestamp",
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# Detector: maintainer_account_change
# ---------------------------------------------------------------------------

def _maintainer_account_change_check(
    dep: Dependency, meta: _Meta, now: datetime,
) -> List[RegistryMetaFinding]:
    """Heuristic for the Axios pattern: maintainer email changed within
    ``_MAINTAINER_CHANGE_DAYS`` of a new release.

    Triggered when ``last_email_change`` (custom enrichment field; not
    in vanilla npm/PyPI metadata) AND ``latest_publish`` are both within
    the window. Like `maintainer_change`, this fires only when the data
    is present -- currently a structural placeholder ready for richer
    feeds to plug in.
    """
    if meta.latest_publish is None:
        return []
    cutoff = now - timedelta(days=_MAINTAINER_CHANGE_DAYS)
    if meta.latest_publish < cutoff:
        return []
    suspect: List[Dict[str, Any]] = []
    for m in meta.maintainers:
        chg = m.get("last_email_change")
        if isinstance(chg, str):
            ts = _parse_iso(chg)
            if ts and ts >= cutoff:
                suspect.append({"name": m.get("name"),
                                "changed_at": chg})
    if not suspect:
        return []
    return [RegistryMetaFinding(
        kind="maintainer_account_change",
        dependency=dep,
        detail=(f"{len(suspect)} maintainer email change(s) within "
                f"{_MAINTAINER_CHANGE_DAYS} days of release "
                f"({meta.latest_publish.isoformat()})"),
        evidence={
            "latest_publish": meta.latest_publish.isoformat(),
            "suspect_maintainers": suspect,
        },
        severity="high",
        confidence=Confidence(
            "high",
            reason="email-change-within-release-window pattern",
        ),
    )]


# ---------------------------------------------------------------------------
# Detector: low_bus_factor
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Detector: payload_size_spike
# ---------------------------------------------------------------------------
#
# Compare ``dep.version``'s unpacked tarball size against the version
# PUBLISHED IMMEDIATELY BEFORE it. Flag dramatic growth — the Mini
# Shai-Hulud (May 2026) shape: ``size-sensor`` jumped from a small
# utility (50 KB) to 498 KB when the compromised maintainer
# published the malicious version.
#
# Complements ``binary_capability_delta`` (capability-shape change):
# that catches "the code now does new dangerous things"; this
# catches "the code grew dramatically even if the shape is similar"
# (e.g. a massively-inflated obfuscated payload).
#
# Defaults tuned to surface only obvious outliers:
#   * ratio > 5x          — five-fold growth
#   * absolute floor 50KB — don't fire on a 1KB → 10KB jump
#
# Both gates must pass before a finding emits. A 100 byte → 1 KB
# growth is ratio-wise large but absolutely tiny — not actionable.

# Minimum new-version size in bytes for the detector to fire.
# Below this, the ratio signal is dominated by tarball-format
# overhead noise and would false-positive on tiny utility
# packages.
_PAYLOAD_SIZE_FLOOR_BYTES = 50 * 1024

# New-version size / previous-version size threshold. 5x covers
# the Mini Shai-Hulud shape (498 KB / 50 KB ≈ 10x) with headroom
# for less dramatic injections (300% growth still surfaces).
_PAYLOAD_SIZE_RATIO_THRESHOLD = 5.0


def _payload_size_check(
    dep: Dependency, meta: _Meta,
) -> List[RegistryMetaFinding]:
    """Compare ``dep.version`` size to the immediately-prior version.

    Returns ``[]`` when:
      * the dep has no concrete version (no lockfile pin),
      * the registry didn't carry per-version ``unpackedSize``
        for this dep (PyPI, or pre-v6 npm publishes),
      * the dep's version is the FIRST published version (no prior
        to compare against),
      * neither growth-ratio nor absolute-floor gate fires.

    Confidence is ``medium`` rather than ``high`` because legitimate
    growth happens — a library that legitimately added a large
    feature (new runtime, native binary, bundled assets) can hit
    5x. Operator triage is the right disposition.
    """
    if not dep.version:
        return []
    if not meta.version_sizes or not meta.version_chronology:
        return []
    new_size = meta.version_sizes.get(dep.version)
    if new_size is None:
        return []
    # Find the version published immediately before ``dep.version``.
    # ``version_chronology`` is oldest→newest. If dep.version isn't
    # in the chronology (rare — typically means it was unpublished
    # later), bail.
    try:
        idx = meta.version_chronology.index(dep.version)
    except ValueError:
        return []
    if idx == 0:
        return []  # first published version — no prior to compare
    # Walk backward to find the most-recent prior with a known
    # size. Some packages have intermediate versions without
    # unpackedSize (e.g. an old pre-v6 publish that was later
    # supplemented).
    prev_ver = None
    prev_size = None
    for back_idx in range(idx - 1, -1, -1):
        candidate_ver = meta.version_chronology[back_idx]
        candidate_size = meta.version_sizes.get(candidate_ver)
        if candidate_size is not None and candidate_size > 0:
            prev_ver = candidate_ver
            prev_size = candidate_size
            break
    if prev_ver is None or prev_size is None:
        return []
    if new_size < _PAYLOAD_SIZE_FLOOR_BYTES:
        return []
    ratio = new_size / prev_size
    if ratio < _PAYLOAD_SIZE_RATIO_THRESHOLD:
        return []
    return [RegistryMetaFinding(
        kind="payload_size_spike",
        dependency=dep,
        detail=(
            f"{dep.ecosystem}:{dep.name}@{dep.version} unpacked "
            f"size is {new_size:,} bytes — {ratio:.1f}x larger than "
            f"the previous published version {prev_ver} "
            f"({prev_size:,} bytes). Mini Shai-Hulud used this "
            f"shape (legitimate utility → bloated obfuscated "
            f"payload) as the primary injection signature."
        ),
        evidence={
            "current_version": dep.version,
            "current_size_bytes": new_size,
            "previous_version": prev_ver,
            "previous_size_bytes": prev_size,
            "growth_ratio": round(ratio, 2),
            "ratio_threshold": _PAYLOAD_SIZE_RATIO_THRESHOLD,
            "size_floor_bytes": _PAYLOAD_SIZE_FLOOR_BYTES,
        },
        severity="medium",
        confidence=Confidence(
            "medium",
            reason=(
                "registry unpackedSize delta; legitimate large "
                "growth is possible — operator triage needed"
            ),
        ),
    )]


def _low_bus_factor_check(
    dep: Dependency, meta: _Meta,
) -> List[RegistryMetaFinding]:
    """Flag packages with a single maintainer.

    Single-maintainer packages are inherently more vulnerable to account
    takeover -- one compromised credential gives full publish access.
    This is an informational signal, not a vulnerability.
    """
    # Only fire when we have a concrete maintainer list.
    if not meta.maintainers:
        return []
    # Count distinct maintainer names.
    names = {m.get("name", "").lower().strip()
             for m in meta.maintainers if m.get("name")}
    if len(names) != 1:
        return []
    sole = meta.maintainers[0].get("name", "unknown")
    return [RegistryMetaFinding(
        kind="low_bus_factor",
        dependency=dep,
        detail=(
            f"{dep.ecosystem}:{dep.name} has a single maintainer "
            f"({sole}) -- account compromise would grant full "
            f"publish access"
        ),
        evidence={
            "maintainer_count": 1,
            "sole_maintainer": sole,
        },
        severity="info",
        confidence=Confidence("high",
                               reason="registry maintainer list"),
    )]


# ---------------------------------------------------------------------------
# Severity escalation -- co-occurrence adjustments
# ---------------------------------------------------------------------------

def _escalate_severity(
    findings: List[RegistryMetaFinding],
    meta: _Meta,
) -> None:
    """Adjust severities based on which signals co-occur for one dep.

    Rules (from the task specification):
      - recent_publish / version_publish alone -> ``info``
      - recent/version_publish + maintainer_change -> ``medium``
      - recent/version_publish + maintainer_change + dormant -> ``high``

    ``maintainer_account_change`` keeps its own ``high`` (narrow signal).
    ``low_bus_factor`` stays ``info`` unless escalated by co-occurrence.
    """
    kinds = {f.kind for f in findings}
    has_publish = "recent_publish" in kinds or "version_publish" in kinds
    has_maint_change = "maintainer_change" in kinds
    has_size_spike = "payload_size_spike" in kinds
    dormant = meta.is_dormant

    # The Mini Shai-Hulud shape: recent version_publish + maintainer
    # change + payload size spike. Any one of the three is moderate
    # noise; all three together is the canonical maintainer-takeover
    # signature. Escalate to ``critical`` so it's impossible to miss
    # via severity filters.
    if has_publish and has_maint_change and has_size_spike:
        target_sev = "critical"
    elif has_publish and has_maint_change and dormant:
        target_sev = "high"
    elif has_publish and has_maint_change:
        target_sev = "medium"
    elif has_size_spike and has_publish:
        # Size spike + recent publish (no observed maintainer change)
        # — could be a maintainer-credential compromise where the
        # registry doesn't expose the maintainer-list delta. Bump to
        # high so the size spike doesn't read as a routine library
        # growth event.
        target_sev = "high"
    else:
        return  # no escalation needed

    for f in findings:
        if f.kind in ("recent_publish", "version_publish",
                       "maintainer_change", "low_bus_factor",
                       "payload_size_spike"):
            f.severity = target_sev


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_iso(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value:
        return None
    s = value.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


__all__ = ["RegistryMetaFinding", "scan_deps"]

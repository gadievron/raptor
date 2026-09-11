"""Offline OSV advisory database — sqlite3-backed.

The OSV project publishes per-ecosystem zip dumps of every advisory at
``https://osv-vulnerabilities.storage.googleapis.com/<Ecosystem>/all.zip``.
Each zip is a flat list of ``GHSA-...``/``PYSEC-...``/etc. JSON files.

This module:

  1. Lazy-downloads only the ecosystems we have deps for.
  2. Indexes advisories into a sqlite3 DB keyed on
     ``(ecosystem, package)``.
  3. Answers ``query(eco, name, version)`` by reading the indexed
     advisories and filtering by ``versions.in_range`` (the same
     range-matching code path the online client's results would have
     gone through downstream).

Why sqlite3 here vs JSON files: a single npm zip is ~50 MB unpacked
containing tens of thousands of advisories; JSON shards would keep us
honest on memory but we'd hit the filesystem hard for every lookup. The
sqlite3 stdlib gives us O(log N) indexed lookups, atomic writes, and
no third-party dep. Inspectability is preserved — operators can still
``sqlite3 osv-db.sqlite "SELECT * FROM advisories ..."`` to debug.

Wired in by ``OsvClient`` when ``--offline`` is set: if the offline DB
exists and is fresh (≤24h), queries route through it; otherwise the
existing per-query JSON cache + cache-miss-on-offline logic applies.
"""

from __future__ import annotations

import logging
import sqlite3
import time
import urllib.parse
import zipfile
from dataclasses import dataclass
from io import BytesIO

from core.zip import ZipEntryCountExceeded, ZipOpenError, extract_files_from_zip
from .osv import _canonical_name, parse_osv_record
from .versions import VersionError, in_range as _in_range
from typing import TYPE_CHECKING

from core.json import loads

if TYPE_CHECKING:
    from .models import Advisory
    from core.http import HttpClient
    from collections.abc import Iterable
    from pathlib import Path

logger = logging.getLogger(__name__)


_OSV_DUMP_URL = (
    "https://osv-vulnerabilities.storage.googleapis.com/{eco}/all.zip"
)
_DEFAULT_TTL = 24 * 3600
# Per-zip download cap — OSV's largest current zip (npm) is ~60 MB
# unpacked and well under 100 MB compressed. 200 MB gives headroom.
_DOWNLOAD_CAP = 200 * 1024 * 1024

# OSV's bucket spells some ecosystems differently from how our
# Dependency.ecosystem field does. Map our value → bucket folder.
# Release-suffixed distro ecosystems ("Debian:11", "Alpine:v3.18",
# "Ubuntu:22.04") are normalised to their base name before this
# lookup (see ``_storage_ecosystem``) — OSV publishes a combined
# base-name dump for each distro that covers every release stream.
# ``None`` = deliberately no OSV coverage (silent skip); a MISSING
# key = an ecosystem this map hasn't been taught about, which logs a
# visible warning instead of silently returning zero advisories.
_BUCKET_NAME = {
    "PyPI": "PyPI",
    "npm": "npm",
    "Maven": "Maven",
    "Cargo": "crates.io",
    "Go": "Go",
    "RubyGems": "RubyGems",
    "NuGet": "NuGet",
    "Packagist": "Packagist",
    "Debian": "Debian",
    "Alpine": "Alpine",
    "Ubuntu": "Ubuntu",
    "Red Hat": "Red Hat",
    "GitHub Actions": "GitHub Actions",
    "ConanCenter": "ConanCenter",
    # No OSV coverage:
    "Homebrew": None,
    "vcpkg": None,       # OSV has no vcpkg ecosystem (C/C++ deps go
                         # through the online OSS-Fuzz fallback only)
    "GitHub": None,      # .gitmodules / FetchContent rows — no OSV
                         # index; online path uses the OSS-Fuzz fallback
}


def _storage_ecosystem(ecosystem: str) -> str:
    """DB / bucket key for an ecosystem string.

    Distro ecosystems arrive release-suffixed on image-derived rows
    ("Alpine:v3.18"); advisories are ingested from the distro's base
    bucket and stored under the base name. Release narrowing happens
    at match time against each record's per-block ecosystem.
    """
    from .ecosystems import distro_base
    return distro_base(ecosystem) or ecosystem


@dataclass
class _IngestStats:
    ecosystem: str
    advisories: int
    skipped: int
    elapsed_ms: int


class OsvOfflineDB:
    """sqlite3-backed offline OSV index."""

    def __init__(
        self,
        db_path: Path,
        *,
        http: HttpClient | None = None,
        ttl_seconds: int = _DEFAULT_TTL,
    ) -> None:
        self._db_path = db_path
        self._http = http
        self._ttl = ttl_seconds
        self._conn: sqlite3.Connection | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ensure_fresh(
        self, ecosystems: Iterable[str], *, force: bool = False,
    ) -> list[_IngestStats]:
        """Ensure each requested ecosystem has fresh data in the DB.

        ``force=True`` re-downloads even if the cached zip is fresh.
        """
        self._init_db()
        out: list[_IngestStats] = []
        for eco in sorted({_storage_ecosystem(e) for e in ecosystems}):
            if eco not in _BUCKET_NAME:
                logger.warning(
                    "sca.osv_offline: unsupported ecosystem %r — no "
                    "known OSV bucket mapping; offline advisories "
                    "unavailable for its deps", eco)
                continue
            bucket = _BUCKET_NAME[eco]
            if bucket is None:
                logger.debug(
                    "sca.osv_offline: no OSV bucket for ecosystem %r", eco)
                continue
            if not force and self._is_fresh(eco):
                logger.debug("sca.osv_offline: %s up to date", eco)
                continue
            stats = self._ingest_ecosystem(eco, bucket)
            if stats is not None:
                out.append(stats)
        return out

    def query(
        self, ecosystem: str, name: str, version: str | None,
    ) -> list[Advisory]:
        """Return advisories matching (ecosystem, name) at ``version``.

        ``version=None`` returns every advisory for that name (the
        caller can't filter by range without a version, but knowing
        "this dep has any advisories at all" is still useful).
        """
        self._init_db()
        rows = self._lookup_rows(ecosystem, name)
        if not rows:
            return []

        out: list[Advisory] = []
        for raw_json in rows:
            try:
                record = loads(raw_json)
            except ValueError:
                continue
            if version is None or _record_matches_version(
                record, ecosystem, version, name=name,
            ):
                out.append(parse_osv_record(record))
        return out

    def close(self) -> None:
        if self._conn is not None:
            self._conn.close()
            self._conn = None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        if self._conn is not None:
            return
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self._db_path))
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS advisories (
                osv_id    TEXT NOT NULL,
                ecosystem TEXT NOT NULL,
                package   TEXT NOT NULL,
                json      TEXT NOT NULL,
                PRIMARY KEY (osv_id, ecosystem, package)
            );
            CREATE INDEX IF NOT EXISTS idx_eco_pkg
              ON advisories(ecosystem, package);
            CREATE TABLE IF NOT EXISTS ingest_meta (
                ecosystem  TEXT PRIMARY KEY,
                ingested_at INTEGER NOT NULL
            );
        """)
        self._conn.commit()

    def _is_fresh(self, ecosystem: str) -> bool:
        assert self._conn is not None
        cur = self._conn.execute(
            "SELECT ingested_at FROM ingest_meta WHERE ecosystem = ?",
            (ecosystem,),
        )
        row = cur.fetchone()
        if row is None:
            return False
        age = int(time.time()) - int(row[0])
        return age < self._ttl

    def _lookup_rows(self, ecosystem: str, name: str) -> list[str]:
        assert self._conn is not None
        # Rows are stored under the base (release-suffix-free)
        # ecosystem; a "Alpine:v3.18" query reads the "Alpine" rows
        # and release narrowing happens in the version-match step.
        storage_eco = _storage_ecosystem(ecosystem)
        # Per-ecosystem name canonicalisation for matching.
        canon = _canonical_name(storage_eco, name)
        cur = self._conn.execute(
            "SELECT json FROM advisories "
            "WHERE ecosystem = ? AND package = ?",
            (storage_eco, canon),
        )
        return [row[0] for row in cur.fetchall()]

    def _ingest_ecosystem(
        self, ecosystem: str, bucket: str,
    ) -> _IngestStats | None:
        if self._http is None:
            logger.warning(
                "sca.osv_offline: no HttpClient supplied; cannot refresh %s",
                ecosystem,
            )
            return None
        # Bucket folder names can contain spaces ("GitHub Actions",
        # "Red Hat") — percent-encode the path segment.
        url = _OSV_DUMP_URL.format(eco=urllib.parse.quote(bucket, safe=""))
        t0 = time.monotonic()
        try:
            blob = self._http.get_bytes(url, max_bytes=_DOWNLOAD_CAP)
        except Exception as e:                  # noqa: BLE001
            logger.warning(
                "sca.osv_offline: download failed for %s (%s): %s",
                ecosystem, url, e,
            )
            return None

        added = 0
        skipped = 0
        assert self._conn is not None

        # Substrate-based safe walk. ``core.zip.extract_files_from_zip``
        # centralises zip-slip / symlink / oversize / compression-bomb /
        # entry-count defences — stronger than the pre-migration inline
        # ``..`` / abs-path checks.
        #
        # Skipped-counter preservation: the substrate silently drops
        # entries that fail any safety check (logged at debug). To keep
        # the operator-visible ``skipped`` metric meaningful, we
        # separately count ``.json`` entries in the archive and
        # attribute the (expected - returned) delta to safety drops.
        expected_json_entries = 0
        try:
            with zipfile.ZipFile(BytesIO(blob)) as _zf_count:
                for _info in _zf_count.infolist():
                    if _info.filename.endswith(".json"):
                        expected_json_entries += 1
        except zipfile.BadZipFile as e:
            logger.warning(
                "sca.osv_offline: invalid zip for %s: %s", ecosystem, e)
            return None
        # FAIL CLOSED on the substrate's typed refusals (corrupt zip,
        # over-entry-cap / bomb shape): abort ingest BEFORE the
        # DELETE below so a refused download can never wipe an
        # ecosystem's advisories and stamp a fresh ingest_meta —
        # existing cached advisories stay live until a good download
        # ingests.
        try:
            files = extract_files_from_zip(
                blob,
                selector=lambda info: (
                    info.filename if info.filename.endswith(".json") else None
                ),
            )
        except (ZipOpenError, ZipEntryCountExceeded) as e:
            logger.warning(
                "sca.osv_offline: refusing zip for %s (%s); "
                "keeping existing advisories", ecosystem, e)
            return None
        if not files:
            # Covers both a genuinely advisory-free archive
            # (expected == 0) and every-entry-dropped-by-safety
            # (expected > 0): either way there is nothing to ingest,
            # so keep the existing advisories instead of wiping.
            logger.warning(
                "sca.osv_offline: no advisories extracted for %s "
                "(%d .json entries in archive); keeping existing "
                "advisories", ecosystem, expected_json_entries,
            )
            return None
        skipped += expected_json_entries - len(files)
        # Wipe stale advisories for this ecosystem before re-ingesting
        # so removed (deprecated) IDs don't linger. Placed after zip
        # validation so a corrupt download doesn't destroy the cache.
        self._conn.execute(
            "DELETE FROM advisories WHERE ecosystem = ?", (ecosystem,))
        for raw in files.values():
            try:
                record = loads(raw)
            except ValueError:
                skipped += 1
                continue
            advisories_added = self._insert_record(
                ecosystem, record, raw_json=raw.decode(
                    "utf-8", errors="replace"),
            )
            added += advisories_added

        self._conn.execute(
            "INSERT OR REPLACE INTO ingest_meta (ecosystem, ingested_at) "
            "VALUES (?, ?)",
            (ecosystem, int(time.time())),
        )
        self._conn.commit()
        elapsed = int((time.monotonic() - t0) * 1000)
        return _IngestStats(
            ecosystem=ecosystem,
            advisories=added,
            skipped=skipped,
            elapsed_ms=elapsed,
        )

    def _insert_record(
        self, ecosystem: str, record: dict, *, raw_json: str,
    ) -> int:
        """Insert one advisory; returns # of (eco, name) rows written.

        OSV records can list multiple affected packages — we write one
        row per (eco, package) so lookups are O(log N) per name.
        """
        osv_id = record.get("id")
        if not isinstance(osv_id, str):
            return 0
        affected = record.get("affected") or []
        if not isinstance(affected, list):
            return 0
        rows: list[tuple[str, str, str, str]] = []
        for blk in affected:
            if not isinstance(blk, dict):
                continue
            pkg = blk.get("package") or {}
            if not isinstance(pkg, dict):
                continue
            blk_eco = pkg.get("ecosystem")
            blk_name = pkg.get("name")
            if not isinstance(blk_eco, str) or not isinstance(blk_name, str):
                continue
            # OSV uses the bucket-spelling for ecosystem (e.g.,
            # ``crates.io``); normalise back to our canonical Cargo
            # / etc. when we have a reverse mapping. Distro blocks
            # carry release-suffixed ecosystems ("Debian:11",
            # "Alpine:v3.18") — compare on the base identifier, or a
            # distro bucket ingests ZERO advisories. Rows are stored
            # under the base name; per-release narrowing happens at
            # query time in ``_record_matches_version``, which sees
            # the block-level ecosystem in the stored JSON.
            our_eco = _our_ecosystem(blk_eco.split(":", 1)[0])
            if our_eco != ecosystem:
                # Multi-ecosystem advisory — we index it under the
                # bucket we're currently ingesting only.
                continue
            canon = _canonical_name(ecosystem, blk_name)
            rows.append((osv_id, ecosystem, canon, raw_json))
        if not rows:
            return 0
        assert self._conn is not None
        self._conn.executemany(
            "INSERT OR REPLACE INTO advisories "
            "(osv_id, ecosystem, package, json) VALUES (?, ?, ?, ?)",
            rows,
        )
        return len(rows)


# ---------------------------------------------------------------------------
# Canonicalisation + matching
# ---------------------------------------------------------------------------

def _our_ecosystem(osv_value: str) -> str | None:
    """Reverse-map OSV's ecosystem-string (``crates.io``) to ours
    (``Cargo``). Returns the OSV value unchanged when no mapping needed."""
    reverse = {
        "crates.io": "Cargo",
    }
    return reverse.get(osv_value, osv_value)


def _record_matches_version(
    record: dict, ecosystem: str, version: str,
    name: str | None = None,
) -> bool:
    """True if ``version`` falls inside any of the record's affected
    ranges for this ecosystem (and package ``name`` when given).

    Ecosystem comparison is on the base identifier — OSV suffixes
    release streams onto distro ecosystems ("Debian:11"), mirroring
    the online client's handling. When BOTH the query ecosystem and
    the affected block carry a release suffix, the suffixes must
    match (a "Debian:11"-only advisory does not apply to a
    "Debian:12" dep); when either side is release-agnostic, the base
    match suffices — the recall-safe reading.
    """
    query_base, _, query_release = ecosystem.partition(":")
    query_base = _our_ecosystem(query_base)
    affected = record.get("affected") or []
    for blk in affected:
        if not isinstance(blk, dict):
            continue
        pkg = blk.get("package") or {}
        if not isinstance(pkg, dict):
            continue
        blk_eco_raw = pkg.get("ecosystem")
        if not isinstance(blk_eco_raw, str):
            continue
        blk_base, _, blk_release = blk_eco_raw.partition(":")
        if _our_ecosystem(blk_base) != query_base:
            continue
        if query_release and blk_release and blk_release != query_release:
            continue
        if name is not None:
            blk_name = pkg.get("name")
            if isinstance(blk_name, str):
                if _canonical_name(query_base, blk_name) != _canonical_name(query_base, name):
                    continue
        for rng in blk.get("ranges") or []:
            if not isinstance(rng, dict):
                continue
            if rng.get("type") == "GIT":
                # GIT range events are commit SHAs — not version-
                # comparable (feeding them through a version
                # comparator yields arbitrary verdicts; some
                # comparators accept hex strings without raising).
                # Only ECOSYSTEM / SEMVER ranges carry orderable
                # versions; mirrors the online client's skip.
                continue
            events = rng.get("events") or []
            if not isinstance(events, list):
                continue
            try:
                if _in_range(query_base, version, events):
                    return True
            except VersionError:
                continue
        # Non-range "versions" array — direct equality check.
        if version in (blk.get("versions") or []):
            return True
    return False


def discover_ecosystems_from_deps(deps) -> set[str]:
    """Helper: collect the unique ecosystems present in a dep set."""
    return {d.ecosystem for d in deps if d.ecosystem}


__all__ = [
    "OsvOfflineDB",
    "discover_ecosystems_from_deps",
]

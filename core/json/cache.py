"""Disk-backed JSON cache with TTL.

A small key→JSON store with atomic-rename writes and per-entry TTL.
Designed for caching deterministic, infrequently-changing data —
e.g. HTTP feed responses, advisory records, lookup tables — where
re-fetching is expensive and a stale window of seconds-to-days is
acceptable.

Layout:
  Each key maps to a file under the supplied root. Keys may contain
  ``/`` to denote subdirectories, e.g. ``vulns/GHSA-xxx`` →
  ``<root>/vulns/GHSA-xxx.json``.

Concurrency:
  Writes use atomic rename — write to ``<path>.tmp.<pid>.<tid>``,
  then rename. Tempfile names include both pid and thread id so
  concurrent writers (cross-process or cross-thread within a
  process) never share a tempfile path. Concurrent writers are
  last-writer-wins, which is correct because cache values are
  deterministic per key. Readers see either the old version or
  the new version, never a torn write.

Failure modes (silent, by design):
  - Cache root unwritable → in-memory-only mode (every put no-ops,
    every get returns None). The run still succeeds, just slower.
  - Corrupted entries (truncated, invalid JSON, missing fields) →
    treated as miss, caller refetches.

Caller TTL semantics:
  ``get(key, ttl_seconds=N)`` returns the cached value only if the
  entry is younger than ``min(stored_ttl, N)``. So a caller can
  effectively shorten the TTL of pre-existing entries (e.g.
  ``--offline`` mode might decide that a 24h-old entry is now
  stale even though it was written with a 7d TTL).
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Tuple

logger = logging.getLogger(__name__)

# Sentinel TTL meaning "never expire". Use for keys whose freshness
# is encoded in the key itself (e.g., wheel-metadata keyed on
# (name, exact-version) — content can't change for a given key).
TTL_FOREVER = -1


# Sentinel for `try_get` — distinguishes "no entry" from "entry
# exists but value is None". `get()` collapses both to None which
# forced consumers (notably packages.nvd.client) to invent ad-hoc
# wrapper sentinels (`_NVD_CACHE_MISSING`) to cache "not found"
# verdicts without re-issuing the upstream request on every read.
# Use a class-level singleton (not just `object()`) so `is`
# comparisons across module reloads still work for tests.
class _MissingType:
    _instance: Optional["_MissingType"] = None

    def __new__(cls) -> "_MissingType":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "<JsonCache._MISSING>"

    def __bool__(self) -> bool:
        return False


MISSING = _MissingType()


@dataclass(frozen=True)
class CacheEnvelope:
    """Internal representation of a cached entry."""

    written_at: float    # unix seconds
    ttl_seconds: int     # ttl from written_at; TTL_FOREVER = no expiry
    value: Any           # the JSON-serialisable payload

    def is_fresh(self, now: float) -> bool:
        if self.ttl_seconds == TTL_FOREVER:
            return True
        return (now - self.written_at) <= self.ttl_seconds


class JsonCache:
    """Filesystem-backed JSON cache with per-entry TTL.

    Construct one per logical store (one per project run, one per
    feed source, etc.) and pass it to consumers via dependency
    injection. The path layout is keyed so different callers can't
    collide as long as they pick distinct keyspaces.
    """

    def __init__(self, root: Path) -> None:
        self._root: Optional[Path] = root
        self._writable = True
        # Hit / miss counters for surfacing cache-effectiveness metrics.
        # Reset only by reconstructing the cache.
        self.hits = 0
        self.misses = 0
        try:
            self._root.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning(
                "core.json.cache: cache directory %s unwritable (%s); "
                "running without disk cache.",
                self._root, e,
            )
            self._writable = False
            self._root = None
            return
        self._reap_orphan_tempfiles()

    def _reap_orphan_tempfiles(self) -> None:
        """Sweep ``*.tmp.<pid>.<tid>`` files left by a previously-crashed writer.

        ``put()`` writes to ``<path>.tmp.<pid>.<tid>`` then renames atomically —
        if the writer was killed between the open and the rename, the
        tempfile is orphaned. Without this sweep, every crash leaks one
        tempfile per partial write, and the cache dir slowly fills up
        across many runs (each run has a different pid, so old orphans
        are never overwritten).

        Best-effort: any remove failure is ignored. Runs once at
        construction time; not in the hot path.
        """
        if self._root is None:
            return
        try:
            entries = list(self._root.rglob("*.tmp.*"))
        except OSError:
            return
        for entry in entries:
            # Defensive: only target files whose suffix matches the
            # tempfile shape we write — either legacy ``.tmp.<pid>``
            # (single all-digit segment) or current
            # ``.tmp.<pid>.<tid>`` (two all-digit segments). Anything
            # else is left alone so we don't collide with caller-chosen
            # keys that happen to contain ".tmp.".
            parts = entry.name.rsplit(".tmp.", 1)
            if len(parts) != 2:
                continue
            tail = parts[1].split(".")
            if 1 <= len(tail) <= 2 and all(s.isdigit() for s in tail):
                try:
                    entry.unlink()
                except OSError:
                    pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, key: str, *, ttl_seconds: int) -> Optional[Any]:
        """Return cached value if fresh; else ``None``.

        Note: returns ``None`` for both "no entry" and "entry holds
        None". Callers that need to distinguish those cases should
        use :meth:`try_get` instead.
        """
        value = self.try_get(key, ttl_seconds=ttl_seconds)
        if value is MISSING:
            return None
        return value

    def try_get(self, key: str, *, ttl_seconds: int) -> Any:
        """Return cached value if fresh; else the ``MISSING`` sentinel.

        Distinguishes "no entry" / "expired" / "corrupt" from
        "entry holds None". The latter is a legitimate cached
        value — operators caching `null` JSON responses
        (NVD's "no record for this CVE" verdict, GitHub's
        empty-array responses, distro tracker no-data signals)
        previously had to wrap with their own sentinel because
        `get` returned `None` indistinguishably for both cases.
        """
        if not self._writable or self._root is None:
            self.misses += 1
            return MISSING
        path = self._path_for(key)
        if not path.exists():
            self.misses += 1
            return MISSING
        try:
            envelope = self._read_envelope(path)
        except (OSError, ValueError, KeyError) as e:
            logger.debug("core.json.cache: corrupt entry %s: %s", path, e)
            self.misses += 1
            return MISSING
        # Caller may downgrade TTL relative to what was stored. Honour
        # the *minimum* TTL.
        effective_ttl = ttl_seconds if ttl_seconds < envelope.ttl_seconds \
            or envelope.ttl_seconds == TTL_FOREVER else envelope.ttl_seconds
        envelope = CacheEnvelope(
            written_at=envelope.written_at,
            ttl_seconds=effective_ttl,
            value=envelope.value,
        )
        if not envelope.is_fresh(time.time()):
            self.misses += 1
            return MISSING
        self.hits += 1
        return envelope.value

    def put(self, key: str, value: Any, *, ttl_seconds: int) -> None:
        """Atomically write ``value`` under ``key``."""
        if not self._writable or self._root is None:
            return
        path = self._path_for(key)
        path.parent.mkdir(parents=True, exist_ok=True)
        envelope = CacheEnvelope(
            written_at=time.time(),
            ttl_seconds=ttl_seconds,
            value=value,
        )
        # Tempfile suffix MUST include the thread id, not just pid:
        # two threads in the same process writing the same key would
        # otherwise share a tmp path, and ``open("w")`` truncates on
        # open — clobbering each other's partial writes. With pid+tid
        # each writer has its own tmpfile, and atomic rename serialises
        # which one wins (last-writer-wins is the documented contract).
        tmp = path.with_suffix(f".tmp.{os.getpid()}.{threading.get_ident()}")
        try:
            with tmp.open("w", encoding="utf-8") as fh:
                json.dump({
                    "written_at": envelope.written_at,
                    "ttl_seconds": envelope.ttl_seconds,
                    "value": envelope.value,
                }, fh)
            tmp.replace(path)
        except (OSError, TypeError, ValueError) as e:
            # OSError: disk full, permission denied, etc.
            # TypeError/ValueError: caller passed a non-JSON-serialisable
            # value (e.g. datetime). Clean up the partial temp file
            # either way so we don't leak stragglers in the cache dir.
            logger.warning("core.json.cache: failed to write %s: %s", path, e)
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def invalidate(self, key: str) -> None:
        """Remove an entry. Safe to call on missing keys."""
        if not self._writable or self._root is None:
            return
        path = self._path_for(key)
        try:
            path.unlink(missing_ok=True)
        except OSError as e:
            logger.debug("core.json.cache: failed to remove %s: %s", path, e)

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _path_for(self, key: str) -> Path:
        """Resolve a cache key to a filesystem path.

        Keys are caller-chosen and may contain ``/`` to denote a
        subdirectory (e.g., ``vulns/GHSA-xxx``). They MUST NOT contain
        ``..`` or absolute paths; we sanitise defensively to keep
        adversarial input from escaping the cache root.
        """
        if self._root is None:
            raise RuntimeError("cache root not initialised")
        clean_parts = []
        for part in key.split("/"):
            if not part or part in (".", ".."):
                continue
            # Strip path separators that may have leaked in.
            clean_parts.append(part.replace(os.sep, "_"))
        if not clean_parts:
            raise ValueError(f"empty cache key after sanitisation: {key!r}")
        # Append the suffix directly rather than ``Path.with_suffix``:
        # the last component is typically a version string like
        # ``4.17.4``, and ``with_suffix(".json")`` would replace the
        # existing ``.4`` token, collapsing every multi-segment version
        # for the same package onto the same cache file.
        final_name = clean_parts[-1] + ".json"
        return self._root.joinpath(*clean_parts[:-1], final_name)

    @staticmethod
    def _read_envelope(path: Path) -> CacheEnvelope:
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        if not isinstance(data, dict):
            raise ValueError("cache entry is not an object")
        return CacheEnvelope(
            written_at=float(data["written_at"]),
            ttl_seconds=int(data["ttl_seconds"]),
            value=data["value"],
        )


__all__ = ["JsonCache", "TTL_FOREVER", "CacheEnvelope"]

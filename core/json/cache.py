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

from .utils import _reject_non_finite

logger = logging.getLogger(__name__)

# Sentinel TTL meaning "never expire". Use for keys whose freshness
# is encoded in the key itself (e.g., wheel-metadata keyed on
# (name, exact-version) — content can't change for a given key).
TTL_FOREVER = -1


# Reaper freshness threshold. Tempfiles whose mtime is within this
# many seconds are assumed to be in-flight writes from another
# concurrent writer, not crash-orphans. 60s is comfortably longer
# than any realistic write window (single-key json.dump → fsync →
# rename completes in milliseconds even on slow storage) and tight
# enough that real crash-orphans get cleaned on the next session.
_REAP_FRESHNESS_S = 60.0


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
        #
        # Pre-fix `self.hits += 1` / `self.misses += 1` were
        # un-locked. Python's `+=` on an int is NOT atomic — it
        # decomposes into LOAD/INCR/STORE, so concurrent
        # increments under threads can lose updates. The cache
        # is hit from the CodeQL agent's per-finding parallel
        # dispatch and from the cve-diff worker pool, both of
        # which call `get()` from multiple threads. Lost
        # increments quietly skewed the cache-effectiveness
        # metric (hit rate read low) — operators tuning cache
        # TTL / size based on this metric were getting biased
        # signal.
        #
        # Add a lock and increment under it. Cost: one mutex
        # acquire per get(), which is microseconds (the actual
        # cache lookup work is several orders of magnitude
        # slower; locking overhead is in the noise).
        import threading
        self._counter_lock = threading.Lock()
        self.hits = 0
        self.misses = 0
        # Per-instance in-process memo. Disk-cache hot paths (OSV
        # per-query, KEV containment, registry metadata, supply-chain
        # tracker lookups) call ``try_get`` with the same key many
        # times within a single scan — pre-memo the SCA pipeline
        # spent ~5s of a 20s saleor warm scan re-opening + re-parsing
        # the same JSON files for the same keys. The memo is bounded
        # by the working set (typically a few thousand entries per
        # scan); we don't LRU-evict because scans are short-lived
        # and the memo is reclaimed when the cache instance is GC'd.
        # ``put`` and ``invalidate`` write through to keep the memo
        # consistent with disk for callers who put + immediately get.
        # ``MISSING`` is also memoised so a cold-cache miss isn't
        # re-checked on disk repeatedly.
        self._memo_lock = threading.Lock()
        self._memo: dict = {}
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

        Skips tempfiles modified within ``_REAP_FRESHNESS_S`` seconds.
        Pre-fix the reaper unlinked every tempfile shape it found,
        including those another concurrent JsonCache instance (in
        another process or another thread) was actively writing to —
        race: writer A opens `tmp.<pidA>.<tidA>`, writer B's
        constructor scans, finds A's tempfile, treats it as a
        crash-orphan, unlinks it mid-write. A's subsequent
        `tmp.replace(path)` then fails with FileNotFoundError, the
        cache write is lost, and the operator sees a confused
        warning instead of the cached entry.

        Best-effort: any remove failure is ignored. Runs once at
        construction time; not in the hot path.
        """
        if self._root is None:
            return
        try:
            entries = list(self._root.rglob("*.tmp.*"))
        except OSError:
            return
        now = time.time()
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
            if not (1 <= len(tail) <= 2 and all(s.isdigit() for s in tail)):
                continue
            # Skip if mtime is recent — concurrent writer is in
            # the middle of producing this file.
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            if now - mtime < _REAP_FRESHNESS_S:
                continue
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
            with self._counter_lock:
                self.misses += 1
            return MISSING
        # In-process memo — disk-hot keys (OSV per-query, registry
        # metadata, supply-chain tracker lookups) get hit many times
        # in one scan; pre-memo each repeat paid disk + JSON parse.
        # We memoise the parsed envelope keyed on the disk file's
        # mtime so external rewrites (test fixtures, concurrent
        # processes) still get re-read instead of returning a stale
        # in-memory copy. Stat is much cheaper than read + JSON parse,
        # so the memo still wins net even with the per-hit stat.
        path = self._path_for(key)
        try:
            file_mtime = path.stat().st_mtime
        except OSError:
            file_mtime = None
        if file_mtime is None:
            with self._memo_lock:
                self._memo[key] = MISSING
            with self._counter_lock:
                self.misses += 1
            return MISSING
        with self._memo_lock:
            cached_pair = self._memo.get(key)
        envelope: Optional[CacheEnvelope] = None
        if (isinstance(cached_pair, tuple) and len(cached_pair) == 2
                and cached_pair[1] == file_mtime):
            envelope = cached_pair[0]
        elif cached_pair is MISSING:
            # Negative-cached miss is rechecked because the file may
            # have appeared between the previous miss and this call —
            # disk stat already proved presence above, so fall through
            # to the read path.
            pass
        if envelope is None:
            try:
                envelope = self._read_envelope(path)
            except (OSError, ValueError, KeyError) as e:
                logger.debug("core.json.cache: corrupt entry %s: %s", path, e)
                with self._memo_lock:
                    self._memo[key] = MISSING
                with self._counter_lock:
                    self.misses += 1
                return MISSING
            with self._memo_lock:
                self._memo[key] = (envelope, file_mtime)
        # Caller may downgrade TTL relative to what was stored. Honour
        # the *minimum* TTL.
        #
        # `TTL_FOREVER = -1` is a sentinel for "infinite", NOT a tiny
        # negative TTL. Pre-fix the comparison `ttl_seconds <
        # envelope.ttl_seconds` treated -1 as smaller than any finite
        # TTL — so a caller passing `TTL_FOREVER` against a stored
        # 60s entry got `effective_ttl = -1` (FOREVER), silently
        # extending the entry's lifetime past its actual expiry.
        # Operators saw stale data persist indefinitely after they
        # started passing FOREVER for a hot key.
        #
        # Correct minimum-with-sentinel logic:
        #   * Both FOREVER → FOREVER.
        #   * One FOREVER, other finite → finite (it IS the minimum).
        #   * Both finite → arithmetic min.
        if ttl_seconds == TTL_FOREVER and envelope.ttl_seconds == TTL_FOREVER:
            effective_ttl = TTL_FOREVER
        elif ttl_seconds == TTL_FOREVER:
            effective_ttl = envelope.ttl_seconds
        elif envelope.ttl_seconds == TTL_FOREVER:
            effective_ttl = ttl_seconds
        else:
            effective_ttl = min(ttl_seconds, envelope.ttl_seconds)
        envelope = CacheEnvelope(
            written_at=envelope.written_at,
            ttl_seconds=effective_ttl,
            value=envelope.value,
        )
        if not envelope.is_fresh(time.time()):
            with self._counter_lock:
                self.misses += 1
            return MISSING
        with self._counter_lock:
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
        # Drop any memo entry under this key so a concurrent reader
        # doesn't return a stale envelope before the disk write
        # completes. The next ``try_get`` after the rename will
        # repopulate the memo via the stat + read path.
        with self._memo_lock:
            self._memo.pop(key, None)
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
        with self._memo_lock:
            self._memo.pop(key, None)
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
            # Strip BOTH separators regardless of host. Pre-fix
            # `part.replace(os.sep, "_")` only stripped the host's
            # separator — on Linux (os.sep="/") an embedded
            # backslash from a Windows-formatted cache key
            # (`"vulns\\GHSA-xxx"`) leaked through; the resulting
            # filename either confused downstream tooling or, on a
            # filesystem that honours backslash as a literal byte,
            # produced a file with a backslash in its name that
            # later glob patterns missed. Replace both `\` and `/`
            # explicitly so the same key produces the same cache
            # file regardless of which platform formatted it.
            clean = part.replace("\\", "_").replace("/", "_")
            # Strip os.sep too in case the platform uses a third
            # separator (Path.alt_sep on some systems).
            if os.sep not in ("\\", "/"):
                clean = clean.replace(os.sep, "_")
            clean_parts.append(clean)
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
        # `parse_constant` rejects ``NaN`` / ``Infinity`` / ``-Infinity``
        # at parse time. Pre-fix `json.load` accepted them by default
        # (a stdlib JSON5-ish extension), so a corrupt or hostile cache
        # entry with `"ttl_seconds": Infinity` would parse cleanly,
        # then blow up downstream with `OverflowError` from
        # `int(float('inf'))` — an exception type try_get's
        # `except (OSError, ValueError, KeyError)` does not cover, so
        # the error leaked all the way out and crashed the consumer.
        # Reject at parse time so the existing JSONDecodeError /
        # ValueError handler treats it as a corrupt entry and the
        # cache falls back to MISSING.
        with path.open("r", encoding="utf-8") as fh:
            data = json.load(fh, parse_constant=_reject_non_finite)
        if not isinstance(data, dict):
            raise ValueError("cache entry is not an object")
        # `ttl_seconds` may still be a non-numeric string from a
        # truly malformed entry — keep the int-coerce guard for that.
        ttl_raw = data["ttl_seconds"]
        try:
            ttl = int(ttl_raw)
        except (OverflowError, ValueError, TypeError) as e:
            raise ValueError(f"non-numeric ttl_seconds: {ttl_raw!r}") from e
        return CacheEnvelope(
            written_at=float(data["written_at"]),
            ttl_seconds=ttl,
            value=data["value"],
        )


__all__ = ["JsonCache", "TTL_FOREVER", "CacheEnvelope"]

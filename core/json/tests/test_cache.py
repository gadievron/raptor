"""Tests for ``core.json.cache.JsonCache``.

Adapted from the original ``packages/sca/tests/test_cache.py`` written
for the SCA-specific cache module — same coverage, retargeted to the
generic ``core.json.cache`` location.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

import pytest

# core/json/tests/test_cache.py -> repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from core.json import TTL_FOREVER, JsonCache


def test_put_and_get_roundtrip(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", {"v": 1}, ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == {"v": 1}


def test_get_returns_none_for_missing_key(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    assert cache.get("nope", ttl_seconds=60) is None


def test_expired_entry_returns_none(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=1)
    # Force expiry by rewriting the envelope with an old timestamp.
    p = tmp_path / "k.json"
    raw = json.loads(p.read_text())
    raw["written_at"] = time.time() - 10_000
    p.write_text(json.dumps(raw))
    assert cache.get("k", ttl_seconds=1) is None


def test_caller_can_downgrade_ttl(tmp_path: Path) -> None:
    """A fresh entry with TTL=86400 is stale under TTL=1."""
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=86400)
    p = tmp_path / "k.json"
    raw = json.loads(p.read_text())
    raw["written_at"] = time.time() - 60   # 1 min old
    p.write_text(json.dumps(raw))
    assert cache.get("k", ttl_seconds=10) is None
    assert cache.get("k", ttl_seconds=300) == "v"


def test_ttl_forever_is_never_stale(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=TTL_FOREVER)
    p = tmp_path / "k.json"
    raw = json.loads(p.read_text())
    raw["written_at"] = 0   # epoch
    p.write_text(json.dumps(raw))
    assert cache.get("k", ttl_seconds=TTL_FOREVER) == "v"


def test_corrupt_json_treated_as_miss(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    (tmp_path / "k.json").write_text("not json")
    assert cache.get("k", ttl_seconds=60) is None


def test_truncated_envelope_treated_as_miss(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    (tmp_path / "k.json").write_text('{"value": "x"}')   # missing ttl
    assert cache.get("k", ttl_seconds=60) is None


def test_subdirectory_keys(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("vulns/GHSA-xxx", {"id": "GHSA-xxx"}, ttl_seconds=60)
    assert (tmp_path / "vulns" / "GHSA-xxx.json").exists()
    assert cache.get("vulns/GHSA-xxx", ttl_seconds=60) == {"id": "GHSA-xxx"}


def test_path_traversal_in_key_is_blocked(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("../escape", "should-not-escape", ttl_seconds=60)
    # Either the file lives inside the cache root, or the put silently
    # discarded the segment; either way, no escape.
    assert not (tmp_path.parent / "escape.json").exists()
    assert (tmp_path / "escape.json").exists()


def test_empty_key_after_sanitisation_raises(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    with pytest.raises(ValueError):
        cache.put("../..", "x", ttl_seconds=60)


def test_invalidate_removes_entry(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=60)
    cache.invalidate("k")
    assert cache.get("k", ttl_seconds=60) is None


def test_unwritable_root_falls_back_to_no_op(tmp_path: Path) -> None:
    """If the root can't be created, cache becomes a no-op (warns once)."""
    bad = tmp_path / "not-a-dir"
    bad.write_text("file blocking dir creation")
    cache = JsonCache(root=bad)
    cache.put("k", "v", ttl_seconds=60)        # silently no-ops
    assert cache.get("k", ttl_seconds=60) is None


def test_atomic_write_does_not_leave_temp_files(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=60)
    leftovers = [p for p in tmp_path.iterdir() if ".tmp." in p.name]
    assert leftovers == []


def test_keys_with_dotted_segments_do_not_collide(tmp_path: Path) -> None:
    """Regression: ``4.17.4`` and ``4.17.21`` used to collide on
    ``4.17.json`` because ``Path.with_suffix(".json")`` treated the
    trailing ``.4`` / ``.21`` as the existing suffix and replaced it."""
    cache = JsonCache(root=tmp_path)
    cache.put("queries/npm/lodash/4.17.4", ["v1"], ttl_seconds=60)
    cache.put("queries/npm/lodash/4.17.21", ["v2"], ttl_seconds=60)
    assert cache.get("queries/npm/lodash/4.17.4", ttl_seconds=60) == ["v1"]
    assert cache.get("queries/npm/lodash/4.17.21", ttl_seconds=60) == ["v2"]
    # Both files exist under the same parent.
    parent = tmp_path / "queries" / "npm" / "lodash"
    names = sorted(p.name for p in parent.iterdir())
    assert names == ["4.17.21.json", "4.17.4.json"]


def test_key_without_dots_still_lands_with_json_suffix(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("vulns/GHSA-test", {"id": "x"}, ttl_seconds=60)
    assert (tmp_path / "vulns" / "GHSA-test.json").exists()


def test_orphan_tempfiles_are_reaped_at_construction(tmp_path: Path) -> None:
    """A stale tempfile left by a crashed writer must be cleaned up
    the next time a JsonCache is constructed against the same root,
    so the dir doesn't accumulate orphans across runs. Both the
    legacy single-pid format and the current pid.tid format are
    recognised.

    Test files are aged past `_REAP_FRESHNESS_S` so the
    concurrent-writer-protection (batch 193) doesn't skip them.
    """
    import os
    # Legacy ``.tmp.<pid>`` shape (orphans from earlier code on disk).
    legacy = tmp_path / "k.tmp.99999"
    legacy.write_text('{"partial": true}')
    (tmp_path / "vulns").mkdir()
    inner = tmp_path / "vulns" / "GHSA-xxx.tmp.12345"
    inner.write_text('{"x": 1}')
    # Current ``.tmp.<pid>.<tid>`` shape (what put() writes now).
    current = tmp_path / "current.tmp.12345.67890"
    current.write_text('{"partial": true}')
    # Also a file with a similar but non-matching suffix — must NOT be reaped.
    decoy = tmp_path / "config.tmp.json"
    decoy.write_text("user data")

    # Age the orphans past the freshness threshold so the
    # concurrent-writer-protection added in batch 193 doesn't
    # skip them.
    old = time.time() - 3600
    for f in (legacy, inner, current):
        os.utime(f, (old, old))

    JsonCache(root=tmp_path)   # construction triggers the sweep

    assert not legacy.exists()
    assert not inner.exists()
    assert not current.exists()
    assert decoy.exists(), "must not reap files whose suffix isn't .tmp.<digits>[.<digits>]"


def test_orphan_tempfile_recent_is_skipped(tmp_path: Path) -> None:
    """A tempfile modified seconds ago is presumed to belong to a
    concurrent in-flight writer in another process / thread — DON'T
    reap it. Pre-fix the constructor unlinked any tempfile shape it
    found, racing the writer's tmp.replace() into FileNotFoundError."""
    fresh = tmp_path / "live.tmp.99999.11111"
    fresh.write_text('{"in_progress": true}')
    # Default mtime is now — within the freshness window.
    JsonCache(root=tmp_path)
    assert fresh.exists(), "fresh tempfile (concurrent writer) must survive"


def test_concurrent_threads_same_key_no_torn_writes(tmp_path: Path) -> None:
    """REGRESSION: two threads in the same process writing the same key
    must not share a tempfile path. Earlier code used ``.tmp.<pid>``
    only — both threads would ``open("w")`` the same path, the second
    open truncating the first's partial write. Result: a torn file
    that fails JSON parsing on next read.

    With pid+tid in the suffix, each writer has its own tmpfile; the
    final atomic rename is last-writer-wins, but both writers complete
    a whole file independently.
    """
    import threading as _threading

    cache = JsonCache(root=tmp_path)
    barrier = _threading.Barrier(8)

    def writer(i: int) -> None:
        barrier.wait()
        for _ in range(50):
            cache.put("hot-key", {"writer": i, "n": _}, ttl_seconds=60)

    threads = [_threading.Thread(target=writer, args=(i,))
               for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Whatever the final winner is, the read MUST succeed (no torn
    # file) and produce a value from one of the writers.
    got = cache.get("hot-key", ttl_seconds=60)
    assert got is not None, "concurrent writers produced an unparseable file"
    assert "writer" in got and 0 <= got["writer"] < 8


def test_non_json_serialisable_value_does_not_leak_tempfile(tmp_path: Path) -> None:
    """If a caller passes a non-JSON-serialisable value, the put silently
    no-ops AND cleans up its partial tempfile — no .tmp.<pid> leftovers."""
    import datetime
    cache = JsonCache(root=tmp_path)
    # datetime is not JSON-serialisable by default; json.dump will raise
    # TypeError. Older versions of this code only caught OSError, leaking
    # the partial tempfile.
    cache.put("k", datetime.datetime.now(), ttl_seconds=60)
    # Tempfile leak = .tmp.<pid>[.<tid>] shaped leftovers. The reaper's
    # rate-limit sentinel (``.reap_last_run``) is cache infrastructure,
    # not a leak — exclude it from the assertion.
    tempfile_leftovers = sorted(
        p.name for p in tmp_path.rglob("*")
        if p.is_file() and ".tmp." in p.name
    )
    assert tempfile_leftovers == [], (
        f"tempfile leak: {tempfile_leftovers}"
    )
    # And the cache returns None on subsequent get (write was rejected).
    assert cache.get("k", ttl_seconds=60) is None


# ---------------------------------------------------------------------------
# In-process memo
# ---------------------------------------------------------------------------


def test_memo_serves_repeat_get_without_disk_read(
    tmp_path: Path, monkeypatch,
) -> None:
    """Second get on the same key should be served from the memo
    without re-parsing the JSON file."""
    cache = JsonCache(root=tmp_path)
    cache.put("k", {"big": "value"}, ttl_seconds=60)

    # Spy on the parse path: count calls to _read_envelope.
    original = JsonCache._read_envelope
    calls = {"n": 0}
    def counting(path):
        calls["n"] += 1
        return original(path)
    # ``monkeypatch`` cleanly restores the staticmethod wrapper on
    # teardown — direct `JsonCache._read_envelope = original` would
    # leave the class attribute as a plain function, breaking later
    # tests that call the method via the class binding.
    monkeypatch.setattr(JsonCache, "_read_envelope", staticmethod(counting))
    for _ in range(10):
        assert cache.get("k", ttl_seconds=60) == {"big": "value"}
    # 10 get()s, only 1 read.
    assert calls["n"] == 1, f"expected 1 disk read, got {calls['n']}"


def test_memo_invalidated_on_external_disk_rewrite(tmp_path: Path) -> None:
    """If the disk file is rewritten externally (different mtime),
    the next get must re-read rather than serve a stale memo entry.
    Pins the test that exposed the original memo correctness bug."""
    cache = JsonCache(root=tmp_path)
    cache.put("k", "old", ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == "old"
    # Wait long enough that the next mtime is detectably different.
    p = tmp_path / "k.json"
    import os as _os
    raw = json.loads(p.read_text())
    raw["value"] = "new"
    # Rewrite + bump mtime (st_mtime usually has 1ns resolution
    # on Linux; force-bump explicitly to be safe across filesystems).
    p.write_text(json.dumps(raw))
    new_mtime = p.stat().st_mtime + 5.0
    _os.utime(p, (new_mtime, new_mtime))
    assert cache.get("k", ttl_seconds=60) == "new"


def test_memo_invalidated_on_put(tmp_path: Path) -> None:
    """put under the same key must replace the memo entry."""
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v1", ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == "v1"
    cache.put("k", "v2", ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == "v2"


def test_memo_invalidated_on_invalidate(tmp_path: Path) -> None:
    cache = JsonCache(root=tmp_path)
    cache.put("k", "v", ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == "v"
    cache.invalidate("k")
    assert cache.get("k", ttl_seconds=60) is None


def test_memo_negative_cached_miss_is_recomputed_after_put(
    tmp_path: Path,
) -> None:
    """Repeated misses on a never-written key shouldn't trigger
    repeat disk stat — but a subsequent put on that key must be
    seen by the next get."""
    cache = JsonCache(root=tmp_path)
    assert cache.get("k", ttl_seconds=60) is None
    assert cache.get("k", ttl_seconds=60) is None
    cache.put("k", "v", ttl_seconds=60)
    assert cache.get("k", ttl_seconds=60) == "v"


# ---------------------------------------------------------------------------
# Reaper rate-limit
# ---------------------------------------------------------------------------

def test_reaper_writes_sentinel_after_first_run(tmp_path: Path) -> None:
    """First-ever JsonCache construction reaps + drops a sentinel."""
    JsonCache(root=tmp_path)
    sentinel = tmp_path / ".reap_last_run"
    assert sentinel.is_file()


def test_reaper_skipped_when_sentinel_is_fresh(
    tmp_path: Path, monkeypatch,
) -> None:
    """Second construction within the rate-limit window must NOT
    re-walk the cache. We assert by stubbing the candidate iterator
    to detect the call."""
    JsonCache(root=tmp_path)
    # Sentinel now exists with current mtime.
    from core.json import cache as cache_mod
    calls: list = []
    original = cache_mod._iter_tempfile_candidates

    def spy(root, **kwargs):
        calls.append(str(root))
        return original(root, **kwargs)

    monkeypatch.setattr(cache_mod, "_iter_tempfile_candidates", spy)
    JsonCache(root=tmp_path)
    cache_walks = [c for c in calls if str(tmp_path) in c]
    assert cache_walks == [], (
        f"reaper was not rate-limit-skipped on warm sentinel: {cache_walks}"
    )


def test_reaper_runs_when_sentinel_is_stale(
    tmp_path: Path, monkeypatch,
) -> None:
    """When the sentinel's mtime is older than the rate-limit window,
    the reaper must run again."""
    JsonCache(root=tmp_path)
    sentinel = tmp_path / ".reap_last_run"
    # Make the sentinel old enough to fall outside the rate-limit
    # window (default 3600s; backdate by 2 hours for safety).
    old = time.time() - 7200
    import os as _os
    _os.utime(sentinel, (old, old))

    from core.json import cache as cache_mod
    calls: list = []
    original = cache_mod._iter_tempfile_candidates

    def spy(root, **kwargs):
        calls.append(str(root))
        return original(root, **kwargs)

    monkeypatch.setattr(cache_mod, "_iter_tempfile_candidates", spy)
    JsonCache(root=tmp_path)
    cache_walks = [c for c in calls if str(tmp_path) in c]
    assert len(cache_walks) == 1, (
        f"reaper did not run on stale sentinel: {cache_walks}"
    )


def test_reaper_finds_shallow_tempfiles_but_skips_deep(tmp_path: Path) -> None:
    """Depth-bounded scan picks up depth-1/2 orphans (the SCA cache
    shape) but stops before walking the whole tree on big caches.

    Also exercises the legacy ``.tmp.<pid>`` shape so a writer crash
    from an older RAPTOR version still gets cleaned."""
    # Depth-1 orphan with current shape.
    (tmp_path / "shallow.json.tmp.12345.99999").write_text("{}")
    # Depth-2 orphan under a normal SCA subdir.
    sub = tmp_path / "npm-meta:@scope"
    sub.mkdir()
    (sub / "name.json.tmp.12345.99999").write_text("{}")
    # Backdate both so they're outside the freshness window.
    import os as _os
    old = time.time() - 600  # 10 min ago
    _os.utime(tmp_path / "shallow.json.tmp.12345.99999", (old, old))
    _os.utime(sub / "name.json.tmp.12345.99999", (old, old))
    JsonCache(root=tmp_path)
    assert not (tmp_path / "shallow.json.tmp.12345.99999").exists()
    assert not (sub / "name.json.tmp.12345.99999").exists()


# ---------------------------------------------------------------------------
# Memo byte-budget LRU
# ---------------------------------------------------------------------------

def test_memo_evicts_oldest_when_budget_exceeded(tmp_path: Path) -> None:
    """Once the byte budget is exceeded, the LRU front entry is dropped
    and ``memo_evictions`` increments. Disk values stay; only the
    in-process memo is cleared, so a re-read still works."""
    c = JsonCache(root=tmp_path)
    # Tight budget makes every entry trigger eviction.
    c._memo_budget = 256
    payload = "x" * 200
    for i in range(5):
        c.put(f"key_{i}", payload, ttl_seconds=3600)
        c.get(f"key_{i}", ttl_seconds=3600)  # populate memo
    # ~200B payload + envelope JSON overhead ~80B = ~280B per entry,
    # so each get() pushes us past budget and the oldest entry is
    # evicted. Final state: only the most-recently-inserted entry
    # survives (a single oversize entry is always kept regardless of
    # budget — eviction stops before dropping the just-inserted row).
    assert len(c._memo) == 1
    assert c.memo_evictions >= 4
    # A re-read after eviction still works — the disk file is intact.
    assert c.get("key_0", ttl_seconds=3600) == payload


def test_memo_touch_keeps_hot_entry_alive(tmp_path: Path) -> None:
    """LRU-touched (recently-read) entries survive eviction over
    cold entries even when the cold entries were inserted later."""
    c = JsonCache(root=tmp_path)
    # Budget chosen so two entries (~268B each) fit but a third
    # triggers eviction of one.
    c._memo_budget = 700
    payload = "x" * 200
    c.put("hot", payload, ttl_seconds=3600)
    c.get("hot", ttl_seconds=3600)            # memo[hot]
    c.put("cold_1", payload, ttl_seconds=3600)
    c.get("cold_1", ttl_seconds=3600)         # memo[hot, cold_1]
    # Re-read "hot" — now hot is MRU, cold_1 is LRU.
    c.get("hot", ttl_seconds=3600)            # memo[cold_1, hot]
    # Third entry forces one eviction; cold_1 (LRU) goes, hot stays.
    c.put("cold_2", payload, ttl_seconds=3600)
    c.get("cold_2", ttl_seconds=3600)         # memo[hot, cold_2]
    assert "hot" in c._memo
    assert "cold_1" not in c._memo
    assert c.memo_evictions >= 1

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
    """
    # Legacy ``.tmp.<pid>`` shape (orphans from earlier code on disk).
    (tmp_path / "k.tmp.99999").write_text('{"partial": true}')
    (tmp_path / "vulns").mkdir()
    (tmp_path / "vulns" / "GHSA-xxx.tmp.12345").write_text('{"x": 1}')
    # Current ``.tmp.<pid>.<tid>`` shape (what put() writes now).
    (tmp_path / "current.tmp.12345.67890").write_text('{"partial": true}')
    # Also a file with a similar but non-matching suffix — must NOT be reaped.
    decoy = tmp_path / "config.tmp.json"
    decoy.write_text("user data")

    JsonCache(root=tmp_path)   # construction triggers the sweep

    assert not (tmp_path / "k.tmp.99999").exists()
    assert not (tmp_path / "vulns" / "GHSA-xxx.tmp.12345").exists()
    assert not (tmp_path / "current.tmp.12345.67890").exists()
    assert decoy.exists(), "must not reap files whose suffix isn't .tmp.<digits>[.<digits>]"


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
    leftovers = sorted(p.name for p in tmp_path.rglob("*") if p.is_file())
    assert leftovers == [], f"tempfile leak: {leftovers}"
    # And the cache returns None on subsequent get (write was rejected).
    assert cache.get("k", ttl_seconds=60) is None

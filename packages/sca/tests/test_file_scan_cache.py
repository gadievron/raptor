"""Tests for ``packages.sca._file_scan_cache``.

The cache helper sits between the two AST walkers (reachability +
python_imports) and ``core.json.JsonCache``. Tests cover:

* cache-hit short-circuits the compute callable (the load-bearing
  perf claim — repeat scans skip AST parsing entirely)
* cache miss invokes compute, caches, returns
* cache=None falls through to compute (legacy behaviour preserved)
* duck-type guard — sentinel objects (used in some unit tests)
  don't crash the helper
* hash invalidation — different content → different cache key
"""

from __future__ import annotations

from pathlib import Path

from core.json import JsonCache

from packages.sca._file_scan_cache import (
    cached_per_file,
    file_sha256,
)


def _make_cache(tmp_path: Path) -> JsonCache:
    return JsonCache(root=tmp_path / "cache")


# ---------------------------------------------------------------------------
# file_sha256
# ---------------------------------------------------------------------------


def test_file_sha256_is_deterministic():
    h1 = file_sha256("hello world")
    h2 = file_sha256("hello world")
    assert h1 == h2
    assert len(h1) == 64                        # sha256 hex


def test_file_sha256_distinguishes_content():
    """One byte change → different hash → different cache key →
    cache miss → recompute. Without this property the cache would
    serve stale results across edits."""
    assert file_sha256("hello world") != file_sha256("hello worl")


# ---------------------------------------------------------------------------
# cached_per_file — cache miss / hit / no-cache
# ---------------------------------------------------------------------------


def test_cache_miss_invokes_compute_and_caches(tmp_path: Path):
    cache = _make_cache(tmp_path)
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        return ["module-a", "module-b"]

    out = cached_per_file(cache, "tester", "abc", compute)
    assert out == ["module-a", "module-b"]
    assert calls["count"] == 1
    assert cache.misses == 1


def test_cache_hit_skips_compute(tmp_path: Path):
    """The performance contract: once a (consumer, content_hash) pair
    is in the cache, repeat lookups don't re-invoke compute. This is
    the entire point of the helper — without it, the per-scan AST
    parsing of unchanged files isn't avoided."""
    cache = _make_cache(tmp_path)
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        return ["x"]

    cached_per_file(cache, "tester", "abc", compute)        # populate
    cached_per_file(cache, "tester", "abc", compute)        # hit
    cached_per_file(cache, "tester", "abc", compute)        # hit
    assert calls["count"] == 1, (
        "cache hit must NOT re-invoke compute"
    )


def test_no_cache_falls_through_to_compute(tmp_path: Path):
    """``cache=None`` → legacy uncached behaviour. Used by callers
    that opt out of caching (e.g. mid-test fixtures) without changing
    the consumer signature."""
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        return "value"

    for _ in range(3):
        cached_per_file(None, "tester", "abc", compute)
    assert calls["count"] == 3


def test_duck_type_guard_for_sentinel_cache(tmp_path: Path):
    """Some unit tests pass ``object()`` as a placeholder cache to
    satisfy a parameter contract without supplying a real
    JsonCache. The helper must fall through to compute rather
    than ``AttributeError`` on the missing ``.get`` method."""
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        return 42

    sentinel = object()
    out = cached_per_file(sentinel, "tester", "abc", compute)
    assert out == 42
    assert calls["count"] == 1


# ---------------------------------------------------------------------------
# Different content → different cache key
# ---------------------------------------------------------------------------


def test_different_content_creates_new_entry(tmp_path: Path):
    """Edit a file → its hash changes → fresh cache key → recompute.
    Without this, the cache would serve stale results across file
    edits (the central correctness invariant of content-hashed
    caching)."""
    cache = _make_cache(tmp_path)
    calls = []

    def compute_a():
        calls.append("a")
        return ["from-a"]

    def compute_b():
        calls.append("b")
        return ["from-b"]

    out_a = cached_per_file(cache, "tester", "version 1", compute_a)
    out_b = cached_per_file(cache, "tester", "version 2", compute_b)

    assert out_a == ["from-a"]
    assert out_b == ["from-b"]
    assert calls == ["a", "b"]


# ---------------------------------------------------------------------------
# Different consumer → different cache namespace
# ---------------------------------------------------------------------------


def test_different_consumer_namespaces_isolated(tmp_path: Path):
    """The reachability scanner and the python_imports scanner can
    cache the same file's content under their respective consumer
    keys without collisions. Without this, one consumer's result
    would shadow the other's."""
    cache = _make_cache(tmp_path)
    out_a = cached_per_file(cache, "consumer-a", "abc", lambda: ["a-result"])
    out_b = cached_per_file(cache, "consumer-b", "abc", lambda: ["b-result"])
    assert out_a == ["a-result"]
    assert out_b == ["b-result"]


# ---------------------------------------------------------------------------
# Persistence across cache reconstruction
# ---------------------------------------------------------------------------


def test_cache_survives_reconstruction(tmp_path: Path):
    """Repeat scans of the same project (separate raptor-sca runs)
    construct fresh JsonCache instances pointing at the same path.
    The helper must serve hits across that boundary — that's where
    the actual perf win lives, not within a single process."""
    root = tmp_path / "cache"
    cache_a = JsonCache(root=root)
    cached_per_file(cache_a, "tester", "abc", lambda: ["fresh"])

    cache_b = JsonCache(root=root)
    calls = {"count": 0}

    def compute():
        calls["count"] += 1
        return ["should-not-fire"]

    out = cached_per_file(cache_b, "tester", "abc", compute)
    assert out == ["fresh"], "second-run cache must serve first-run's value"
    assert calls["count"] == 0


# ---------------------------------------------------------------------------
# JSON-serialisability constraint
# ---------------------------------------------------------------------------


def test_value_is_round_tripped_through_json(tmp_path: Path):
    """Ensure cache-stored values come back through json.loads
    (lists become lists, dicts become dicts, but tuples become
    lists). Documents the consumer-side contract — pure-JSON
    structures only; no dataclasses; flatten before storing."""
    cache = _make_cache(tmp_path)
    cached_per_file(
        cache, "tester", "abc",
        lambda: [{"k": 1, "lst": [1, 2, 3]}],
    )
    # Reconstruct via fresh cache → must round-trip.
    out = cached_per_file(
        JsonCache(root=tmp_path / "cache"),
        "tester", "abc", lambda: ["should-not-fire"],
    )
    assert out == [{"k": 1, "lst": [1, 2, 3]}]

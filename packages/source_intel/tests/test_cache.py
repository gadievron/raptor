"""Tests for ``packages.source_intel.cache``."""

from __future__ import annotations


from packages.source_intel.analyze import SourceIntelResult
from packages.source_intel.cache import SourceIntelCache


def test_cache_get_returns_none_on_miss(tmp_path):
    c = SourceIntelCache()
    assert c.get(tmp_path) is None
    assert c.size() == 0


def test_cache_put_then_get_returns_stored(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    c = SourceIntelCache()
    r = SourceIntelResult(target=str(tmp_path))
    c.put(tmp_path, None, r)
    out = c.get(tmp_path)
    assert out is r
    assert c.size() == 1


def test_cache_distinguishes_different_targets(tmp_path):
    """Two different targets must produce distinct keys."""
    a = tmp_path / "a"
    b = tmp_path / "b"
    a.mkdir(); b.mkdir()
    (a / "x.c").write_text("int x(void){return 0;}\n")
    (b / "x.c").write_text("int y(void){return 1;}\n")

    c = SourceIntelCache()
    r_a = SourceIntelResult(target=str(a))
    r_b = SourceIntelResult(target=str(b))
    c.put(a, None, r_a)
    c.put(b, None, r_b)

    assert c.get(a) is r_a
    assert c.get(b) is r_b
    assert c.size() == 2


def test_cache_invalidates_when_target_content_changes(tmp_path):
    """Content-addressed: changing the target tree should miss the
    cached result (because target_hash changes)."""
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    c = SourceIntelCache()
    r = SourceIntelResult(target=str(tmp_path))
    c.put(tmp_path, None, r)
    # Modify the file — hash should change → cache miss.
    (tmp_path / "x.c").write_text("int main(void){return 1;}\n")
    assert c.get(tmp_path) is None


def test_cache_invalidates_when_rules_dir_changes(tmp_path):
    """Two different rules dirs produce different keys for the same
    target — rule-set version is part of the cache key."""
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    rules_a = tmp_path / "rules_a"; rules_a.mkdir()
    (rules_a / "r.cocci").write_text("@@\n@@\n")
    rules_b = tmp_path / "rules_b"; rules_b.mkdir()
    (rules_b / "r.cocci").write_text("@@\n@@\n@@\n")  # different content

    c = SourceIntelCache()
    r = SourceIntelResult(target=str(tmp_path))
    c.put(tmp_path, rules_a, r)
    assert c.get(tmp_path, rules_a) is r
    # Different rules → miss.
    assert c.get(tmp_path, rules_b) is None


def test_cache_invalidate_clears_entries(tmp_path):
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    c = SourceIntelCache()
    c.put(tmp_path, None, SourceIntelResult())
    assert c.size() == 1
    c.invalidate()
    assert c.size() == 0
    assert c.get(tmp_path) is None


def test_cache_handles_missing_target_gracefully(tmp_path):
    """Cache key derivation for a non-existent target must not crash."""
    c = SourceIntelCache()
    nonexistent = tmp_path / "does-not-exist"
    out = c.get(nonexistent)
    assert out is None  # Should not raise.


def test_cache_handles_single_file_target(tmp_path):
    """Single-file target is a valid input and must produce a stable
    key. Single-file caching is useful when source_intel runs on
    just the bug-relevant file rather than a whole tree."""
    f = tmp_path / "single.c"
    f.write_text("int main(void){return 0;}\n")
    c = SourceIntelCache()
    r = SourceIntelResult(target=str(f))
    c.put(f, None, r)
    assert c.get(f) is r

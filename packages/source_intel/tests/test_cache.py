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
    a.mkdir()
    b.mkdir()
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
    rules_a = tmp_path / "rules_a"
    rules_a.mkdir()
    (rules_a / "r.cocci").write_text("@@\n@@\n")
    rules_b = tmp_path / "rules_b"
    rules_b.mkdir()
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


# =====================================================================
# Key-derivation memo (content-hash amortisation)
# =====================================================================


def test_key_derivation_content_hash_amortised_on_unchanged_tree(tmp_path):
    """Consumers derive a key per finding against the same tree; the
    content-hash walk must run once per tree STATE, not per lookup —
    the stat-only signature validates the memo on each call."""
    from unittest.mock import patch

    import packages.source_intel.cache as cache_mod

    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    cache_mod.clear_key_memo()
    c = SourceIntelCache()

    calls = {"n": 0}
    real = cache_mod._hash_target_tree

    def _counting(target):
        calls["n"] += 1
        return real(target)

    with patch.object(cache_mod, "_hash_target_tree", _counting):
        c.get(tmp_path)
        c.get(tmp_path)
        c.get(tmp_path)
        assert calls["n"] == 1

        # An edit flips the stat signature → the content hash is
        # recomputed exactly once more.
        (tmp_path / "x.c").write_text("int main(void){return 1;}\n")
        c.get(tmp_path)
        c.get(tmp_path)
        assert calls["n"] == 2


# =====================================================================
# Key-carrying get/put (tree drift during analyze)
# =====================================================================


def test_key_carried_across_drift_does_not_launder_stale_result(tmp_path):
    """A result computed over the pre-drift tree must be stored under
    the PRE-drift key: a post-drift lookup (which sees the new tree)
    must miss, and only the explicit old key still returns it."""
    (tmp_path / "x.c").write_text("int main(void){return 0;}\n")
    c = SourceIntelCache()
    r = SourceIntelResult(target=str(tmp_path))

    key = c.key_for(tmp_path)
    assert c.get_by_key(key) is None

    # Tree drifts while "analyze" runs…
    (tmp_path / "x.c").write_text("int main(void){return 1;}\n")

    # …and the store uses the carried key, not a re-derived one.
    c.put_by_key(key, r)
    assert c.get(tmp_path) is None          # post-drift tree: miss
    assert c.get_by_key(key) is r           # pre-drift key: hit


# =====================================================================
# Default (shipped) rules dir participates in the key
# =====================================================================


def test_default_rules_key_observes_shipped_rule_edits(tmp_path):
    """``rules_dir=None`` hashes the shipped rules directory, so a
    rule-corpus edit invalidates default-keyed entries exactly like
    an explicit-dir edit would."""
    import os
    from unittest.mock import patch

    import packages.source_intel.cache as cache_mod

    rules = tmp_path / "rules"
    (rules / "axis").mkdir(parents=True)
    rule = rules / "axis" / "r.cocci"
    rule.write_text("@r@\n@@\n- foo()\n")

    with patch.object(
        cache_mod, "_shipped_rules_root", lambda: rules,
    ):
        h1 = cache_mod._hash_rules_dir(None)
        assert h1 not in ("default-rules", "missing-rules")
        # Same content as an explicit path → same hash.
        assert h1 == cache_mod._hash_rules_dir(rules)

        rule.write_text("@r@\n@@\n- bar()\n")
        os.utime(rule, ns=(1, 1))
        h2 = cache_mod._hash_rules_dir(None)
        assert h2 != h1

    # Minimal install (no shipped root) keeps the sentinel.
    with patch.object(
        cache_mod, "_shipped_rules_root", lambda: None,
    ):
        assert cache_mod._hash_rules_dir(None) == "default-rules"

"""Existing build marker spellings must participate in cache freshness."""

import pytest

from packages.source_intel import cache


@pytest.mark.parametrize("name", ["makefile", "Makefile", "GNUmakefile", "Kbuild"])
def test_build_marker_edit_changes_signature_and_cached_hash(tmp_path, monkeypatch, name):
    monkeypatch.setattr(cache, "_TREE_HASH_MEMO", {})
    marker = tmp_path / name
    marker.write_text("owned-A\n")
    signature_before = cache.compute_target_signature(tmp_path)
    hash_before = cache._hash_target_tree_cached(tmp_path)
    marker.write_text("owned-B-with-different-size\n")
    signature_after = cache.compute_target_signature(tmp_path)
    hash_after = cache._hash_target_tree_cached(tmp_path)
    assert signature_after != signature_before
    assert hash_after != hash_before


def test_unrelated_marker_suffix_does_not_change_fingerprint(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_TREE_HASH_MEMO", {})
    marker = tmp_path / "makefile.bak"
    marker.write_text("owned-A\n")
    signature_before = cache.compute_target_signature(tmp_path)
    hash_before = cache._hash_target_tree_cached(tmp_path)
    marker.write_text("owned-B-with-different-size\n")
    assert cache.compute_target_signature(tmp_path) == signature_before
    assert cache._hash_target_tree_cached(tmp_path) == hash_before

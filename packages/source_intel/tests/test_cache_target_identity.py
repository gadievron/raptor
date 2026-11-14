"""Path-specific cached evidence cannot cross content-identical targets."""

from pathlib import Path

import pytest

from packages.source_intel import cache
from packages.source_intel.analyze import AttributeEvidence, SourceIntelResult


@pytest.fixture
def owned_cache(tmp_path, monkeypatch):
    monkeypatch.setattr(cache, "_TREE_HASH_MEMO", {})
    monkeypatch.setattr(cache, "_RULES_HASH_MEMO", {})
    rules = tmp_path / "rules"
    rules.mkdir()
    return cache.SourceIntelCache(), rules


def test_identical_directory_contents_cannot_replay_other_target_paths(tmp_path, owned_cache):
    store, rules = owned_cache
    first, second = tmp_path / "first", tmp_path / "second"
    for target in (first, second):
        target.mkdir()
        (target / "owned.c").write_text("owned identical bytes\n")
    record = SourceIntelResult(target=str(first), attributes=(AttributeEvidence(
        kind="wur", function_name="owned", location=(str(first / "owned.c"), 1),
        match_source="known_alias", raw_match="__must_check",
    ),))
    key = store.key_for(first, rules)
    store.put_by_key(key, record)
    assert store.get_by_key(store.key_for(first, rules)) is record
    assert store.get_by_key(store.key_for(second, rules)) is None


def test_missing_targets_have_distinct_stable_keys(tmp_path, owned_cache):
    store, rules = owned_cache
    first, second = tmp_path / "missing-a", tmp_path / "missing-b"
    assert store.key_for(first, rules) == store.key_for(first, rules)
    assert store.key_for(first, rules) != store.key_for(second, rules)


def test_relative_and_absolute_input_spellings_keep_distinct_result_paths(
    tmp_path, monkeypatch, owned_cache,
):
    store, rules = owned_cache
    target = tmp_path / "owned"
    target.mkdir()
    (target / "owned.c").write_text("owned identical bytes\n")
    monkeypatch.chdir(tmp_path)
    assert store.key_for(Path("owned"), rules) != store.key_for(target, rules)


def test_relative_target_identity_tracks_working_directory(tmp_path, monkeypatch, owned_cache):
    store, rules = owned_cache
    keys = []
    for base in (tmp_path / "one", tmp_path / "two"):
        (base / "owned").mkdir(parents=True)
        (base / "owned" / "owned.c").write_text("owned identical bytes\n")
        monkeypatch.chdir(base)
        keys.append(store.key_for(Path("owned"), rules))
    assert keys[0] != keys[1]

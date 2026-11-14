"""Cached query resolution reuses its existing per-pack lock."""

import threading
from types import SimpleNamespace

import pytest

import core.audit.codeql_query_resolver as resolver
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def owned_resolver_cache():
    with isolated_module_state(
        resolver, {"_PACK_INDEX_CACHE": {}, "_PACK_LOCKS": {}},
        lock=resolver._CACHE_LOCK,
    ):
        yield


@pytest.fixture
def lock_calls(monkeypatch):
    calls = []

    def owned_lock():
        value = threading.Lock()
        calls.append(value)
        return value

    monkeypatch.setattr(resolver, "threading", SimpleNamespace(Lock=owned_lock))
    return calls


def test_cached_missing_pack_reuses_lock_and_clear_rebuilds_index(monkeypatch, lock_calls):
    indexed = []

    def owned_index(pack):
        indexed.append(pack)
        return None

    monkeypatch.setattr(resolver, "_index_pack", owned_index)
    for _ in range(3):
        assert resolver.resolve_query_id("cpp/owned") is None
    assert len(lock_calls) == 1
    assert indexed == ["codeql/cpp-queries"]
    resolver.clear_cache()
    assert resolver.resolve_query_id("cpp/owned") is None
    assert len(lock_calls) == 1
    assert indexed == ["codeql/cpp-queries", "codeql/cpp-queries"]


def test_alias_and_distinct_pack_keep_lock_keys(monkeypatch, lock_calls):
    monkeypatch.setattr(resolver, "_index_pack", lambda _: None)
    for query in ("cpp/owned", "c/owned", "py/owned", "cpp/owned"):
        assert resolver.resolve_query_id(query) is None
    assert len(lock_calls) == 2
    assert set(resolver._PACK_LOCKS) == {"codeql/cpp-queries", "codeql/python-queries"}


def test_cached_valid_query_file_reuses_lock(tmp_path, monkeypatch, lock_calls):
    query = tmp_path / "Owned.ql"
    query.write_text("owned metadata-only fixture\n")
    monkeypatch.setattr(resolver, "_index_pack", lambda _: {"cpp/owned": str(query)})
    for _ in range(3):
        assert resolver.resolve_query_id("cpp/owned") == str(query)
    assert len(lock_calls) == 1

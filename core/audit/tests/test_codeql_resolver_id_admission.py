"""Malformed query IDs do not reach pack discovery."""

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


def test_trailing_newline_id_avoids_pack_discovery(monkeypatch):
    def forbidden_index(*args):
        raise AssertionError("malformed query ID must not discover a pack")

    monkeypatch.setattr(resolver, "_index_pack", forbidden_index)
    assert resolver.resolve_query_id("cpp/owned\n") is None


@pytest.mark.parametrize("query", ["cpp/owned\r\n", "cpp/owned\n\n"])
def test_other_line_endings_remain_refused(query, monkeypatch):
    def forbidden_index(*args):
        raise AssertionError("malformed query ID must not discover a pack")

    monkeypatch.setattr(resolver, "_index_pack", forbidden_index)
    assert resolver.resolve_query_id(query) is None


def test_valid_id_retains_owned_file_resolution(tmp_path, monkeypatch):
    query = tmp_path / "Owned.ql"
    query.write_text("owned metadata-only fixture\n")
    calls = []

    def owned_index(pack):
        calls.append(pack)
        return {"cpp/owned": str(query)}

    monkeypatch.setattr(resolver, "_index_pack", owned_index)
    assert resolver.resolve_query_id("cpp/owned") == str(query)
    assert resolver.resolve_query_id("cpp/owned") == str(query)
    assert calls == ["codeql/cpp-queries"]


def test_absent_owned_query_file_retains_refusal(tmp_path, monkeypatch):
    monkeypatch.setattr(resolver, "_index_pack",
                        lambda _: {"cpp/owned": str(tmp_path / "absent.ql")})
    assert resolver.resolve_query_id("cpp/owned") is None

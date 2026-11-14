"""Owned lookup routes preserve best-effort resolution on filesystem refusal."""

from types import SimpleNamespace

import pytest

import core.audit.codeql_query_resolver as resolver
from core.testing.module_state import isolated_module_state


@pytest.fixture(autouse=True)
def owned_resolver_state(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("owned resolver route tests must never invoke the CLI")

    monkeypatch.setattr(resolver, "subprocess", SimpleNamespace(run=forbidden))
    with isolated_module_state(
        resolver, {"_PACK_INDEX_CACHE": {}, "_PACK_LOCKS": {}},
        lock=resolver._CACHE_LOCK,
    ):
        yield


@pytest.mark.parametrize("refused", [1, 2], ids=["package-cache", "bundled"])
def test_one_refused_lookup_retains_other_roots(tmp_path, monkeypatch, refused):
    roots = [tmp_path / f"route{index}" for index in range(3)]
    for root in roots:
        root.mkdir()
    calls = []
    names = ("_cli_qlpack_roots", "_package_cache_roots", "_distribution_roots")
    for index, name in enumerate(names):
        def lookup(pack, route=index):
            assert pack == "codeql/cpp-queries"
            calls.append(route)
            if route == refused:
                raise PermissionError("owned lookup refusal")
            return [roots[route]]
        monkeypatch.setattr(resolver, name, lookup)
    assert resolver._pack_roots("codeql/cpp-queries") == [
        root for index, root in enumerate(roots) if index != refused
    ]
    assert calls == [0, 1, 2]


def test_all_unavailable_routes_produce_public_miss(monkeypatch):
    calls = []

    def absent(pack):
        calls.append("cli")
        return []

    def refused(pack):
        calls.append("refused")
        raise OSError("owned lookup refusal")

    monkeypatch.setattr(resolver, "_cli_qlpack_roots", absent)
    monkeypatch.setattr(resolver, "_package_cache_roots", refused)
    monkeypatch.setattr(resolver, "_distribution_roots", refused)
    assert resolver.resolve_query_id("cpp/owned") is None
    assert calls == ["cli", "refused", "refused"]


def test_successful_routes_keep_order_filtering_and_deduplication(tmp_path, monkeypatch):
    first, second, file = tmp_path / "first", tmp_path / "second", tmp_path / "file"
    first.mkdir()
    second.mkdir()
    file.touch()
    monkeypatch.setattr(resolver, "_cli_qlpack_roots", lambda _: [first, file])
    monkeypatch.setattr(resolver, "_package_cache_roots", lambda _: [first])
    monkeypatch.setattr(resolver, "_distribution_roots", lambda _: [second])
    assert resolver._pack_roots("codeql/cpp-queries") == [first, second]

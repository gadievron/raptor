"""The chain fixture must not borrow host packs or leak its resolver state."""

from contextlib import nullcontext

import pytest

from core.audit import codeql_query_resolver as resolver
from core.audit import orchestrator
from core.audit.tests.codeql_catalogue import owned_codeql_catalogue


@pytest.mark.parametrize("failure", [None, RuntimeError, KeyboardInterrupt],
                         ids=["success", "error", "interrupt"])
def test_catalogue_restores_discovery_caches_and_logs(tmp_path, monkeypatch, failure):
    def forbidden(*args, **kwargs):
        pytest.fail("chain fixture reached host CodeQL discovery")

    for name in ("_cli_qlpack_roots", "_package_cache_roots", "_distribution_roots"):
        monkeypatch.setattr(resolver, name, forbidden)
    borrowed_roots = resolver._pack_roots
    borrowed_index = resolver._PACK_INDEX_CACHE
    borrowed_locks = resolver._PACK_LOCKS
    borrowed_logged = orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED
    before_index = dict(borrowed_index)
    before_locks = dict(borrowed_locks)
    before_logged = set(borrowed_logged)

    with pytest.raises(failure) if failure else nullcontext():
        with owned_codeql_catalogue(tmp_path) as queries:
            assert resolver._PACK_INDEX_CACHE is not borrowed_index
            assert resolver._PACK_LOCKS is not borrowed_locks
            assert orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED is not borrowed_logged
            query = "cpp/overflow-buffer"
            assert resolver.resolve_query_id(query) == str(queries[query])
            assert orchestrator._resolved_codeql_query(query) == str(queries[query])
            assert orchestrator._resolved_codeql_query("cpp/not-a-table-query") is None
            assert "cpp/not-a-table-query" in orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED
            with pytest.raises(TypeError):
                queries[query] = tmp_path / "consumer-edit.ql"
            if failure:
                raise failure("body interrupted")

    assert resolver._pack_roots is borrowed_roots
    assert resolver._PACK_INDEX_CACHE is borrowed_index
    assert resolver._PACK_LOCKS is borrowed_locks
    assert orchestrator._CODEQL_UNSUPPORTED_IDS_LOGGED is borrowed_logged
    assert borrowed_index == before_index
    assert borrowed_locks == before_locks
    assert borrowed_logged == before_logged

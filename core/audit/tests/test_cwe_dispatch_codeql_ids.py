"""Pin the dispatch table's CodeQL query IDs to reality.

Every ``codeql`` entry in CWE_TO_TOOL_DISPATCH must either resolve
against an installed pack's ``@id`` index or be dropped by the
loud-once unsupported-query path (the chain slot stays honestly empty
— never a phantom dispatch, never a silent per-dispatch skip storm).

Hermetic tests stub the resolver's per-process pack index; the
opportunistic test checks the REAL installed packs and skips per
language when that pack is absent (CI installs none).
"""

from __future__ import annotations

import logging

import pytest

from core.audit import codeql_query_resolver as resolver
from core.audit.cwe_dispatch import codeql_query_ids_by_pack

_TABLE_IDS = codeql_query_ids_by_pack()


@pytest.fixture(autouse=True)
def _fresh_resolver_cache():
    from core.testing.module_state import isolated_module_state

    with isolated_module_state(
        resolver, {"_PACK_INDEX_CACHE": {}, "_PACK_LOCKS": {}},
        lock=resolver._CACHE_LOCK,
    ):
        yield


class TestTableIdShape:
    """Structural pins — an ID failing these can NEVER resolve."""

    def test_table_is_not_empty(self):
        assert _TABLE_IDS

    @pytest.mark.parametrize(
        "query_id",
        [q for ids in _TABLE_IDS.values() for q in ids],
    )
    def test_id_shape_and_pack_prefix(self, query_id):
        assert resolver._QUERY_ID_RE.match(query_id), (
            f"{query_id!r} fails the resolver's ID-shape gate"
        )
        prefix = query_id.split("/", 1)[0]
        assert prefix in resolver._LANG_PREFIX_TO_PACK, (
            f"{query_id!r} names a language prefix with no known pack"
        )


class TestStubbedResolver:
    """Hermetic route pins with a stubbed pack index."""

    def test_every_table_id_resolves_against_stub_index(
        self, tmp_path, monkeypatch,
    ):
        fake_ql = tmp_path / "Query.ql"
        fake_ql.write_text("select 1\n", encoding="utf-8")
        stub_cache: dict[str, dict[str, str] | None] = {}
        for prefix, ids in _TABLE_IDS.items():
            pack = resolver._LANG_PREFIX_TO_PACK[prefix]
            stub_cache.setdefault(pack, {}).update(
                {q: str(fake_ql) for q in ids},
            )
        monkeypatch.setattr(resolver, "_PACK_INDEX_CACHE", stub_cache)

        for ids in _TABLE_IDS.values():
            for query_id in ids:
                assert resolver.resolve_query_id(query_id) == str(fake_ql)

    def test_unresolvable_id_takes_loud_once_drop_path(
        self, monkeypatch, caplog,
    ):
        from core.audit import orchestrator

        # Pack "installed" but the @id is absent from its index — the
        # ID class the table audit exists to catch.
        monkeypatch.setattr(
            resolver, "_PACK_INDEX_CACHE",
            {resolver._LANG_PREFIX_TO_PACK["cpp"]: {}},
        )
        monkeypatch.setattr(
            orchestrator, "_CODEQL_UNSUPPORTED_IDS_LOGGED", set(),
        )
        dead_id = "cpp/no-such-query-id"
        assert resolver.resolve_query_id(dead_id) is None

        with caplog.at_level(logging.INFO, logger=orchestrator.__name__):
            assert orchestrator._resolved_codeql_query(dead_id) is None
            assert orchestrator._resolved_codeql_query(dead_id) is None
        loud = [
            r for r in caplog.records
            if r.levelno == logging.INFO
            and "codeql chain step unsupported" in r.getMessage()
        ]
        assert len(loud) == 1  # once per id, not per dispatch


class TestInstalledPacks:
    """Opportunistic: audit the table against REAL installed packs.

    Skips per language when the pack is not installed (CI has none) —
    on a host with packs, every table ID for that language must carry
    an exact ``@id`` match, or the entry is a dead dispatch that skips
    on every run.
    """

    @pytest.mark.parametrize("prefix", sorted(_TABLE_IDS))
    def test_table_ids_resolve_in_installed_pack(self, prefix):
        pack = resolver._LANG_PREFIX_TO_PACK[prefix]
        index = resolver._index_pack(pack)
        if not index:
            pytest.skip(f"pack {pack} not installed")
        missing = [q for q in _TABLE_IDS[prefix] if q not in index]
        assert not missing, (
            f"dispatch-table IDs with no @id match in installed "
            f"{pack}: {missing}"
        )

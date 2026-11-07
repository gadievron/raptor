"""Owned query packs for tests of other channels in a mixed tool chain."""

from contextlib import contextmanager
from types import MappingProxyType

import pytest

from core.testing.module_state import isolated_module_state


@contextmanager
def owned_codeql_catalogue(root):
    from core.audit import codeql_query_resolver as resolver
    from core.audit import orchestrator
    from core.audit.cwe_dispatch import CWE_TO_TOOL_DISPATCH

    packs = {}
    queries = {}
    ids = {entry["codeql"] for entry in CWE_TO_TOOL_DISPATCH.values()
           if entry.get("codeql")}
    for index, query in enumerate(sorted(ids)):
        pack = resolver._LANG_PREFIX_TO_PACK.get(query.partition("/")[0])
        if pack is None:
            continue
        directory = root / pack
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / f"query-{index}.ql"
        path.write_text(f"/**\n * @id {query}\n */\nselect 1\n")
        packs[pack] = directory
        queries[query] = path

    # Keep the real resolver, header index and chain builder. Only discovery
    # of the operator's CLI/cache/distribution is incidental to these tests.
    with isolated_module_state(resolver, {
        "_pack_roots": lambda pack: [packs[pack]] if pack in packs else [],
        "_PACK_INDEX_CACHE": {},
        "_PACK_LOCKS": {},
    }, lock=resolver._CACHE_LOCK), isolated_module_state(orchestrator, {
        "_CODEQL_UNSUPPORTED_IDS_LOGGED": set(),
    }, lock=orchestrator._CODEQL_UNSUPPORTED_IDS_LOCK):
        yield MappingProxyType(queries)


@pytest.fixture
def codeql_chain_catalogue(tmp_path):
    """Opt-in catalogue; native pack-discovery tests keep their own scope."""
    with owned_codeql_catalogue(tmp_path / "codeql-packs") as queries:
        yield queries

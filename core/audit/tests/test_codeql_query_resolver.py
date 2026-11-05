"""CWE-table CodeQL query IDs must resolve to on-disk query files.

Dual-control: a table pack ID resolves to an existing ``.ql`` file
through the installed-pack ``@id`` index (hermetic fake pack), and a
bogus ID drops loudly-once with the chain's codeql slot left empty —
never a phantom dispatch that errors on every use."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

import core.audit.codeql_query_resolver as resolver
import core.audit.orchestrator as orch
from core.audit.codeql_query_resolver import resolve_query_id
from core.audit.orchestrator import _cwe_fallback_chain


def _fake_pack(tmp_path: Path) -> Path:
    root = tmp_path / "cpp-queries" / "1.0.0"
    qdir = root / "Security" / "CWE" / "CWE-119"
    qdir.mkdir(parents=True)
    (qdir / "OverflowBuffer.ql").write_text(
        "/**\n"
        " * @name Buffer overflow\n"
        " * @id cpp/overflow-buffer\n"
        " * @kind problem\n"
        " */\n"
        "import cpp\nselect 1\n"
    )
    (qdir / "Other.ql").write_text(
        "/**\n * @id cpp/other-query\n */\nimport cpp\nselect 1\n"
    )
    return root


@pytest.fixture(autouse=True)
def _fresh_caches(monkeypatch):
    from contextlib import ExitStack

    from core.testing.module_state import isolated_module_state

    with ExitStack() as scope:
        scope.enter_context(isolated_module_state(
            resolver, {"_PACK_INDEX_CACHE": {}, "_PACK_LOCKS": {}},
            lock=resolver._CACHE_LOCK,
        ))
        scope.enter_context(isolated_module_state(
            orch, {"_CODEQL_UNSUPPORTED_IDS_LOGGED": set()},
        ))
        yield


class TestResolution:
    def test_pack_id_resolves_to_existing_file(self, tmp_path, monkeypatch):
        root = _fake_pack(tmp_path)
        monkeypatch.setattr(resolver, "_pack_roots", lambda pack: [root])
        path = resolve_query_id("cpp/overflow-buffer")
        assert path is not None
        assert Path(path).is_file()
        assert Path(path).name == "OverflowBuffer.ql"
        # Second id from the same single pack walk.
        assert Path(resolve_query_id("cpp/other-query")).name == "Other.ql"

    def test_unknown_id_in_installed_pack_returns_none(
        self, tmp_path, monkeypatch,
    ):
        root = _fake_pack(tmp_path)
        monkeypatch.setattr(resolver, "_pack_roots", lambda pack: [root])
        assert resolve_query_id("cpp/no-such-query") is None

    def test_missing_pack_returns_none_and_probes_once(self, monkeypatch):
        probes: list[str] = []

        def fake_roots(pack):
            probes.append(pack)
            return []

        monkeypatch.setattr(resolver, "_pack_roots", fake_roots)
        assert resolve_query_id("cpp/overflow-buffer") is None
        assert resolve_query_id("cpp/other-query") is None
        assert probes == ["codeql/cpp-queries"]

    def test_malformed_and_unknown_prefix_ids(self, monkeypatch):
        monkeypatch.setattr(
            resolver, "_pack_roots",
            lambda pack: pytest.fail("probed a pack for a bad id"),
        )
        assert resolve_query_id("") is None
        assert resolve_query_id("../../etc/passwd") is None
        assert resolve_query_id("CPP/Upper") is None
        assert resolve_query_id("zz/unknown-language") is None


class TestChainWiring:
    def test_resolved_id_lands_in_the_chain(self, tmp_path, monkeypatch):
        ql = tmp_path / "OverflowBuffer.ql"
        ql.write_text("import cpp\nselect 1\n")
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: str(ql) if qid == "cpp/overflow-buffer" else None,
        )
        chain = _cwe_fallback_chain("CWE-120")
        steps = [e for e in chain if e["type"] == "codeql"]
        assert len(steps) == 1
        assert steps[0]["config"]["query"] == str(ql)

    def test_unresolvable_id_drops_loudly_once(self, monkeypatch, caplog):
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: None,
        )
        with caplog.at_level(logging.INFO, logger=orch.__name__):
            chain1 = _cwe_fallback_chain("CWE-120")
            chain2 = _cwe_fallback_chain("CWE-120")
        assert not [e for e in chain1 if e["type"] == "codeql"]
        assert not [e for e in chain2 if e["type"] == "codeql"]
        loud = [
            r for r in caplog.records
            if "did not resolve" in r.getMessage()
            and r.levelno == logging.INFO
        ]
        assert len(loud) == 1

    def test_on_disk_path_bypasses_the_resolver(self, tmp_path, monkeypatch):
        ql = tmp_path / "direct.ql"
        ql.write_text("import cpp\nselect 1\n")
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: pytest.fail("resolver consulted for a file path"),
        )
        assert orch._resolved_codeql_query(str(ql)) == str(ql)


class TestSharedLookupSurface:
    """The dispatch gate and pack-wide enumeration both consult
    _codeql_query_file — a resolvable pack ID must pass THE shared
    surface so every consumer activates together."""

    def test_gate_returns_resolved_path_for_pack_id(
        self, tmp_path, monkeypatch,
    ):
        ql = tmp_path / "OverflowBuffer.ql"
        ql.write_text("select 1")
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: str(ql) if qid == "cpp/overflow-buffer" else None,
        )
        assert orch._codeql_query_file("cpp/overflow-buffer") == str(ql)
        assert orch._codeql_query_file("cpp/never-heard-of-it") is None
        assert orch._codeql_query_file("") is None

    def test_dispatch_path_accepts_pack_id_through_the_gate(
        self, tmp_path, monkeypatch,
    ):
        import core.audit.sweep as sweep_mod
        from core.audit.orchestrator import TierCounters, _run_tool_chain
        from core.audit.sweep import SweepResult

        ql = tmp_path / "OverflowBuffer.ql"
        ql.write_text("select 1")
        monkeypatch.setattr(
            "core.audit.codeql_query_resolver.resolve_query_id",
            lambda qid: str(ql) if qid == "cpp/overflow-buffer" else None,
        )
        dispatched_paths: list[str] = []

        def fake_sweep(**kw):
            dispatched_paths.append(kw["query_path"])
            return SweepResult(
                tool="codeql", file_path=kw["file_path"],
                function_name=kw["function_name"], outcome="refuted",
            )

        monkeypatch.setattr(sweep_mod, "run_codeql_sweep", fake_sweep)

        class _Cfg:
            target_path = tmp_path
            out_dir = None
            codeql_db_path = str(tmp_path / "cpp-db")
            project_sinks = None

        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "a.c").write_text("int f(void){return 0;}\n")
        counters = {"codeql": TierCounters()}
        _run_tool_chain(
            [{
                "type": "codeql",
                "config": {"query": "cpp/overflow-buffer"},
            }],
            config=_Cfg(),
            file_path="src/a.c",
            function_name="f",
            source="",
            hypothesis="buffer overflow via memcpy",
            tier_counters=counters,
            joern_server=None,
        )
        # The step dispatched with the RESOLVED file, not the raw id.
        assert dispatched_paths == [str(ql)]
        assert counters["codeql"].skipped == 0


class TestVersionDirSelection:
    def test_version_key_orders_numerically(self):
        from core.audit.codeql_query_resolver import _version_key

        names = ["0.9.0", "0.10.0", "0.11.1"]
        assert max(names, key=_version_key) == "0.11.1"
        assert sorted(names, key=_version_key) == [
            "0.9.0", "0.10.0", "0.11.1",
        ]

    def test_package_cache_picks_newest_double_digit_version(
        self, tmp_path, monkeypatch,
    ):
        base = tmp_path / ".codeql" / "packages" / "codeql" / "cpp-queries"
        for v in ("0.9.0", "0.10.0", "0.11.1"):
            (base / v).mkdir(parents=True)
        monkeypatch.setattr(
            resolver.Path, "home", classmethod(lambda cls: tmp_path),
        )
        roots = resolver._package_cache_roots("codeql/cpp-queries")
        assert [r.name for r in roots] == ["0.11.1"]

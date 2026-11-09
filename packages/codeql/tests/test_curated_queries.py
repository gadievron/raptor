"""Tests for the curated in-repo query pass in `/codeql`.

`QueryRunner.analyze_curated_packs` runs the hand-written packs under
`engine/codeql/queries/<lang>/` after the standard suite. Symmetric to
`test_iris_pack_killswitch.py`: the kill-switch must early-out before
any pack work happens, and the CLI flag must reach the master switch.
"""

import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest


from types import ModuleType
from core.testing.module_bindings import patch_module_attribute

_discovery_imports = ModuleType("discovery_fixture_imports")


@pytest.fixture(autouse=True)
def _owned_discovery_imports(monkeypatch):
    import packages.codeql.query_runner as owner
    import shutil
    from core.testing.module_views import scoped_function_imports

    with scoped_function_imports(owner, ('_bundled_stdlib_roots',), {'shutil': shutil}) as imports:
        try:
            monkeypatch.setitem(globals(), "_discovery_imports", imports)
            yield
        finally:
            monkeypatch.undo()


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))


def _bare_runner():
    from packages.codeql.query_runner import QueryRunner
    runner = QueryRunner.__new__(QueryRunner)  # bypass __init__
    runner.codeql_cli = "codeql"
    return runner


class TestAnalyzeCuratedPacksKillSwitch:
    def test_returns_empty_when_disabled(self, monkeypatch):
        from core.config import RaptorConfig

        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", False)
        result = _bare_runner().analyze_curated_packs(
            databases={"cpp": Path("./db")},
            out_dir=Path("./out"),
        )
        assert result == {}

    def test_returns_empty_when_codeql_disabled(self, monkeypatch):
        from core.config import RaptorConfig

        monkeypatch.setattr(RaptorConfig, "CODEQL_ENABLED", False)
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        result = _bare_runner().analyze_curated_packs(
            databases={"cpp": Path("./db")},
            out_dir=Path("./out"),
        )
        assert result == {}

    def test_returns_empty_when_no_pack_root(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig

        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        monkeypatch.setattr(
            RaptorConfig, "CODEQL_QUERIES_DIR", tmp_path / "missing",
        )
        result = _bare_runner().analyze_curated_packs(
            databases={"cpp": tmp_path / "db"},
            out_dir=tmp_path / "out",
        )
        assert result == {}

    def test_skips_languages_without_pack(self, monkeypatch, tmp_path):
        """A pack dir without qlpack.yml or without .ql files is not
        analyzable; languages with no dir at all are skipped too."""
        from core.config import RaptorConfig

        pack_root = tmp_path / "queries"
        (pack_root / "cpp").mkdir(parents=True)  # dir, but empty
        (pack_root / "go").mkdir()
        (pack_root / "go" / "qlpack.yml").write_text("name: x\n")
        # go has manifest but no .ql — still not analyzable
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", pack_root)
        result = _bare_runner().analyze_curated_packs(
            databases={
                "cpp": tmp_path / "db1",
                "go": tmp_path / "db2",
                "python": tmp_path / "db3",
            },
            out_dir=tmp_path / "out",
        )
        assert result == {}


class TestAnalyzeCuratedPacksExecution:
    """End-to-end through `_run_local_pack` with the sandbox mocked."""

    def _make_pack(self, tmp_path: Path, lang: str = "cpp") -> Path:
        pack_root = tmp_path / "queries"
        pack_dir = pack_root / lang
        pack_dir.mkdir(parents=True)
        (pack_dir / "qlpack.yml").write_text(
            f'name: raptor/{lang}-custom-queries\nversion: 0.0.1\ndependencies:\n  codeql/{lang}-all: "*"\n'
        )
        (pack_dir / "Example.ql").write_text("select 1\n")
        return pack_root

    def _sarif(self, n_results: int) -> str:
        return json.dumps({
            "runs": [{"results": [{"ruleId": "x"}] * n_results}],
        })

    def test_success_writes_curated_sarif(self, monkeypatch, tmp_path):
        from core.config import RaptorConfig

        pack_root = self._make_pack(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", pack_root)

        expected_sarif = out_dir / "codeql_cpp_curated.sarif"

        def _fake_run(cmd, **_kwargs):
            if "analyze" in cmd:
                expected_sarif.write_text(self._sarif(2))
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("core.sandbox.run", side_effect=_fake_run):
            result = _bare_runner().analyze_curated_packs(
                databases={"cpp": tmp_path / "db"},
                out_dir=out_dir,
            )

        assert set(result) == {"cpp"}
        assert result["cpp"].success is True
        assert result["cpp"].findings_count == 2
        assert result["cpp"].suite_name == "raptor-curated"
        assert result["cpp"].sarif_path == expected_sarif

    def test_analyze_failure_degrades_to_result_errors(
        self, monkeypatch, tmp_path,
    ):
        from core.config import RaptorConfig

        pack_root = self._make_pack(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", pack_root)

        fail = SimpleNamespace(returncode=2, stdout="", stderr="boom")
        with patch("core.sandbox.run", return_value=fail):
            result = _bare_runner().analyze_curated_packs(
                databases={"cpp": tmp_path / "db"},
                out_dir=out_dir,
            )

        assert result["cpp"].success is False
        assert result["cpp"].errors == ["boom"]

    def test_vendored_root_passes_additional_packs_and_skips_install(
        self, monkeypatch, tmp_path,
    ):
        from core.config import RaptorConfig
        from packages.codeql import query_runner as qr

        pack_root = self._make_pack(tmp_path)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        vendored = tmp_path / "vendored"
        vendored.mkdir()
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        monkeypatch.setattr(RaptorConfig, "CODEQL_QUERIES_DIR", pack_root)
        monkeypatch.setattr(
            qr, "_vendored_stdlib_roots", lambda _lang, **_kwargs: [vendored],
        )

        seen_cmds = []

        def _fake_run(cmd, **_kwargs):
            seen_cmds.append(list(cmd))
            if "analyze" in cmd:
                (out_dir / "codeql_cpp_curated.sarif").write_text(
                    self._sarif(0)
                )
            return SimpleNamespace(returncode=0, stdout="", stderr="")

        with patch("core.sandbox.run", side_effect=_fake_run):
            result = _bare_runner().analyze_curated_packs(
                databases={"cpp": tmp_path / "db"},
                out_dir=out_dir,
            )

        assert result["cpp"].success is True
        # No `pack install` subprocess when a vendored root resolves deps.
        assert not any("install" in cmd for cmd in seen_cmds)
        analyze_cmd = next(cmd for cmd in seen_cmds if "analyze" in cmd)
        assert f"--additional-packs={vendored}" in analyze_cmd


class TestVendoredStdlibRoots:
    def test_picks_newest_version_with_libraries(self, monkeypatch, tmp_path):
        from packages.codeql import query_runner as qr

        base = tmp_path / ".codeql" / "packages" / "codeql" / "cpp-queries"
        old = base / "1.8.1" / ".codeql" / "libraries" / "codeql"
        old.mkdir(parents=True)
        # Newer version without vendored libraries must be skipped.
        (base / "1.10.0").mkdir(parents=True)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        assert qr._vendored_stdlib_roots("cpp") == [old]

    def test_empty_when_nothing_cached(self, monkeypatch, tmp_path):
        from packages.codeql import query_runner as qr

        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr(qr, "_bundled_stdlib_roots", lambda _lang, **_kwargs: [])
        assert qr._vendored_stdlib_roots("cpp") == []

    def test_falls_through_to_bundled(self, monkeypatch, tmp_path):
        from packages.codeql import query_runner as qr

        bundled = tmp_path / "codeql-queries" / "cpp" / "ql" / "lib"
        bundled.mkdir(parents=True)
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr(qr, "_bundled_stdlib_roots", lambda _lang, **_kwargs: [bundled])
        assert qr._vendored_stdlib_roots("cpp") == [bundled]

    def test_bundled_resolves_from_cli(self, monkeypatch, tmp_path):
        from packages.codeql import query_runner as qr

        dist = tmp_path / "codeql"
        dist.mkdir()
        cli = dist / "codeql"
        cli.touch()
        lib_root = tmp_path / "codeql-queries" / "cpp" / "ql" / "lib"
        lib_root.mkdir(parents=True)
        (lib_root / "qlpack.yml").write_text("name: codeql/cpp-all\n")
        (tmp_path / "codeql-queries" / "codeql-workspace.yml").write_text("provide: []\n")
        monkeypatch.setenv("CODEQL_CLI", str(cli))
        assert qr._bundled_stdlib_roots("cpp") == [tmp_path / "codeql-queries"]

    def test_bundled_empty_when_no_cli(self, monkeypatch):
        from packages.codeql import query_runner as qr

        monkeypatch.delenv("CODEQL_CLI", raising=False)
        patch_module_attribute(monkeypatch, _discovery_imports, 'shutil', 'which', lambda _name: None)
        assert qr._bundled_stdlib_roots("cpp") == []


class TestCodeqlCliFlag:
    """`/codeql --no-curated-queries` flips the master switch."""

    @staticmethod
    def _make_args(**overrides):
        base = {
            "repo": "/tmp/some-repo",
            "out": None,
            "codeql_cli": None,
            "languages": None,
            "build_command": None,
            "force": False,
            "extended": False,
            "min_files": 1,
            "traced_build": False,
            "scan_only": False,
            "no_iris_tier1": False,
            "no_curated_queries": False,
        }
        base.update(overrides)
        return SimpleNamespace(**base)

    def _run_workflow(self, args):
        import raptor_codeql
        from core.config import RaptorConfig

        seen = {}

        def _scan(**_kwargs):
            seen["enabled"] = RaptorConfig.CODEQL_CURATED_ENABLED
            return MagicMock(success=True, total_findings=0)

        agent = MagicMock()
        agent.run_autonomous_analysis.side_effect = _scan
        with patch.object(raptor_codeql, "CodeQLAgent", return_value=agent), \
             patch.object(raptor_codeql, "store_codeql_build_reliability"):
            raptor_codeql.run_autonomous_workflow(args)
        return seen["enabled"]

    def test_parser_accepts_flag(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[3]
                                 / "raptor_codeql.py"), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "--no-curated-queries" in r.stdout

    def test_agent_parser_accepts_flag(self):
        import subprocess
        r = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parents[1]
                                 / "agent.py"), "--help"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        assert r.returncode == 0, r.stderr
        assert "--no-curated-queries" in r.stdout

    def test_flag_reaches_master_switch(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        enabled = self._run_workflow(
            self._make_args(no_curated_queries=True)
        )
        assert enabled is False

    def test_no_flag_leaves_switch_on(self, monkeypatch):
        from core.config import RaptorConfig
        monkeypatch.setattr(RaptorConfig, "CODEQL_CURATED_ENABLED", True)
        enabled = self._run_workflow(self._make_args())
        assert enabled is True


# ---------------------------------------------------------------------------
# Evasion regression: every shipped query must be structurally valid
# ---------------------------------------------------------------------------

def _curated_ql_files():
    """Discover checked-in queries; required configuration errors must fail."""
    from core.config import RaptorConfig

    root = Path(RaptorConfig.CODEQL_QUERIES_DIR)
    assert root.is_dir(), f"curated query directory is missing: {root}"
    queries = sorted(root.rglob("*.ql"))
    assert queries, f"no checked-in curated queries found under {root}"
    return queries


class TestCuratedQueryStructure:
    """Each curated .ql file must contain a select clause — a file
    that fails this is either empty, truncated, or not a query."""

    def test_at_least_one_query_per_language(self):
        langs = {q.parent.name for q in _curated_ql_files()}
        assert "cpp" in langs
        assert "java" in langs

    @pytest.mark.parametrize(
        "ql", _curated_ql_files(),
        ids=lambda p: f"{p.parent.name}/{p.name}",
    )
    def test_query_has_select_clause(self, ql):
        text = ql.read_text()
        assert "\nselect" in text.lower() or text.lower().startswith("select"), (
            f"{ql.name} has no select clause"
        )


class TestCuratedQueryDiscoveryContract:
    @staticmethod
    def _discover(config=None, error=None):
        from core.testing.module_views import module_function_view

        owner = sys.modules[__name__]
        imported = ModuleType("core.config")
        imported.RaptorConfig = config
        calls = []

        def import_config(name, globals=None, locals=None, fromlist=(), level=0):
            assert (name, fromlist, level) == ("core.config", ("RaptorConfig",), 0)
            calls.append(name)
            if error is not None:
                raise error
            return imported

        view = module_function_view(owner, import_hook=import_config)
        try:
            return view._curated_ql_files()
        finally:
            assert calls == ["core.config"]
            assert owner._curated_ql_files.__globals__ is vars(owner)

    def test_valid_config_discovers_sorted_queries(self, tmp_path):
        for language in ("java", "cpp"):
            pack = tmp_path / language
            pack.mkdir()
            (pack / "Example.ql").write_text("select 1\n")
        assert self._discover(SimpleNamespace(CODEQL_QUERIES_DIR=tmp_path)) == [
            tmp_path / "cpp" / "Example.ql", tmp_path / "java" / "Example.ql",
        ]

    def test_missing_required_config_attribute_fails(self):
        with pytest.raises(AttributeError, match="CODEQL_QUERIES_DIR"):
            self._discover(SimpleNamespace())

    @pytest.mark.parametrize("error", [ImportError("missing required config"), RuntimeError("broken config")])
    def test_required_config_import_failure_propagates(self, error):
        with pytest.raises(type(error), match=str(error)):
            self._discover(error=error)

    @pytest.mark.parametrize("exists", [False, True], ids=["missing-directory", "empty-directory"])
    def test_missing_checked_in_queries_fails(self, tmp_path, exists):
        root = tmp_path / "queries"
        if exists:
            root.mkdir()
        with pytest.raises(AssertionError, match="curated quer"):
            self._discover(SimpleNamespace(CODEQL_QUERIES_DIR=root))


class TestLocalDependencyContracts:
    @pytest.fixture
    def dependency_pack(self, tmp_path, monkeypatch):
        from packages.codeql import query_runner as qr

        pack = tmp_path / "query"
        pack.mkdir()
        (pack / "qlpack.yml").write_text('dependencies:\n  codeql/cpp-all: "*"\n')
        (pack / "query.ql").write_text("select 1\n")
        root = tmp_path / "libraries"
        root.mkdir()
        runner = _bare_runner()
        runner.codeql_cli = "/selected/distribution/codeql"
        seen = []
        def roots(language, *, codeql_cli=None):
            seen.append((language, codeql_cli))
            return [root]
        monkeypatch.setattr(qr, "_vendored_stdlib_roots", roots)
        return runner, pack, root, seen

    @pytest.mark.parametrize("selection", [".", "query.ql"])
    def test_uses_selected_cli_for_directory_and_single_query(self, dependency_pack, selection):
        runner, pack, root, seen = dependency_pack
        assert runner._local_dependency_roots("cpp", pack / selection) == [root]
        assert seen == [("cpp", runner.codeql_cli)]

    @pytest.mark.parametrize("contract", ["locked", "broken-lock", "pinned", "extra", "malformed", "oversized", "deep"])
    def test_never_overrides_dependency_contracts(self, dependency_pack, contract):
        runner, pack, root, seen = dependency_pack
        manifest = pack / "qlpack.yml"
        if contract == "locked":
            (pack / "codeql-pack.lock.yml").write_text("dependencies: {}\n")
        elif contract == "broken-lock":
            (pack / "codeql-pack.lock.yml").symlink_to(pack / "absent")
        elif contract == "pinned":
            manifest.write_text("dependencies:\n  codeql/cpp-all: 6.1.3\n")
        elif contract == "extra":
            manifest.write_text('dependencies:\n  codeql/cpp-all: "*"\n  example/other: "*"\n')
        elif contract == "malformed":
            manifest.write_text("dependencies: [\n")
        elif contract == "deep":
            manifest.write_text("[" * 2000 + "]" * 2000)
        else:
            manifest.write_text("#" * (64 * 1024 + 1))
        assert runner._local_dependency_roots("cpp", pack) == []
        assert not seen

    def test_custom_analysis_selects_roots_without_install_or_network(self, dependency_pack, tmp_path, monkeypatch):
        import core.sandbox
        from core.config import RaptorConfig

        runner, pack, root, seen = dependency_pack
        output = tmp_path / "out"
        calls = []
        monkeypatch.setattr(runner, "_compatible_query_args", lambda path: ([str(path)], []))
        monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
        def run(command, **scope):
            calls.append((command, scope))
            (output / "codeql_cpp_custom.sarif").write_text(json.dumps({"runs": [{"results": []}]}))
            return SimpleNamespace(returncode=0, stdout="", stderr="")
        monkeypatch.setattr(core.sandbox, "run", run)
        result = runner.run_custom_queries(tmp_path / "db", pack / "query.ql", output, "cpp")
        assert result.success, result.errors
        assert len(calls) == 1
        command, scope = calls[0]
        assert f"--additional-packs={root}" in command
        assert scope["block_network"] is True
        assert str(root) in scope["readable_paths"]
        assert str(root) not in scope["writable_paths"]

    def test_explicit_cli_wins_over_ambient_cli(self, tmp_path, monkeypatch):
        from packages.codeql import query_runner as qr
        install = tmp_path / "selected" / "codeql"
        install.mkdir(parents=True)
        binary = install / "codeql"
        binary.touch()
        workspace = install.parent / "codeql-queries"
        library = workspace / "cpp" / "ql" / "lib"
        library.mkdir(parents=True)
        (library / "qlpack.yml").write_text("name: codeql/cpp-all\n")
        (workspace / "codeql-workspace.yml").write_text("provide: []\n")
        monkeypatch.setenv("CODEQL_CLI", "/wrong/distribution/codeql")
        assert qr._bundled_stdlib_roots("cpp", codeql_cli=str(binary)) == [workspace]


    def test_bare_bundled_library_keeps_leaf_discovery(self, tmp_path):
        from packages.codeql import query_runner as qr
        install = tmp_path / "codeql"
        install.mkdir()
        binary = install / "codeql"
        binary.touch()
        library = tmp_path / "codeql-queries" / "cpp" / "ql" / "lib"
        library.mkdir(parents=True)
        (library / "qlpack.yml").write_text("name: codeql/cpp-all\n")
        assert qr._bundled_stdlib_roots("cpp", codeql_cli=str(binary)) == [library]

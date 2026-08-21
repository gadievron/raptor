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
            f"name: raptor/{lang}-custom-queries\nversion: 0.0.1\n"
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
            qr, "_vendored_stdlib_roots", lambda _lang: [vendored],
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
        assert qr._vendored_stdlib_roots("cpp") == []


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

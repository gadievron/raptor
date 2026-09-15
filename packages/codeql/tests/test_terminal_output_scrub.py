"""Tool output reaching the operator terminal is control-escaped.

CodeQL stderr and SARIF-derived strings carry content the scanned repo
controls: traced builds run its build scripts, extractor diagnostics
quote hostile source, and SARIF rule ids / messages / paths come from
analysing it. Raw ANSI/OSC/bidi sequences in any of those can spoof or
overwrite the operator's live terminal (core.logging does no control
scrubbing of its own), so every echo site must escape before print /
logger emission.
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

HOSTILE = "\x1b]0;pwned\x07\x1b[31mred‮evil"


def _assert_inert(text: str) -> None:
    assert "\x1b" not in text
    assert "\x07" not in text
    assert "‮" not in text
    # The escaped spelling must survive — evidence is kept, not dropped.
    assert "\\x1b" in text


class TestPrintSummaryErrors:
    def test_hostile_error_lines_escaped(self, tmp_path, capsys):
        from packages.codeql.agent import CodeQLAgent, CodeQLWorkflowResult

        agent = CodeQLAgent.__new__(CodeQLAgent)
        agent.out_dir = tmp_path
        result = CodeQLWorkflowResult(
            success=False,
            repo_path="repo",
            timestamp="t",
            duration_seconds=0.0,
            languages_detected={},
            databases_created={},
            analyses_completed={},
            total_findings=0,
            sarif_files=[],
            errors=[HOSTILE],
        )
        agent.print_summary(result)
        _assert_inert(capsys.readouterr().out)


class TestDataflowExamples:
    def test_sarif_derived_fields_escaped(self, tmp_path):
        from packages.codeql.agent import CodeQLAgent

        agent = CodeQLAgent.__new__(CodeQLAgent)
        loc = {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/{HOSTILE}.c"},
                    "region": {"startLine": 3},
                },
            },
        }
        sarif = {
            "runs": [{
                "results": [{
                    "ruleId": f"cpp/{HOSTILE}",
                    "message": {"text": HOSTILE},
                    "codeFlows": [{
                        "threadFlows": [{"locations": [loc, loc]}],
                    }],
                }],
            }],
        }
        examples = agent._extract_dataflow_examples(
            tmp_path / "x.sarif", sarif_data=sarif,
        )
        assert examples, "fixture must reach the append site"
        for example in examples:
            for key in ("rule", "message", "source", "sink"):
                _assert_inert(example[key])


class TestAnalyzeStderrEcho:
    def test_run_suite_failure_stderr_escaped(self, tmp_path, monkeypatch,
                                              caplog):
        from packages.codeql.query_runner import QueryRunner

        fake_cli = tmp_path / "codeql"
        fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_cli.chmod(0o755)
        runner = QueryRunner(codeql_cli=str(fake_cli))

        def _fail(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr=HOSTILE,
            )

        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fail)
        with caplog.at_level("ERROR"):
            result = runner.run_suite(
                tmp_path / "db", "python", tmp_path / "out",
            )
        assert result.success is False
        _assert_inert(caplog.text)


class TestLocalPackStderrEchoes:
    """The IRIS/curated pack worker's failure path is the lane's main
    echo surface: analyze stderr quotes hostile source (extractor
    diagnostics) and pack-install stderr relays registry-influenced
    content. Both echoes must be escaped; the stored error list stays
    raw (data plane)."""

    def _runner(self, tmp_path):
        from packages.codeql.query_runner import QueryRunner

        fake_cli = tmp_path / "codeql"
        fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        fake_cli.chmod(0o755)
        return QueryRunner(codeql_cli=str(fake_cli))

    def test_analyze_failure_stderr_escaped(self, tmp_path, monkeypatch,
                                            caplog):
        runner = self._runner(tmp_path)

        def _fail(cmd, **kwargs):
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr=HOSTILE,
            )

        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fail)
        pack = tmp_path / "pack"
        pack.mkdir()
        with caplog.at_level("WARNING"):
            result = runner._run_local_pack(
                "python", tmp_path / "db", pack, tmp_path / "out",
                suite_name="raptor-iris-local",
                sarif_name="codeql_python_iris.sarif",
                label="IRIS LocalFlowSource",
                skip_install=True,
            )
        assert result.success is False
        # Stored errors keep the raw string — the echo is what escapes.
        assert result.errors and "\x1b" in result.errors[0]
        _assert_inert(caplog.text)

    def test_pack_install_stderr_escaped(self, tmp_path, monkeypatch,
                                         caplog):
        runner = self._runner(tmp_path)

        def _fake(cmd, **kwargs):
            # First call is `codeql pack install` (no lockfile in the
            # empty pack dir, so the resolved-deps skip cannot fire);
            # the analyze call after it also fails hostile.
            return subprocess.CompletedProcess(
                args=cmd, returncode=1, stdout="", stderr=HOSTILE,
            )

        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fake)
        pack = tmp_path / "pack"
        pack.mkdir()
        with caplog.at_level("WARNING"):
            result = runner._run_local_pack(
                "python", tmp_path / "db", pack, tmp_path / "out",
                suite_name="raptor-iris-local",
                sarif_name="codeql_python_iris.sarif",
                label="IRIS LocalFlowSource",
                skip_install=False,
            )
        assert result.success is False
        assert "pack install" in caplog.text, "fixture must hit the install echo"
        _assert_inert(caplog.text)


class TestDatabaseCreationStderrEcho:
    def test_creation_failure_stderr_escaped(self, tmp_path, caplog):
        from core.build.build_detector import BuildSystem
        from packages.codeql.database_manager import DatabaseManager

        with patch.object(
            DatabaseManager, "_detect_codeql_cli",
            return_value="/usr/bin/codeql",
        ):
            mgr = DatabaseManager()
        mgr.codeql_cli = "/usr/bin/codeql"
        mgr.cache_dir = tmp_path / "cache"
        mgr.cache_dir.mkdir()
        mgr.db_root = mgr.cache_dir

        bs = BuildSystem(
            type="npm", command="", working_dir=tmp_path,
            env_vars={}, confidence=1.0, detected_files=[],
        )

        def fake_run(cmd, **kwargs):
            r = MagicMock()
            if "--version" in cmd:
                r.returncode = 0
                r.stdout = "2.16.0\n"
                r.stderr = ""
            else:
                r.returncode = 1
                r.stdout = ""
                r.stderr = HOSTILE
            return r

        db_path = tmp_path / "db"
        with patch("core.sandbox.run", side_effect=fake_run), \
             patch.object(mgr, "_count_database_files", return_value=0), \
             patch.object(mgr, "save_metadata"), \
             patch.object(mgr, "get_cached_database", return_value=None), \
             patch.object(mgr, "compute_repo_hash", return_value="abc"), \
             patch.object(mgr, "get_database_dir", return_value=db_path), \
             patch.object(
                 mgr, "_salvage_creation_log", return_value=HOSTILE,
             ), \
             caplog.at_level("ERROR"):
            result = mgr.create_database(tmp_path, "javascript", bs)

        assert result.success is False
        _assert_inert(caplog.text)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))

"""Regression: run_suite never reports success without readable SARIF.

An analyze that exits 0 but leaves no parseable SARIF behind used to
return QueryResult(success=True, findings_count=0) — an unreadable
output read downstream as a clean scan.
"""

from __future__ import annotations

import json
import subprocess

import pytest

from packages.codeql.query_runner import QueryRunner


@pytest.fixture()
def runner(tmp_path, monkeypatch):
    fake_cli = tmp_path / "codeql"
    fake_cli.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    fake_cli.chmod(0o755)
    monkeypatch.delenv("CODEQL_QUERIES", raising=False)
    return QueryRunner(codeql_cli=str(fake_cli))


def _fake_sandbox(write_sarif=None):
    """A sandbox stub: rc=0 and optionally writes SARIF via callback."""

    def _run(cmd, **kwargs):
        if write_sarif is not None:
            write_sarif(cmd)
        return subprocess.CompletedProcess(
            args=cmd, returncode=0, stdout="", stderr="",
        )

    return _run


def _sarif_out_path(cmd):
    for arg in cmd:
        if str(arg).startswith("--output="):
            return str(arg)[len("--output="):]
    raise AssertionError("no --output= in analyze cmd")


class TestRunSuiteSarifFailure:
    def test_missing_sarif_after_rc0_is_failure(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fake_sandbox())
        result = runner.run_suite(
            tmp_path / "db", "python", tmp_path / "out",
        )
        assert result.success is False
        assert result.findings_count == 0
        assert any("SARIF output missing" in e for e in result.errors)

    def test_unparseable_sarif_after_rc0_is_failure(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox

        def _write_garbage(cmd):
            from pathlib import Path
            Path(_sarif_out_path(cmd)).write_text(
                "{not json", encoding="utf-8",
            )

        monkeypatch.setattr(
            core.sandbox, "run", _fake_sandbox(_write_garbage),
        )
        result = runner.run_suite(
            tmp_path / "db", "python", tmp_path / "out",
        )
        assert result.success is False
        assert any("unreadable" in e for e in result.errors)

    def test_valid_empty_sarif_is_a_clean_success(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox

        def _write_valid(cmd):
            from pathlib import Path
            Path(_sarif_out_path(cmd)).write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "codeql", "rules": []}},
                    "results": [],
                }],
            }), encoding="utf-8")

        monkeypatch.setattr(
            core.sandbox, "run", _fake_sandbox(_write_valid),
        )
        result = runner.run_suite(
            tmp_path / "db", "python", tmp_path / "out",
        )
        assert result.success is True
        assert result.findings_count == 0

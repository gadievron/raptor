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


class TestRunCustomQueriesSarifFailure:
    """Same guard, sibling entry point: run_custom_queries used to map
    an rc==0 analyze whose SARIF the bounded loader refuses to
    success=True findings_count=0 — a verified silence."""

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
        result = runner.run_custom_queries(
            tmp_path / "db", tmp_path / "pack", tmp_path / "out",
            "python",
        )
        assert result.success is False
        assert result.findings_count == 0
        assert any("unreadable" in e for e in result.errors)

    def test_missing_sarif_after_rc0_is_failure(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fake_sandbox())
        result = runner.run_custom_queries(
            tmp_path / "db", tmp_path / "pack", tmp_path / "out",
            "python",
        )
        assert result.success is False
        assert any("SARIF output missing" in e for e in result.errors)

    def test_valid_sarif_counts_findings(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox

        def _write_valid(cmd):
            from pathlib import Path
            Path(_sarif_out_path(cmd)).write_text(json.dumps({
                "version": "2.1.0",
                "runs": [{
                    "tool": {"driver": {"name": "codeql", "rules": []}},
                    "results": [{"ruleId": "r1", "message": {"text": "x"}}],
                }],
            }), encoding="utf-8")

        monkeypatch.setattr(
            core.sandbox, "run", _fake_sandbox(_write_valid),
        )
        result = runner.run_custom_queries(
            tmp_path / "db", tmp_path / "pack", tmp_path / "out",
            "python",
        )
        assert result.success is True
        assert result.findings_count == 1


class TestRunLocalPackSarifFailure:
    """Same guard for the IRIS/curated pack worker."""

    def _run(self, runner, tmp_path):
        pack = tmp_path / "pack"
        pack.mkdir(exist_ok=True)
        return runner._run_local_pack(
            "python", tmp_path / "db", pack, tmp_path / "out",
            suite_name="raptor-iris-local",
            sarif_name="codeql_python_iris.sarif",
            label="IRIS LocalFlowSource",
            skip_install=True,
        )

    def test_unparseable_sarif_after_rc0_is_failure(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox

        (tmp_path / "out").mkdir()
        (tmp_path / "out" / "codeql_python_iris.sarif").write_text(
            "{not json", encoding="utf-8",
        )
        monkeypatch.setattr(core.sandbox, "run", _fake_sandbox())
        result = self._run(runner, tmp_path)
        assert result.success is False
        assert result.findings_count == 0
        assert any("unreadable" in e for e in result.errors)

    def test_missing_sarif_after_rc0_is_failure(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sandbox
        monkeypatch.setattr(core.sandbox, "run", _fake_sandbox())
        result = self._run(runner, tmp_path)
        assert result.success is False
        assert any("SARIF output missing" in e for e in result.errors)


# JSON that load_sarif accepts but that is NOT a SARIF document: a
# 0-byte file (parses to {}) and a valid-JSON dict without a `runs`
# list. Both used to read as success=True findings_count=0.
NON_SARIF_SHAPES = [
    ("empty_file", ""),
    ("wrong_schema", json.dumps({"hello": "world"})),
    ("runs_not_a_list", json.dumps({"runs": "corrupt"})),
]


def _write_shape(content):
    def _write(cmd):
        from pathlib import Path
        Path(_sarif_out_path(cmd)).write_text(content, encoding="utf-8")
    return _write


class TestNonSarifJsonIsFailure:
    """rc==0 plus JSON-that-is-not-SARIF must never be a clean scan."""

    @pytest.mark.parametrize(
        "shape,content", NON_SARIF_SHAPES, ids=[s for s, _ in NON_SARIF_SHAPES],
    )
    def test_run_suite(self, runner, tmp_path, monkeypatch, shape, content):
        import core.sandbox
        monkeypatch.setattr(
            core.sandbox, "run", _fake_sandbox(_write_shape(content)),
        )
        result = runner.run_suite(tmp_path / "db", "python", tmp_path / "out")
        assert result.success is False
        assert result.findings_count == 0
        assert any("unreadable" in e for e in result.errors)

    @pytest.mark.parametrize(
        "shape,content", NON_SARIF_SHAPES, ids=[s for s, _ in NON_SARIF_SHAPES],
    )
    def test_run_custom_queries(
        self, runner, tmp_path, monkeypatch, shape, content,
    ):
        import core.sandbox
        monkeypatch.setattr(
            core.sandbox, "run", _fake_sandbox(_write_shape(content)),
        )
        result = runner.run_custom_queries(
            tmp_path / "db", tmp_path / "pack", tmp_path / "out", "python",
        )
        assert result.success is False
        assert result.findings_count == 0
        assert any("unreadable" in e for e in result.errors)

    @pytest.mark.parametrize(
        "shape,content", NON_SARIF_SHAPES, ids=[s for s, _ in NON_SARIF_SHAPES],
    )
    def test_run_local_pack(
        self, runner, tmp_path, monkeypatch, shape, content,
    ):
        import core.sandbox
        pack = tmp_path / "pack"
        pack.mkdir()
        (tmp_path / "out").mkdir()
        (tmp_path / "out" / "codeql_python_iris.sarif").write_text(
            content, encoding="utf-8",
        )
        monkeypatch.setattr(core.sandbox, "run", _fake_sandbox())
        result = runner._run_local_pack(
            "python", tmp_path / "db", pack, tmp_path / "out",
            suite_name="raptor-iris-local",
            sarif_name="codeql_python_iris.sarif",
            label="IRIS LocalFlowSource",
            skip_install=True,
        )
        assert result.success is False
        assert result.findings_count == 0
        assert any("unreadable" in e for e in result.errors)

    def test_count_helper_refuses_malformed_run_entries(
        self, runner, tmp_path,
    ):
        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({"runs": [42]}), encoding="utf-8")
        assert runner._count_sarif_findings(p) is None
        p.write_text(
            json.dumps({"runs": [{"results": "corrupt"}]}), encoding="utf-8",
        )
        assert runner._count_sarif_findings(p) is None

    def test_count_helper_counts_valid_runs(self, runner, tmp_path):
        p = tmp_path / "x.sarif"
        p.write_text(json.dumps({
            "version": "2.1.0",
            "runs": [
                {"results": [{"ruleId": "r1"}, {"ruleId": "r2"}]},
                {"results": []},
            ],
        }), encoding="utf-8")
        assert runner._count_sarif_findings(p) == 2


class TestOversizedSarifDiagnosis:
    """The refusal stays honest-loud, but the oversized case is
    diagnosed with the mechanical facts (size vs SARIF_MAX_BYTES) —
    a completed multi-hour analyze discarded over the parser cap
    must name the limit that fired and that the artifact is intact,
    not the undifferentiated parse/size/schema wording."""

    def test_oversized_reason_names_the_cap(
        self, runner, tmp_path, monkeypatch,
    ):
        import core.sarif.parser as sarif_parser
        monkeypatch.setattr(sarif_parser, "SARIF_MAX_BYTES", 64)
        big = tmp_path / "results.sarif"
        big.write_text(json.dumps({"runs": [{"results": []}]}) + " " * 200)
        reason = runner._unreadable_sarif_reason(big)
        assert "exceeds the parser cap" in reason
        assert "SARIF_MAX_BYTES=64" in reason
        assert "artifact is intact" in reason

    def test_undersized_unreadable_keeps_parse_wording(
        self, runner, tmp_path,
    ):
        bad = tmp_path / "results.sarif"
        bad.write_text("{not json")
        reason = runner._unreadable_sarif_reason(bad)
        assert "parse/schema failure" in reason

    def test_missing_wording_unchanged(self, runner, tmp_path):
        reason = runner._unreadable_sarif_reason(tmp_path / "gone.sarif")
        assert "SARIF output missing" in reason

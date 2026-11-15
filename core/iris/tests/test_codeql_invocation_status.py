"""Refinement success requires usable CodeQL invocation diagnostics."""

import json

import pytest

import packages.codeql
from packages.codeql import query_runner
from core.iris.codeql_runner import make_codeql_tool_runner
from core.iris.specs import TaintSpec


@pytest.mark.parametrize("invocation,successful", [
    ({"executionSuccessful": False}, False),
    ({"executionSuccessful": True, "toolExecutionNotifications": [{"level": "error"}]}, False),
    ({"executionSuccessful": True, "toolExecutionNotifications": {}}, False),
    ({"executionSuccessful": True, "toolExecutionNotifications": [{
        "level": "warning", "properties": {"coverage_limitation": "partial_analysis"},
    }]}, False),
    ({"executionSuccessful": True, "toolExecutionNotifications": [{"level": "warning"}]}, True),
    ({"executionSuccessful": True}, True),
], ids=["failed", "error-note", "malformed", "partial", "warning", "clean"])
def test_feedback_preserves_invocation_status(tmp_path, monkeypatch, invocation, successful):
    database = tmp_path / "db"
    database.mkdir()
    report = tmp_path / "owned.sarif"
    report.write_text(json.dumps({"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "CodeQL"}},
        "invocations": [invocation], "results": [],
    }]}))
    runner = query_runner.QueryRunner(codeql_cli="/owned/codeql")
    calls = []

    def analyze(language, db, pack, out, **kwargs):
        calls.append((language, db))
        assert (pack / "IrisSpecs.ql").is_file()
        return query_runner.QueryResult(
            success=True, language=language, database_path=db,
            sarif_path=report, findings_count=0, duration_seconds=0,
            errors=[], suite_name=kwargs["suite_name"],
        )

    monkeypatch.setattr(runner, "run_local_pack", analyze)
    monkeypatch.setattr(packages.codeql, "is_available", lambda: True)
    monkeypatch.setattr(query_runner, "QueryRunner", lambda: runner)
    monkeypatch.setattr(query_runner, "vendored_stdlib_roots", lambda *args: [])
    callback = make_codeql_tool_runner(database, tmp_path, language="python")
    assert callback is not None
    feedback = callback([
        TaintSpec(function="owned_source", file="owned.py", role="source"),
        TaintSpec(function="owned_sink", file="owned.py", role="sink"),
    ])
    assert calls == [("python", database)]
    assert feedback.n_attempts == 1
    assert feedback.n_successes == int(successful)
    assert bool(feedback.tool_errors) is not successful
    assert feedback.zero_signal is not successful
    assert not feedback.confirmed_keys and not feedback.refuted_keys

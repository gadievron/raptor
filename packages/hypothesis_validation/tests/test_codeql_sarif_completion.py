"""Incomplete query execution cannot support a clean zero-match verdict."""

import json
from pathlib import Path
from types import SimpleNamespace

from core.config import RaptorConfig
from core.testing.module_bindings import patch_module_attribute
from packages.hypothesis_validation.adapters import codeql


def test_incomplete_sarif_execution_is_failure_with_warning_controls(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    query = tmp_path / "query.ql"
    query.write_text("/**\n * @id owned/query\n */\nimport cpp\nselect 1\n")
    run_record = {}
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        output = next(arg.split("=", 1)[1] for arg in cmd if arg.startswith("--output="))
        Path(output).write_text(json.dumps({"runs": [run_record]}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
    patch_module_attribute(monkeypatch, codeql, "subprocess", "run", run)
    adapter = codeql.CodeQLAdapter(database_path=db, codeql_bin="owned-codeql", sandbox=False)
    bad_invocations = (
        [{"executionSuccessful": False}],
        [{"executionSuccessful": "true"}],
        [{"toolExecutionNotifications": [{"level": "error"}]}],
        [{"toolConfigurationNotifications": [{"level": "error"}]}],
        [{"toolConfigurationNotifications": [{"level": "note", "properties": {
            "coverage_limitation": "query_budget",
        }}]}],
        [{"toolExecutionNotifications": None}],
        [None],
        {},
    )
    for invocations in bad_invocations:
        run_record = {"results": [], "invocations": invocations}
        evidence = (
            adapter.run_prebuilt_query(query, tmp_path, env={}),
            adapter.run_prebuilt_queries_batch([query], env={})[str(query)],
            adapter.run("import cpp\nselect 1", tmp_path, env={}),
        )
        for result in evidence:
            assert not result.success, invocations
            assert result.matches == []
            assert "parse failure" in result.error
    for invocation in (
        {"executionSuccessful": True},
        {"toolExecutionNotifications": [{"level": "warning"}]},
        {"toolConfigurationNotifications": [{"level": "warning"}]},
        {"toolConfigurationNotifications": [{"properties": {
            "coverage_limitation": "review_candidates",
        }}]},
    ):
        run_record = {"results": [], "invocations": [invocation]}
        evidence = (
            adapter.run_prebuilt_query(query, tmp_path, env={}),
            adapter.run_prebuilt_queries_batch([query], env={})[str(query)],
            adapter.run("import cpp\nselect 1", tmp_path, env={}),
        )
        assert all(result.success and result.matches == [] for result in evidence)
    assert len(calls) == 36

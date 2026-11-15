"""Malformed coordinates cannot become located CodeQL matches."""

import json
from pathlib import Path
from types import SimpleNamespace

from core.config import RaptorConfig
from core.testing.module_bindings import patch_module_attribute
from packages.hypothesis_validation.adapters import codeql


def test_malformed_sarif_lines_are_failure_evidence(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    query = tmp_path / "query.ql"
    query.write_text("/**\n * @id owned/query\n */\nimport cpp\nselect 1\n")
    line = 1
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        output = next(arg.split("=", 1)[1] for arg in cmd if arg.startswith("--output="))
        Path(output).write_text(json.dumps({"runs": [{"results": [{
            "ruleId": "owned/query", "message": {"text": "owned"},
            "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "a.c"}, "region": {"startLine": line},
            }}],
        }]}]}))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
    patch_module_attribute(monkeypatch, codeql, "subprocess", "run", run)
    adapter = codeql.CodeQLAdapter(database_path=db, codeql_bin="owned-codeql", sandbox=False)
    for line in (True, False, 1.5, "1", None, float("nan"), float("inf")):
        evidence = (
            adapter.run_prebuilt_queries_batch([query], env={})[str(query)],
            adapter.run_prebuilt_query(query, tmp_path, env={}),
            adapter.run("import cpp\nselect 1", tmp_path, env={}),
        )
        assert all(not result.success and result.matches == [] for result in evidence)
        assert all("parse failure" in result.error for result in evidence)
    for line in (0, 1, 1.0):
        result = adapter.run_prebuilt_queries_batch([query], env={})[str(query)]
        assert result.success
        assert result.matches[0]["line"] == int(line)
        assert type(result.matches[0]["line"]) is int
    assert len(calls) == 24

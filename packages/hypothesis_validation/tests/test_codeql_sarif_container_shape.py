"""Malformed SARIF containers must not become zero-match evidence."""

import json
from pathlib import Path
from types import SimpleNamespace

from core.config import RaptorConfig
from core.testing.module_bindings import patch_module_attribute
from packages.hypothesis_validation.adapters import codeql


def test_malformed_container_is_failure_across_codeql_entrypoints(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    query = tmp_path / "query.ql"
    query.write_text("/**\n * @id owned/query\n */\nimport cpp\nselect 1\n")
    current = {}
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        output = next(arg.split("=", 1)[1] for arg in cmd if arg.startswith("--output="))
        Path(output).write_text(json.dumps(current))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
    patch_module_attribute(monkeypatch, codeql, "subprocess", "run", run)
    adapter = codeql.CodeQLAdapter(database_path=db, codeql_bin="owned-codeql", sandbox=False)
    for payload in (
        {}, {"runs": None}, {"runs": {}}, {"runs": ""},
        {"runs": [None]}, {"runs": [{"results": None}]},
        {"runs": [{"results": {}}]}, {"runs": [{"results": ""}]},
    ):
        current = payload
        evidence = [
            adapter.run_prebuilt_query(query, tmp_path, env={}),
            adapter.run_prebuilt_queries_batch([query], env={})[str(query)],
            adapter.run("import cpp\nselect 1", tmp_path, env={}),
        ]
        for result in evidence:
            assert not result.success, payload
            assert result.matches == []
            assert "parse failure" in result.error
    # Empty results and omitted optional results remain successful emptiness.
    for payload in ({"runs": []}, {"runs": [{}]}, {"runs": [{"results": []}]}):
        current = payload
        result = adapter.run_prebuilt_queries_batch([query], env={})[str(query)]
        assert result.success
        assert result.matches == []
    assert len(calls) == 27

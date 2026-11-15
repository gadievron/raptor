"""Ambiguous batch rule identifiers cannot prove per-query absence."""

import json
from pathlib import Path
from types import SimpleNamespace

from core.config import RaptorConfig
from core.testing.module_bindings import patch_module_attribute
from packages.hypothesis_validation.adapters import codeql


def test_duplicate_full_rule_ids_refuse_per_query_attribution(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    queries = []
    for name in ("first", "second", "shared"):
        query = tmp_path / f"{name}.ql"
        qid = "vendor/shared" if name != "shared" else "other/unique"
        query.write_text(f"/**\n * @id {qid}\n */\nimport cpp\nselect 1\n")
        queries.append(query)
    sarif = json.dumps({"runs": [{"results": [{
        "ruleId": "vendor/shared", "message": {"text": "ambiguous hit"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "a.c"}, "region": {"startLine": 1},
        }}],
    }]}]})
    calls = []

    def run(cmd, **kwargs):
        calls.append(cmd)
        output = next(arg.split("=", 1)[1] for arg in cmd if arg.startswith("--output="))
        Path(output).write_text(sarif)
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(RaptorConfig, "CODEQL_OFFLINE", True)
    patch_module_attribute(monkeypatch, codeql, "subprocess", "run", run)
    adapter = codeql.CodeQLAdapter(database_path=db, codeql_bin="owned-codeql", sandbox=False)
    results = adapter.run_prebuilt_queries_batch(queries, env={})
    assert len(calls) == 1
    assert set(results) == {str(q) for q in queries}
    for result in results.values():
        assert not result.success
        assert result.matches == []
        assert "could not be attributed" in result.error

"""Validation cache reuse must retain finding-specific source scope."""

import zipfile
from dataclasses import replace

from packages.hypothesis_validation import Hypothesis

from core.config import RaptorConfig
from packages.hypothesis_validation.adapters import CodeQLAdapter
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.llm_analysis import dataflow_validation as dv


def test_prebuilt_cache_preserves_distinct_finding_locations(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    (db / "codeql-database.yml").write_text("")
    with zipfile.ZipFile(db / "src.zip", "w") as archive:
        archive.writestr("repo/a.c", "int main(void) { return 0; }\n")
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    monkeypatch.setattr(CodeQLAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(dv, "_db_is_stale", lambda *args: False)
    monkeypatch.setattr(dv, "discover_prebuilt_query", lambda *args: tmp_path / "flow.ql")
    evidence = ToolEvidence(
        tool="codeql", rule="flow", success=True,
        matches=[{"file": "a.c", "line": 10, "message": "flow"}],
        summary="one matching location",
    )
    calls = []

    def run_prebuilt(self, query, target):
        calls.append((query, target))
        return evidence

    monkeypatch.setattr(CodeQLAdapter, "run_prebuilt_query", run_prebuilt)
    findings = [
        {"finding_id": fid, "tool": "semgrep", "file_path": "a.c",
         "start_line": line, "cwe_id": "CWE-78"}
        for fid, line in (("F1", 10), ("F2", 90), ("F3", 10))
    ]
    analyses = {
        f["finding_id"]: {"dataflow_summary": "input reaches command",
                          "is_exploitable": True, "cwe_id": "CWE-78"}
        for f in findings
    }
    metrics = dv.validate_dataflow_claims(
        findings=findings, results_by_id=analyses, codeql_db=db,
        repo_path=tmp_path, llm_client=None, deep_validate_disabled=True,
    )
    assert analyses["F1"]["dataflow_validation"]["verdict"] == "confirmed"
    assert analyses["F2"]["dataflow_validation"]["verdict"] == "inconclusive"
    assert analyses["F3"]["dataflow_validation"]["verdict"] == "confirmed"
    assert metrics["n_errors"] == 0
    assert metrics["n_validated"] == 2
    assert metrics["n_cache_hits"] == 1
    assert len(calls) == 2


def test_cache_key_distinguishes_query_and_coverage_scope(tmp_path):
    h = Hypothesis(claim="flow", target=tmp_path, cwe="CWE-78", context="same")
    finding = {"file_path": "source", "start_line": 10, "language": "c",
               "function_name": "handle", "rule_id": "command-injection"}
    db = tmp_path / "db"
    base = dv._hypothesis_cache_key(h, finding=finding, database_path=db)
    assert dv._hypothesis_cache_key(
        h, finding=dict(finding), database_path=db,
    ) == base
    assert dv._hypothesis_cache_key(
        replace(h, context="different premises"), finding=finding, database_path=db,
    ) != base
    assert dv._hypothesis_cache_key(
        h, finding=finding, database_path=tmp_path / "other-db",
    ) != base
    for key, value in (
        ("file_path", "b.c"), ("start_line", 90), ("language", "python"),
        ("function_name", "other"), ("rule_id", "sql-injection"),
        ("cwe_id", "CWE-89"),
    ):
        assert dv._hypothesis_cache_key(
            h, finding={**finding, key: value}, database_path=db,
        ) != base, key

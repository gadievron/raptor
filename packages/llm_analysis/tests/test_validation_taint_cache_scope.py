"""Cached prebuilt absence must retain taint representability scope."""

import zipfile

from core.config import RaptorConfig
from packages.hypothesis_validation.adapters import CodeQLAdapter
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.llm_analysis import dataflow_validation as dv


def test_cache_distinguishes_static_and_approximate_taint_findings(tmp_path, monkeypatch):
    db = tmp_path / "db"
    db.mkdir()
    with zipfile.ZipFile(db / "src.zip", "w") as archive:
        archive.writestr("repo/a.c", "int main(void) { return 0; }\n")
    pack = tmp_path / "pack"
    pack.mkdir()
    query = pack / "flow.ql"
    query.write_text("import cpp\nselect 1\n")
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    monkeypatch.setattr(RaptorConfig, "EXTRA_CODEQL_PACK_ROOTS", [pack])
    monkeypatch.setattr(CodeQLAdapter, "is_available", lambda self: True)
    monkeypatch.setattr(dv, "_db_is_stale", lambda *args: False)
    monkeypatch.setattr(dv, "discover_prebuilt_query", lambda *args: query)
    zero = ToolEvidence(tool="codeql", rule=str(query), success=True, matches=[])
    calls = []

    def run_prebuilt(self, query_path, target):
        calls.append((query_path, target))
        return zero

    monkeypatch.setattr(CodeQLAdapter, "run_prebuilt_query", run_prebuilt)
    findings = [
        {"finding_id": fid, "tool": "taint-crossfile", "file_path": "a.c",
         "start_line": 1, "cwe_id": "CWE-78", "has_dataflow": False,
         "metadata": {"path_tier": tier}}
        for fid, tier in (("static", "resolved_static"),
                          ("approx", "heuristic_dynamic"),
                          ("approx-duplicate", "heuristic_dynamic"))
    ]
    for ordered in (findings, list(reversed(findings))):
        analyses = {f["finding_id"]: {"is_exploitable": True,
                    "dataflow_summary": "input reaches command", "cwe_id": "CWE-78"}
                    for f in ordered}
        calls.clear()
        metrics = dv.validate_dataflow_claims(
            findings=ordered, results_by_id=analyses, codeql_db=db,
            repo_path=tmp_path, llm_client=None, deep_validate_disabled=True,
        )
        assert analyses["static"]["dataflow_validation"]["verdict"] == "refuted"
        assert analyses["approx"]["dataflow_validation"]["verdict"] == "inconclusive"
        assert analyses["approx-duplicate"]["dataflow_validation"]["verdict"] == "inconclusive"
        assert metrics["n_errors"] == 0
        assert metrics["n_validated"] == 2
        assert metrics["n_cache_hits"] == 1
        assert len(calls) == 2

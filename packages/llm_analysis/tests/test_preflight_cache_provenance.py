"""Cached dataflow diagnostics cannot manufacture a CodeQL refutation."""
import copy
from types import SimpleNamespace


def test_preflight_cached_refutation_requires_codeql_receipt(tmp_path, monkeypatch):
    from packages.llm_analysis.agent import AutonomousSecurityAgentV2
    from packages.llm_analysis import dataflow_validation as dv

    agent = AutonomousSecurityAgentV2(
        repo_path=tmp_path / "repo", out_dir=tmp_path / "out", prep_only=True,
    )
    agent._codeql_dbs = {}
    invalid = [
        {"verdict": "refuted"},
        {"verdict": "refuted", "method": "codeql-iris-llm", "tier": "template"},
        {"verdict": "refuted", "method": "codeql-iris", "tier": "retry"},
        {"verdict": "refuted", "method": "structural-treesitter"},
        {"verdict": "refuted", "method": "codeql-iris", "tier": []},
        {"verdict": "refuted", "method": "codeql-iris", "evidence": [
            {"tool": "smt", "rule": "path-feasibility:refuted"},
        ]},
    ]
    for receipt in invalid:
        analysis = {"dataflow_validation": copy.deepcopy(receipt)}
        vuln = SimpleNamespace(analysis=analysis, finding={})
        assert agent._tier1_pre_flight(vuln) == "no_check", receipt
        assert analysis["dataflow_validation"] == receipt

    for receipt in (
        {"verdict": "refuted", "tier": "iris_tier1"},
        {"verdict": "refuted", "method": "codeql-iris"},
        {"verdict": "confirmed"}, {"verdict": "inconclusive"},
    ):
        vuln = SimpleNamespace(analysis={"dataflow_validation": receipt}, finding={})
        assert agent._tier1_pre_flight(vuln) == receipt["verdict"]

    calls = []
    monkeypatch.setattr(dv, "tier1_check_finding", lambda *a, **kw: calls.append(a) or "confirmed")
    agent._codeql_dbs = {"python": tmp_path / "owned-db"}
    vuln = SimpleNamespace(analysis={"dataflow_validation": invalid[1]}, finding={})
    assert agent._tier1_pre_flight(vuln) == "confirmed"
    assert len(calls) == 1

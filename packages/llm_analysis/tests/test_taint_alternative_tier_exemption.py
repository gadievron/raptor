"""Positive approximation evidence on retained sibling paths matters."""
import copy

from core.config import RaptorConfig
from packages.llm_analysis import dataflow_validation as dv


def test_sub_static_alternative_prevents_unrepresentative_codeql_check(monkeypatch):
    static = {"source": {"properties": {"tier": "resolved_static"}},
              "steps": [], "sink": {"properties": {"tier": "resolved_static"}}}
    finding = {"tool": "taint-crossfile", "language": "python", "cwe_id": "CWE-78",
               "metadata": {"path_tier": "resolved_static"},
               "dataflow_path": copy.deepcopy(static)}
    assert dv._taint_sub_static_exemption(finding) is False
    alternative = copy.deepcopy(static)
    alternative["source"]["properties"]["tier"] = "heuristic_dynamic"
    finding["dataflow_path"]["alternative_paths"] = [alternative]
    assert dv._taint_sub_static_exemption(finding) is True

    def unexpected_discovery(*args, **kwargs):
        raise AssertionError("sub-static sibling must abstain before discovery")

    monkeypatch.setattr(dv, "discover_prebuilt_query", unexpected_discovery)
    monkeypatch.setattr(RaptorConfig, "IRIS_TIER1_ENABLED", True)
    assert dv.tier1_check_finding(finding, {}) == "no_check"

    alternative["source"]["properties"] = {
        "tier": "resolved_static", "tags": ["assumed_propagation"],
    }
    assert dv._taint_sub_static_exemption(finding) is True
    alternative["source"]["properties"] = {"tier": None}
    assert dv._taint_sub_static_exemption(finding) is False
    finding["tool"] = "codeql"
    alternative["source"]["properties"] = {"tier": "heuristic_dynamic"}
    assert dv._taint_sub_static_exemption(finding) is False

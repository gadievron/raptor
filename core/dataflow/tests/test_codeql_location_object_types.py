"""Malformed nested objects use the CodeQL adapter refusal contract."""

from copy import deepcopy

import pytest

from core.dataflow.adapters.codeql import from_sarif_result
from core.dataflow.cvefix_corpus_generator import _findings_from_sarif


def test_codeql_nested_objects_refuse_and_keep_later_result(caplog):
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": line},
        }}}

    valid = {"ruleId": "fixture", "codeFlows": [{"threadFlows": [
        {"locations": [location(1), location(2)]},
    ]}]}
    for field in ("location", "physicalLocation", "region", "artifactLocation", "snippet", "message", "result_message"):
        for scalar in (False, 0, "bad", []):
            bad = deepcopy(valid)
            wrapper = bad["codeFlows"][0]["threadFlows"][0]["locations"][0]
            node = wrapper["location"]
            physical = node["physicalLocation"]
            if field == "location":
                wrapper[field] = scalar
            elif field == "physicalLocation":
                node[field] = scalar
            elif field in ("region", "artifactLocation"):
                physical[field] = scalar
            elif field == "snippet":
                physical["region"][field] = scalar
            elif field == "message":
                node[field] = scalar
            else:
                bad["message"] = scalar
            with pytest.raises(ValueError):
                from_sarif_result(bad)
            caplog.clear()
            findings = _findings_from_sarif(
                {"runs": [{"results": [bad, valid]}]}, id_prefix="fixture")
            assert len(findings) == 1
            assert "skipping malformed SARIF result fixture__000" in caplog.text
    nullable = deepcopy(valid)
    nullable["message"] = None
    for wrapper in nullable["codeFlows"][0]["threadFlows"][0]["locations"]:
        wrapper["location"]["message"] = None
        wrapper["location"]["physicalLocation"]["region"]["snippet"] = None
    finding = from_sarif_result(nullable)
    assert finding is not None and finding.source.snippet == ""
    assert finding.message == "(no message)"

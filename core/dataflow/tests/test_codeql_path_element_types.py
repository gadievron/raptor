"""Malformed path-array elements use the adapter refusal contract."""

from copy import deepcopy

import pytest

from core.dataflow.adapters.codeql import from_sarif_result
from core.dataflow.cvefix_corpus_generator import _findings_from_sarif


def test_codeql_path_elements_refuse_without_erasing_sibling_result(caplog):
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": line},
        }}}

    valid = {"ruleId": "fixture", "codeFlows": [{"threadFlows": [
        {"locations": [location(1), location(2)]},
    ]}]}
    for field in ("codeFlows", "threadFlows", "locations"):
        for bad_element in (None, False, 1, "bad", []):
            bad = deepcopy(valid)
            parent = bad if field == "codeFlows" else bad["codeFlows"][0]
            if field == "locations":
                parent = parent["threadFlows"][0]
            parent[field][0] = bad_element
            with pytest.raises(ValueError):
                from_sarif_result(bad)
            caplog.clear()
            findings = _findings_from_sarif(
                {"runs": [{"results": [bad, valid]}]}, id_prefix="fixture")
            assert "skipping malformed SARIF result fixture__000" in caplog.text
            assert len(findings) == 1
            assert findings[0].source.line == 1 and findings[0].sink.line == 2

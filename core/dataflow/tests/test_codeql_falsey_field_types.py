"""Falsey malformed scalar fields must not acquire valid defaults."""

from copy import deepcopy

import pytest

from core.dataflow.adapters.codeql import from_sarif_result


def test_codeql_falsey_scalar_types_refuse():
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": line},
        }}}

    valid = {"ruleId": "fixture", "codeFlows": [{"threadFlows": [
        {"locations": [location(1), location(2)]},
    ]}]}
    for field in ("column", "snippet", "label", "ruleId", "message"):
        for scalar in (False, 0.0, [], {}):
            bad = deepcopy(valid)
            node = bad["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
            region = node["physicalLocation"]["region"]
            if field == "column":
                region["startColumn"] = scalar
            elif field == "snippet":
                region["snippet"] = {"text": scalar}
            elif field == "label":
                node["message"] = {"text": scalar}
            elif field == "ruleId":
                bad[field] = scalar
            else:
                bad[field] = {"text": scalar}
            with pytest.raises(ValueError):
                from_sarif_result(bad)
    for column in (None, 0, 1):
        admitted = deepcopy(valid)
        region = admitted["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]["physicalLocation"]["region"]
        region["startColumn"] = column
        region["snippet"] = {"text": ""}
        admitted["ruleId"] = ""
        admitted["message"] = {"text": None}
        finding = from_sarif_result(admitted)
        assert finding is not None
        assert finding.source.column == (0 if column is None else column)
        assert finding.source.snippet == "" and finding.rule_id == "unknown"
        assert finding.message == "(no message)"

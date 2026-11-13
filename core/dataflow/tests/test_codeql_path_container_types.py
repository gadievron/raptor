"""Invalid scalar path containers are not an absent dataflow path."""

from copy import deepcopy

import pytest

from core.dataflow.adapters.codeql import from_sarif_result
from core.dataflow.finding_diff import diff_sarif_data


def test_codeql_refuses_scalar_path_containers():
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"}, "region": {"startLine": line},
        }}}

    valid = {"ruleId": "fixture", "codeFlows": [{"threadFlows": [
        {"locations": [location(1), location(2)]},
    ]}]}
    def document(result):
        return {"runs": [{"results": [result]}]}

    for field in ("codeFlows", "threadFlows", "locations"):
        for scalar in (False, 0, "", {}, "invalid"):
            bad = deepcopy(valid)
            container = bad if field == "codeFlows" else bad["codeFlows"][0]
            if field == "locations":
                container = container["threadFlows"][0]
            container[field] = scalar
            with pytest.raises(ValueError, match=field):
                from_sarif_result(bad)
            with pytest.raises(ValueError, match=field):
                diff_sarif_data(document(valid), document(bad))
    assert from_sarif_result(valid) is not None
    for empty in (None, [], ()):
        assert from_sarif_result({"codeFlows": empty}) is None
        assert from_sarif_result({"codeFlows": [{"threadFlows": empty}]}) is None
        assert from_sarif_result({"codeFlows": [{"threadFlows": [{"locations": empty}]}]}) is None

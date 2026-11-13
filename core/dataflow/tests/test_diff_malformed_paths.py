"""A malformed augmented path is not a successful suppression."""

from copy import deepcopy

import pytest

from core.dataflow.finding_diff import diff_sarif_data


def _document():
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"},
            "region": {"startLine": line},
        }}}
    return {"runs": [{"results": [{"ruleId": "fixture", "message": {"text": "fixture"},
        "codeFlows": [{"threadFlows": [{"locations": [location(1), location(2)]}]}],
    }]}]}


def test_malformed_path_cannot_be_counted_as_suppression():
    valid = _document()
    assert diff_sarif_data(valid, valid).suppression_rate == 0
    assert diff_sarif_data(valid, {"runs": []}).suppression_rate == 1
    malformed = deepcopy(valid)
    result = malformed["runs"][0]["results"][0]
    source = result["codeFlows"][0]["threadFlows"][0]["locations"][0]
    source["location"]["physicalLocation"]["region"]["startLine"] = 0
    for baseline, augmented in ((valid, malformed), (malformed, valid)):
        with pytest.raises(ValueError, match="line"):
            diff_sarif_data(baseline, augmented)

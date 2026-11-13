"""Malformed SARIF containers cannot impersonate an empty comparison."""

import pytest

from core.dataflow.finding_diff import diff_sarif_data


def test_diff_refuses_malformed_containers():
    empty = {"runs": []}
    malformed = [None, [], {"runs": None}, {"runs": False}, {"runs": 0},
                 {"runs": {}}, {"runs": ""}, {"runs": [None]},
                 {"runs": [{"results": False}]}, {"runs": [{"results": {}}]},
                 {"runs": [{"results": ""}]}, {"runs": [{"results": [None]}]}]
    for document in malformed:
        with pytest.raises(ValueError):
            diff_sarif_data(empty, document)
        with pytest.raises(ValueError):
            diff_sarif_data(document, empty)
    for document in [{}, empty, {"runs": [{}]}, {"runs": [{"results": []}]},
                     {"runs": ({"results": ()},)}]:
        result = diff_sarif_data(document, document)
        assert result.baseline_count == result.augmented_count == 0

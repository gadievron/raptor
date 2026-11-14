"""Native SARIF column defaults preserve strict Step coordinates."""

import pytest

from core.dataflow.adapters.taint_native import from_sarif_result


def _result(column):
    def location(line):
        return {"location": {"physicalLocation": {
            "artifactLocation": {"uri": "fixture.py"},
            "region": {"startLine": line, "startColumn": column},
        }}}

    return {"ruleId": "fixture", "message": {"text": "fixture"},
            "codeFlows": [{"threadFlows": [{
                "locations": [location(1), location(3)],
            }]}]}


@pytest.mark.parametrize("column", [False, True, 0.0, "", [], {}, -1, "1"])
def test_malformed_columns_are_not_normalized_to_zero(column):
    with pytest.raises(ValueError, match="Step.column"):
        from_sarif_result(_result(column))


@pytest.mark.parametrize("column", [None, 0, 1, 7])
def test_null_and_integer_columns_retain_existing_meaning(column):
    finding = from_sarif_result(_result(column))
    assert finding is not None
    assert finding.source.column == (0 if column is None else column)
    assert finding.sink.column == (0 if column is None else column)

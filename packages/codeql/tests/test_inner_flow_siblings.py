"""Malformed inner flow locations must not erase valid sibling paths."""

import logging

import pytest

from packages.codeql.dataflow_validator import DataflowValidator


def _location(file):
    return {"location": {"physicalLocation": {
        "artifactLocation": {"uri": file}, "region": {"startLine": 1},
    }}}


def _thread(name):
    return {"locations": [_location(name + "-source.py"), _location(name + "-sink.py")]}


@pytest.mark.parametrize("bad,before", [
    ({"locations": None}, True),
    ({"locations": None}, False),
    ({"locations": [None, None]}, True),
], ids=["null-before", "null-after", "bad-location"])
def test_valid_siblings_survive_inner_location_failure(bad, before, caplog):
    validator = DataflowValidator.__new__(DataflowValidator)
    validator.logger = logging.getLogger("owned.inner-flow-test")
    threads = [_thread("first"), _thread("second")]
    threads.insert(0 if before else 2, bad)
    with caplog.at_level(logging.WARNING, logger=validator.logger.name):
        path = validator.extract_dataflow_from_sarif({
            "ruleId": "owned", "message": {"text": "owned"},
            "codeFlows": [{"threadFlows": threads}],
        })
    assert path is not None
    assert path.source.file_path == "first-source.py"
    assert [other.source.file_path for other in path.alternatives] == ["second-source.py"]
    assert "Skipped malformed SARIF flow containers" in caplog.text


def test_all_malformed_inner_paths_remain_unavailable():
    validator = DataflowValidator.__new__(DataflowValidator)
    validator.logger = logging.getLogger("owned.inner-flow-test")
    assert validator.extract_dataflow_from_sarif({
        "codeFlows": [{"threadFlows": [{"locations": None}, {"locations": [None, None]}]}],
    }) is None

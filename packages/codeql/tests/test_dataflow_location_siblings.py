"""Malformed locations in one thread cannot erase valid sibling paths."""
from copy import deepcopy
import logging

from packages.codeql.dataflow_validator import DataflowValidator
from packages.codeql.tests.test_dataflow_validator import _sarif_two_flows


def test_malformed_location_thread_retains_valid_sibling_paths():
    validator = object.__new__(DataflowValidator)
    validator.logger = logging.getLogger("owned-location-siblings")
    malformed = [None, 7, "bad", [None, None],
                 [{"location": None}, {"location": {}}],
                 [{"location": {"physicalLocation": None}}, {"location": {}}]]
    for locations in malformed:
        for position in (0, 1, 2):
            result = _sarif_two_flows()
            result["codeFlows"].insert(position, {"threadFlows": [{"locations": locations}]})
            original = deepcopy(result)
            path = validator.extract_dataflow_from_sarif(result)
            assert path is not None, (locations, position)
            assert path.source.file_path == "a.c"
            assert path.sink.file_path == "a.c"
            assert [p.source.file_path for p in path.alternatives] == ["b.c"]
            assert result == original
    result = _sarif_two_flows()
    sibling = result["codeFlows"].pop()["threadFlows"][0]
    result["codeFlows"][0]["threadFlows"].extend([
        {"locations": [None, None]}, sibling,
    ])
    original = deepcopy(result)
    path = validator.extract_dataflow_from_sarif(result)
    assert path is not None
    assert path.source.file_path == "a.c"
    assert [p.source.file_path for p in path.alternatives] == ["b.c"]
    assert result == original
    assert validator.extract_dataflow_from_sarif(
        {"codeFlows": [{"threadFlows": [{"locations": [None, None]}]}]},
    ) is None

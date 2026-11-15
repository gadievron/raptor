"""Malformed SARIF coordinates remain unknown without replacing the primary path."""

import json
import logging

from packages.codeql import dataflow_validator as module


def _location(label, **region):
    return {"location": {"message": {"text": label}, "physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": region,
    }}}


def _result(region):
    return {"ruleId": "cpp/owned", "message": {"text": "owned"}, "codeFlows": [
        {"threadFlows": [{"locations": [_location("primary", **region),
                                          _location("sink", startLine=2, startColumn=1)]}]},
        {"threadFlows": [{"locations": [_location("sibling", startLine=1, startColumn=1),
                                          _location("sibling-sink", startLine=2, startColumn=1)]}]},
    ]}


def test_coordinate_normalisation_retains_primary_and_siblings(tmp_path, caplog):
    (tmp_path / "owned.c").write_text("owned_first_line\nowned_second_line\n")
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("owned-dataflow-coordinates")
    for field in ("startLine", "startColumn"):
        for value in (True, False, "1", 1.5, float("nan"), float("inf"), None, [], {}):
            region = {"startLine": 1, "startColumn": 1, field: value}
            result = _result(region)
            before = json.dumps(result, sort_keys=True)
            caplog.clear()
            path = validator.extract_dataflow_from_sarif(result)
            assert path is not None
            assert path.source.label == "primary"
            assert [p.source.label for p in path.alternatives] == ["sibling"]
            context = validator.read_source_context("owned.c", path.source.line, 0, tmp_path)
            assert (path.source.line, path.source.column) == (
                (0, 1) if field == "startLine" else (1, 0)), context
            assert type(path.source.line) is int
            assert type(path.source.column) is int
            assert (">>>" in context) is (field == "startColumn")
            assert any("SARIF flow coordinates" in record.message for record in caplog.records)
            assert json.dumps(result, sort_keys=True) == before
    for region, expected in (({}, (0, 0)),
                             ({"startLine": 1, "startColumn": 2}, (1, 2)),
                             ({"startLine": 1.0, "startColumn": 2.0}, (1, 2)),
                             ({"startLine": 0, "startColumn": -3}, (0, -3))):
        caplog.clear()
        path = validator.extract_dataflow_from_sarif(_result(region))
        assert path is not None
        assert (path.source.line, path.source.column) == expected
        assert type(path.source.line) is type(path.source.column) is int
        assert not caplog.records

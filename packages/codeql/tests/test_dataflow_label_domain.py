"""Malformed optional labels do not replace a structurally usable primary path."""

import json
import logging

from packages.codeql import dataflow_validator as module


def _location(label, line):
    return {"location": {"message": {"text": label}, "physicalLocation": {
        "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": line},
    }}}


def _result(message):
    middle = _location("validation check", 2)
    middle["location"]["message"] = message
    return {"ruleId": "cpp/owned", "codeFlows": [
        {"threadFlows": [{"locations": [_location("primary", 1), middle,
                                          _location("sink", 3)]}]},
        {"threadFlows": [{"locations": [_location("sibling", 1),
                                          _location("sibling-sink", 3)]}]},
    ]}


def test_malformed_optional_label_retains_primary_path(caplog):
    validator = module.DataflowValidator.__new__(module.DataflowValidator)
    validator.logger = logging.getLogger("owned-dataflow-labels")
    for message in ({"text": ["validation check"]}, {"text": None}, {"text": 1},
                    {"text": True}, {"text": {}}, ["validation check"], "validation check", 7):
        result = _result(message)
        before = json.dumps(result, sort_keys=True)
        caplog.clear()
        path = validator.extract_dataflow_from_sarif(result)
        assert path is not None
        assert path.source.label == "primary"
        assert [p.source.label for p in path.alternatives] == ["sibling"]
        assert path.intermediate_steps[0].label == ""
        assert path.sanitizers == []
        assert any("SARIF flow label" in record.message for record in caplog.records)
        assert json.dumps(result, sort_keys=True) == before
    for message, expected in ((None, ""), ({}, ""), ({"text": ""}, ""),
                              ({"text": "validation check"}, "validation check")):
        caplog.clear()
        path = validator.extract_dataflow_from_sarif(_result(message))
        assert path is not None
        assert path.source.label == "primary"
        assert path.intermediate_steps[0].label == expected
        assert path.sanitizers == ([expected] if expected else [])
        assert not caplog.records

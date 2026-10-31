"""Result descriptors must stay within the referenced SARIF component."""

import pytest

from core.sarif.parser import get_result_rule


@pytest.fixture
def run():
    return {"tool": {
        "driver": {"name": "driver", "rules": [{"id": "same", "name": "driver-rule"}]},
        "extensions": [{"name": "extension", "guid": "extension-guid", "rules": [
            {"id": "same", "guid": "rule-guid", "name": "extension-rule"},
        ]}],
    }}


@pytest.mark.parametrize("result,expected", [
    ({"ruleId": "same"}, "driver-rule"),
    ({"ruleIndex": 0}, "driver-rule"),
    ({"ruleId": "same", "ruleIndex": -1}, "driver-rule"),
    ({"rule": {"index": 0, "toolComponent": {"index": 0}}}, "extension-rule"),
    ({"rule": {"id": "same", "toolComponent": {"name": "extension"}}}, "extension-rule"),
    ({"rule": {"guid": "rule-guid", "toolComponent": {"guid": "extension-guid"}}}, "extension-rule"),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": 5}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": True}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": -2}}}, None),
    ({"ruleId": "same", "rule": {"toolComponent": {"index": 0, "name": "wrong"}}}, None),
    ({"ruleId": "same", "rule": {"id": "different"}}, None),
    ({"ruleIndex": True}, None),
    ({"ruleIndex": -1}, None),
])
def test_component_resolution(run, result, expected):
    assert get_result_rule(run, result).get("name") == expected


def test_ambiguous_extension_reference_cannot_borrow_driver(run):
    run["tool"]["extensions"].append(run["tool"]["extensions"][0])
    result = {"ruleId": "same", "rule": {"toolComponent": {"name": "extension"}}}
    assert get_result_rule(run, result) == {}


def test_ambiguous_driver_cannot_fall_through_to_extension(run):
    run["tool"]["driver"]["rules"].append({"id": "same", "name": "duplicate"})
    assert get_result_rule(run, {"ruleId": "same"}) == {}

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


def test_explicit_index_disambiguates_duplicate_rule_ids(run):
    rules = run['tool']['driver']['rules']
    rules.append({'id': 'same', 'name': 'second-rule', 'defaultConfiguration': {'level': 'error'}})
    assert get_result_rule(run, {'ruleId': 'same', 'ruleIndex': 1}) is rules[1]


@pytest.mark.parametrize('result', [
    {'ruleId': 'same', 'ruleIndex': 1},
    {'ruleId': 'same', 'ruleIndex': True},
    {'ruleId': 'same', 'ruleIndex': -2},
    {'ruleId': 'same', 'ruleIndex': '0'},
    {'ruleId': 'same', 'ruleIndex': 0, 'rule': {'index': 1}},
    {'ruleId': 'same', 'ruleIndex': True, 'rule': {'index': 0}},
])
def test_invalid_or_conflicting_indexes_cannot_borrow_id_metadata(run, result):
    assert get_result_rule(run, result) == {}


@pytest.mark.parametrize('component', ['driver', 'extension'])
@pytest.mark.parametrize('identifier,expected', [
    ('same', True), ('same/subrule', True), ('same/subrule/deeper', False),
    ('same/', False), ('other', False),
])
def test_indexed_reference_validates_readable_rule_id(run, component, identifier, expected):
    reference = {'id': identifier, 'index': 0}
    if component == 'extension':
        reference['toolComponent'] = {'index': 0}
    result = {'rule': reference}
    assert bool(get_result_rule(run, result)) is expected


@pytest.mark.parametrize('guid,expected', [('rule-guid', True), ('different-guid', False)])
def test_index_and_guid_must_resolve_to_same_descriptor(run, guid, expected):
    reference = {'guid': guid, 'index': 0, 'toolComponent': {'index': 0}}
    assert bool(get_result_rule(run, {'rule': reference})) is expected


def test_indexed_reference_does_not_fall_through_to_extension(run):
    run['tool']['driver']['rules'] = [{'id': 'other'}]
    assert get_result_rule(run, {'ruleId': 'same', 'ruleIndex': 0}) == {}
    assert get_result_rule(run, {'ruleId': 'same'})['name'] == 'extension-rule'

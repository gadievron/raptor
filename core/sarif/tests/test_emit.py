"""Tests for ``core.sarif.emit`` — the shared minimal-emitter skeleton.

These artifacts are written with ``save_json(sort_keys=False)``, so
dict insertion order is the on-disk byte order. The order assertions
here compare serialized JSON (not dict equality, which ignores order)
because member order IS the contract the migrated emitters' golden
tests pin.
"""

from __future__ import annotations

import json

import pytest

from core.sarif import emit


def _dumps(obj) -> str:
    return json.dumps(obj, sort_keys=False)


class TestMinimalRule:
    def test_minimal_members_and_order(self):
        rule = emit.minimal_rule("r1")
        assert _dumps(rule) == _dumps({
            "id": "r1",
            "name": "r1",
            "shortDescription": {"text": "r1"},
            "defaultConfiguration": {"level": "warning"},
        })

    def test_all_optional_members_and_order(self):
        rule = emit.minimal_rule(
            "r1",
            full_description="long text",
            level="error",
            help_uri="https://example.invalid/help",
            properties={"cwe": "CWE-79"},
        )
        assert list(rule) == [
            "id", "name", "shortDescription", "fullDescription",
            "defaultConfiguration", "helpUri", "properties",
        ]
        assert rule["fullDescription"] == {"text": "long text"}
        assert rule["defaultConfiguration"] == {"level": "error"}

    def test_none_optionals_omitted_not_empty(self):
        rule = emit.minimal_rule("r1", properties=None)
        assert "properties" not in rule
        assert "fullDescription" not in rule
        assert "helpUri" not in rule


class TestRuleIndex:
    def test_dedup_first_writer_wins(self):
        idx = emit.RuleIndex()
        idx.add(emit.minimal_rule("r1", full_description="first"))
        idx.add(emit.minimal_rule("r1", full_description="second"))
        assert len(idx.rules()) == 1
        assert idx.rules()[0]["fullDescription"] == {"text": "first"}

    def test_contains_and_insertion_order(self):
        idx = emit.RuleIndex()
        assert "r1" not in idx
        idx.add(emit.minimal_rule("r2"))
        idx.add(emit.minimal_rule("r1"))
        assert "r1" in idx and "r2" in idx
        assert [r["id"] for r in idx.rules()] == ["r2", "r1"]


class TestResult:
    def test_order_properties_after_locations(self):
        loc = emit.location("a.c", {"startLine": 3})
        res = emit.result("r1", "msg", [loc], properties={"p": 1})
        assert list(res) == [
            "ruleId", "level", "message", "locations", "properties",
        ]
        assert res["message"] == {"text": "msg"}
        assert res["level"] == "warning"

    def test_order_properties_before_locations(self):
        loc = emit.location("a.c", {"startLine": 3})
        res = emit.result(
            "r1", "msg", [loc],
            properties={"p": 1}, properties_before_locations=True,
        )
        assert list(res) == [
            "ruleId", "level", "message", "properties", "locations",
        ]

    def test_no_properties_member_when_none(self):
        res = emit.result("r1", "msg", [])
        assert "properties" not in res

    def test_caller_appended_members_land_last(self):
        res = emit.result("r1", "msg", [])
        res["codeFlows"] = []
        res["fingerprints"] = {"matchBasedId/v1": "abc"}
        assert list(res)[-2:] == ["codeFlows", "fingerprints"]


class TestLocation:
    def test_shape(self):
        loc = emit.location("src/a.c", {"startLine": 1, "endLine": 2})
        assert loc == {
            "physicalLocation": {
                "artifactLocation": {"uri": "src/a.c"},
                "region": {"startLine": 1, "endLine": 2},
            },
        }


class TestRun:
    def test_driver_order_full(self):
        r = emit.run(
            "toolx", [], [],
            full_name="Tool X", information_uri="https://x.invalid",
        )
        assert list(r["tool"]["driver"]) == [
            "name", "fullName", "informationUri", "rules",
        ]
        assert list(r) == ["tool", "results"]

    def test_driver_order_name_only(self):
        r = emit.run("toolx", [{"id": "r1"}], [{"ruleId": "r1"}])
        assert list(r["tool"]["driver"]) == ["name", "rules"]
        assert r["tool"]["driver"]["rules"] == [{"id": "r1"}]
        assert r["results"] == [{"ruleId": "r1"}]

    def test_caller_appended_invocations_land_after_results(self):
        r = emit.run("toolx", [], [])
        r["invocations"] = [{"executionSuccessful": False}]
        assert list(r) == ["tool", "results", "invocations"]


class TestDocument:
    def test_schema_first_default(self):
        doc = emit.document([], schema_uri=emit.SCHEMA_URI_COMMITTEE)
        assert list(doc) == ["$schema", "version", "runs"]
        assert doc["version"] == "2.1.0"

    def test_version_first(self):
        doc = emit.document(
            [], schema_uri=emit.SCHEMA_URI_SCHEMASTORE, version_first=True,
        )
        assert list(doc) == ["version", "$schema", "runs"]

    def test_schema_uris_are_distinct_and_2_1_0(self):
        uris = {
            emit.SCHEMA_URI_COMMITTEE,
            emit.SCHEMA_URI_SCHEMATA,
            emit.SCHEMA_URI_SCHEMASTORE,
        }
        assert len(uris) == 3
        assert all("2.1.0" in u for u in uris)


@pytest.mark.parametrize('line', [0, -1, True, None, 1.5, float('inf'), float('nan'), '3'],
                         ids=['zero', 'negative', 'boolean', 'missing', 'fraction', 'infinity', 'nan', 'string'])
def test_unknown_start_does_not_acquire_a_region_from_optional_coordinates(line):
    assert emit.source_region(line, end_line=9, column=2, end_column=4,
                              repeat_end_line=True) == {}


@pytest.mark.parametrize('values,expected', [
    pytest.param({'line': 5}, {'startLine': 5}, id='known-start'),
    pytest.param({'line': 5.0, 'column': 2.0}, {'startLine': 5, 'startColumn': 2}, id='integral-floats'),
    pytest.param({'line': 5, 'repeat_end_line': True}, {'startLine': 5, 'endLine': 5}, id='legacy-end-default'),
    pytest.param({'line': 5, 'end_line': 6, 'column': 9, 'end_column': 2},
                 {'startLine': 5, 'endLine': 6, 'startColumn': 9, 'endColumn': 2}, id='multiline-columns'),
    pytest.param({'line': 5, 'end_line': 4, 'column': 9, 'end_column': 10, 'repeat_end_line': True},
                 {'startLine': 5, 'startColumn': 9}, id='backwards-end-line'),
    pytest.param({'line': 5, 'end_line': 5, 'column': 9, 'end_column': 2},
                 {'startLine': 5, 'endLine': 5, 'startColumn': 9}, id='backwards-same-line-column'),
    pytest.param({'line': 5, 'column': 9, 'end_column': 2},
                 {'startLine': 5, 'startColumn': 9}, id='backwards-implicit-end-column'),
    pytest.param({'line': 5, 'column': True, 'end_column': float('inf')},
                 {'startLine': 5}, id='invalid-columns'),
])
def test_source_region_preserves_only_supported_spans(values, expected):
    actual = emit.source_region(**values)
    assert actual == expected
    json.dumps(actual, allow_nan=False)

"""Reference-free result rows cannot amortise a descriptor index."""

from copy import deepcopy

import pytest

from core.sarif import parser
from packages.semgrep.models import parse_sarif_data


@pytest.mark.parametrize("references", [1, 2])
def test_reference_free_siblings_do_not_trigger_rule_index(monkeypatch, references):
    result = {"ruleId": "owned", "message": {"text": "owned"}, "locations": [{
        "physicalLocation": {"artifactLocation": {"uri": "owned.py"},
                             "region": {"startLine": 1}},
    }]}
    run = {"tool": {"driver": {"name": "Semgrep", "rules": [
        {"id": "owned", "defaultConfiguration": {"level": "error"}},
        *({"id": f"other-{i}"} for i in range(2000)),
    ]}}, "results": [{"unexpected": "before"},
                      *(deepcopy(result) for _ in range(references)),
                      {"unexpected": "after"}]}
    original = parser.ResultRuleResolver
    indexed = []

    def resolver(value):
        indexed.append(len(value["tool"]["driver"]["rules"]))
        return original(value)

    monkeypatch.setattr(parser, "ResultRuleResolver", resolver)
    before = deepcopy(run)
    errors = []
    findings = parse_sarif_data({"runs": [run]}, errors=errors)
    assert len(findings) == references
    assert all((f.rule_id, f.file, f.level) == ("owned", "owned.py", "error") for f in findings)
    assert errors == ["SARIF contains 2 malformed entry/entries"]
    assert run == before
    assert indexed == ([] if references == 1 else [2001])


def test_message_only_sibling_is_recovered_without_an_index(monkeypatch):
    def forbidden_index(run):
        pytest.fail("one rule reference must use the direct lookup")

    monkeypatch.setattr(parser, "ResultRuleResolver", forbidden_index)
    errors = []
    findings = parse_sarif_data({"runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [{"id": "owned"}]}},
        "results": [{"ruleId": "owned", "message": {"text": "referenced"}},
                    {"message": {"text": "message-only"}}],
    }]}, errors=errors)
    assert [(finding.rule_id, finding.message) for finding in findings] == [
        ("owned", "referenced"), ("", "message-only"),
    ]
    assert not errors

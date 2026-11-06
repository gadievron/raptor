"""Selection reuses run-owned rule lookup without changing reference semantics."""

import copy
import json

import pytest

from core.sarif import parser
from packages.codeql import finding_selection as selection
from packages.codeql.tests.test_finding_selection import _batch_selection_reference, _selection_signature


def located(reference, line):
    return {**reference, "message": {"text": f"candidate {line}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app.c"},
            "region": {"startLine": line}}}]}


def test_id_only_runs_do_not_hash_references_or_rescan_the_rule_table(tmp_path, monkeypatch):
    rules = [{"id": f"rule-{i}"} for i in range(100)]
    results = [located({"ruleId": rule["id"]}, i + 1) for i, rule in enumerate(rules)]
    run = {"tool": {"driver": {"name": "CodeQL", "rules": rules}}, "results": results}
    monkeypatch.setattr(selection, "load_sarif", lambda path: {"runs": [run]})
    built = []
    resolver = selection.ResultRuleResolver
    content_key = selection._content_key

    def build(actual_run):
        built.append(actual_run is run)
        return resolver(actual_run)

    def no_table_scan(*args):
        pytest.fail("an ID-only result rescanned the rule table")

    def no_reference_hash(value, **kwargs):
        assert not value or not set(value).issubset({"ruleId", "ruleIndex", "rule"})
        return content_key(value, **kwargs)

    monkeypatch.setattr(selection, "ResultRuleResolver", build)
    monkeypatch.setattr(selection, "get_result_rule", no_table_scan)
    monkeypatch.setattr(parser, "get_result_rule", no_table_scan)
    monkeypatch.setattr(selection, "_content_key", no_reference_hash)
    selected, count, duplicates = selection.select_findings_for_analysis([tmp_path / "unused.sarif"], 3)
    assert (len(selected), count, duplicates) == (3, 100, 0)
    assert built == [True]


@pytest.mark.parametrize("kind", ["empty", "single-id", "indexed"])
def test_runs_without_index_reuse_do_not_build_the_id_index(tmp_path, monkeypatch, kind):
    references = [] if kind == "empty" else [{"ruleId": "shared"}]
    if kind == "indexed":
        references = [{"ruleId": "shared", "ruleIndex": 0} for _ in range(5)]
    run = {"tool": {"driver": {"name": "CodeQL", "rules": [{"id": "shared"}]}},
           "results": [located(reference, i + 1) for i, reference in enumerate(references)]}
    monkeypatch.setattr(selection, "load_sarif", lambda path: {"runs": [run]})

    def unexpected(run):
        pytest.fail("single/indexed/empty run built an unnecessary ID index")

    monkeypatch.setattr(selection, "ResultRuleResolver", unexpected)
    selected, count, duplicates = selection.select_findings_for_analysis([tmp_path / "unused.sarif"], 10)
    assert (len(selected), count, duplicates) == (len(references), len(references), 0)


@pytest.mark.parametrize("cap", [0, 1, 5, 100])
@pytest.mark.parametrize("reverse", [False, True])
def test_qualified_and_malformed_references_match_the_validated_batch_oracle(tmp_path, cap, reverse):
    references = [
        {"ruleId": "shared"}, {"ruleIndex": 0}, {"ruleId": "shared", "ruleIndex": 0},
        {"ruleId": "shared", "ruleIndex": True}, {"ruleId": "shared", "ruleIndex": False},
        {"ruleId": "shared", "ruleIndex": 0.0},
        {"ruleId": "shared", "ruleIndex": None}, {"ruleId": "shared", "ruleIndex": "0"},
        {"ruleId": "shared", "ruleIndex": -1}, {"ruleId": "shared", "ruleIndex": -2},
        {"rule": {"id": "shared", "toolComponent": {"index": 0}}},
        {"rule": {"id": "shared", "toolComponent": {}}},
        {"rule": {"id": "shared", "toolComponent": {"index": False}}},
        {"ruleId": "wrong", "rule": {"id": "shared", "index": 0}},
        {"ruleIndex": 1, "rule": {"id": "shared", "index": 0}},
        {"rule": {"id": "shared", "toolComponent": None}},
    ]
    if reverse:
        references.reverse()
    runs = []
    for default in ("note", "error"):
        run = {"tool": {"driver": {"name": "CodeQL", "rules": [
            {"id": "shared", "defaultConfiguration": {"level": default}}]},
            "extensions": [{"name": "extension", "rules": [
            {"id": "shared", "defaultConfiguration": {"level": "warning"}}]}]},
            "results": [located(reference, i + 1) for i, reference in enumerate(references)]}
        run["results"].append(copy.deepcopy(run["results"][0]))
        runs.append(run)
    path = tmp_path / "references.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": runs}))
    expected, expected_count, expected_duplicates = _batch_selection_reference([path], cap)
    selected, count, duplicates = selection.select_findings_for_analysis([path], cap)
    actual = [(candidate.sarif_file, candidate.run, candidate.result) for candidate in selected]
    assert (count, duplicates) == (expected_count, expected_duplicates)
    assert _selection_signature(actual) == _selection_signature(expected)

"""Descriptor indexing counts references without changing candidate retention."""

import json

import pytest

from packages.codeql import finding_selection as selection


@pytest.mark.parametrize("references,cap", [(1, 8), (2, 8), (1, 1)],
                         ids=["one-reference", "two-references", "limited"])
def test_reference_free_candidates_keep_counts_and_ranking(tmp_path, monkeypatch, references, cap):
    results = [{"ruleId": "owned", "level": "error", "message": {"text": f"owned-{i}"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "owned.c"}, "region": {"startLine": i + 1},
                }}]} for i in range(references)]
    run = {"tool": {"driver": {"name": "CodeQL", "rules": [
        {"id": "owned"}, *({"id": f"other-{i}"} for i in range(2000)),
    ]}}, "results": [{"unexpected": "before"}, *results, {"unexpected": "after"}]}
    path = tmp_path / "owned.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}))
    original = selection.ResultRuleResolver
    indexed = []

    def resolver(value):
        indexed.append(len(value["tool"]["driver"]["rules"]))
        return original(value)

    monkeypatch.setattr(selection, "ResultRuleResolver", resolver)
    selected, count, duplicates = selection.select_findings_for_analysis([path], cap)
    assert (len(selected), count, duplicates) == (min(cap, references + 2), references + 2, 0)
    assert selected[0].result["ruleId"] == "owned"
    if cap > count:
        assert {candidate.result["unexpected"] for candidate in selected
                if "unexpected" in candidate.result} == {"before", "after"}
    assert all(len(candidate.run["results"]) == len(selected) for candidate in selected)
    assert indexed == ([] if references == 1 else [2001])
    assert json.loads(path.read_text())["runs"][0] == run

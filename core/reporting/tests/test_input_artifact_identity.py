"""Input lineage cannot choose between distinct same-named captured artifacts."""
from io import StringIO
import json

import pytest

from core.reporting.adapters import context_from_sarif
from core.reporting.lifecycle import find_input_snapshot
from core.reporting.service import complete_reporting


def test_same_named_equivalent_inputs_do_not_overwrite_occurrence_binding(tmp_path):
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "captured"}},
            "results": [{"ruleId": "captured/rule", "message": {"text": "captured claim"}}]}]}
    source = tmp_path / "result.sarif"
    nested = tmp_path / "nested" / "result.sarif"
    nested.parent.mkdir()
    source.write_text(json.dumps(data))
    nested.write_text(json.dumps(data, indent=2))
    context = context_from_sarif([source, nested], run_id="captured")
    assert len(context.findings) == len(context.artifacts) == 2
    assert context.artifacts[0]["digest"] != context.artifacts[1]["digest"]
    assert context.artifacts[0]["canonical_digest"] == context.artifacts[1]["canonical_digest"]
    completed = complete_reporting(context, tmp_path, stream=StringIO())
    assert not completed.errors and completed.publication.committed
    binding = find_input_snapshot(source, data)
    assert binding is None


@pytest.mark.parametrize("reverse", [False, True])
def test_ambiguous_binding_refusal_does_not_discard_imported_findings(tmp_path, reverse):
    from packages.exploitability_validation.orchestrator import convert_sarif_data
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "captured"}},
            "results": [{"ruleId": "captured/rule", "message": {"text": "captured claim"},
                         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"},
                                        "region": {"startLine": 2}}}]}]}]}
    first, second = tmp_path / "result.sarif", tmp_path / "nested" / "result.sarif"
    second.parent.mkdir()
    first.write_text(json.dumps(data))
    second.write_text(json.dumps(data, indent=2))
    paths = [second, first] if reverse else [first, second]
    context = context_from_sarif(paths, run_id="captured")
    assert len(context.findings) == 2
    complete_reporting(context, tmp_path, stream=StringIO())
    binding = find_input_snapshot(first, data)
    assert binding is None
    imported = convert_sarif_data(data, "src", source_binding=binding)
    assert len(imported["findings"]) == 1
    assert "_reporting_source" not in imported["findings"][0]


@pytest.mark.parametrize("other", ["absent", "different-content", "identical-bytes"])
def test_unique_matching_artifact_keeps_occurrence_binding(tmp_path, other):
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "captured"}},
            "results": [{"ruleId": "captured/rule", "message": {"text": "captured claim"}}]}]}
    first, second = tmp_path / "result.sarif", tmp_path / "nested" / "result.sarif"
    first.write_text(json.dumps(data))
    paths = [first]
    if other != "absent":
        second.parent.mkdir()
        second.write_text(json.dumps(data) if other == "identical-bytes" else json.dumps({**data, "note": "different"}))
        paths.append(second)
    context = context_from_sarif(paths, run_id="captured")
    completed = complete_reporting(context, tmp_path, stream=StringIO())
    assert not completed.errors
    binding = find_input_snapshot(first, data)
    assert binding["positions"][(0, 0)]["occurrence_ref"] == context.findings[0]["occurrence_ref"]
    assert find_input_snapshot(first, {**data, "note": "altered"}) is None

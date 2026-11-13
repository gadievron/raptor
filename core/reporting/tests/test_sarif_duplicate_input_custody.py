"""Byte deduplication never removes valid source-file custody."""
import hashlib
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.lifecycle import find_input_snapshot
from core.reporting.writer import load_committed_report


def _sources(directory, duplicate_name="duplicate.json"):
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
            "results": [{"ruleId": "saved-rule", "message": {"text": "owned saved observation"}}]}]}
    raw = json.dumps(data).encode()
    first, duplicate = directory / "first.json", directory / duplicate_name
    first.write_bytes(raw)
    duplicate.write_bytes(raw)
    return first, duplicate, data, raw


def test_json_export_cannot_replace_deduplicated_valid_source(tmp_path):
    first, duplicate, _, raw = _sources(tmp_path)
    assert main(["sarif", str(first), str(duplicate), "--out", str(tmp_path / "output"),
                 "--report-format", "json", "--report-output", str(duplicate)]) == 1
    assert first.read_bytes() == duplicate.read_bytes() == raw
    assert not (tmp_path / "output/reporting-manifest.json").exists()


def test_disabled_summary_cannot_replace_deduplicated_valid_source(tmp_path):
    first, duplicate, _, raw = _sources(tmp_path, duplicate_name="summary.json")
    assert main(["sarif", str(first), str(duplicate), "--out", str(tmp_path), "--no-report"]) == 1
    assert first.read_bytes() == duplicate.read_bytes() == raw
    assert not (tmp_path / "summary.md").exists()
    assert not (tmp_path / "reporting-manifest.json").exists()


@pytest.mark.parametrize("reverse", [False, True], ids=["first-order", "reverse-order"])
def test_saved_duplicate_paths_keep_one_finding_population_and_binding(tmp_path, reverse):
    first, duplicate, data, raw = _sources(tmp_path)
    paths = [duplicate, first] if reverse else [first, duplicate]
    assert main(["sarif", *(str(path) for path in paths), "--out", str(tmp_path),
                 "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, manifest = load_committed_report(tmp_path)
    assert [artifact["path"] for artifact in context.artifacts] == [str(path) for path in paths]
    assert {artifact["digest"] for artifact in context.artifacts} == {hashlib.sha256(raw).hexdigest()}
    assert len({artifact["canonical_digest"] for artifact in context.artifacts}) == 1
    assert len(context.findings) == 1 and context.findings[0]["status"] == "Unconfirmed"
    assert context.extensions["raptor.accounting"] == {"observed_results": 1, "captured_results": 1}
    assert context.state == "partial"
    assert any("Duplicate SARIF input omitted" in note for note in context.diagnostics)
    assert document.extensions["raptor.artifacts"] == context.artifacts
    for path in paths:
        binding = find_input_snapshot(path, data)
        assert binding["positions"][(0, 0)]["occurrence_ref"] == context.findings[0]["occurrence_ref"]
    generation = tmp_path / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    assert (generation / "report.md").read_bytes() == (tmp_path / "report.md").read_bytes()
    assert first.read_bytes() == duplicate.read_bytes() == raw

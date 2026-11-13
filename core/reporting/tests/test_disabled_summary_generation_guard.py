"""Disabled summary completion respects the selected-generation guard."""
from io import StringIO
import json

import pytest

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


def _files(directory):
    return {str(path.relative_to(directory)): path.read_bytes() for path in directory.rglob("*") if path.is_file()}


@pytest.mark.parametrize("stale", [False, True], ids=["current", "stale"])
def test_disabled_summary_guard_preserves_selected_capture(tmp_path, stale):
    source = tmp_path / "saved.json"
    source.write_text(json.dumps({"before": 0, "current": 1, "fresh": 2}))
    source_bytes = source.read_bytes()
    saved = json.loads(source_bytes)
    output = tmp_path / "report"
    generations = []
    for label in ("before", "current"):
        context = ReportContext("fixture", label, state="unknown", artifacts=[{"path": str(source)}],
                                extensions={"raptor.findings_available": False,
                                            "raptor.metrics": {"Recorded value": saved[label]}})
        result = complete_reporting(context, output, options=ReportOptions(("json", "markdown")), stream=StringIO())
        assert not result.errors and result.publication and result.publication.committed
        generations.append(result.publication.generation)
    assert generations[0] != generations[1]
    selected = load_committed_report(output)
    previous_files = _files(output)
    fresh = ReportContext("fixture", "fresh", state="unknown", artifacts=[{"path": str(source)}],
                          extensions={"raptor.findings_available": False,
                                      "raptor.metrics": {"Recorded value": saved["fresh"]}})
    original = fresh.to_dict()
    stream = StringIO()
    result = complete_reporting(fresh, output, options=ReportOptions(enabled=False), stream=stream,
                                expected_generation=generations[0 if stale else 1])
    assert result.publication is None
    assert result.summary.metrics["Recorded value"] == 2
    assert "Recorded value: 2" in stream.getvalue()
    assert "prior report artifacts were not refreshed" in stream.getvalue()
    assert fresh.to_dict() == original and source.read_bytes() == source_bytes
    assert load_committed_report(output) == selected
    if stale:
        assert result.errors and "Report persistence failed (ValueError)" in stream.getvalue()
        assert _files(output) == previous_files
    else:
        assert not result.errors
        summary = json.loads((output / "summary.json").read_text())
        assert summary == result.summary.to_dict()
        assert summary["snapshot_id"] == fresh.snapshot_id
        assert (output / "summary.md").read_bytes() != previous_files["summary.md"]
        assert {name: data for name, data in _files(output).items() if name not in {"summary.json", "summary.md"}} == {
            name: data for name, data in previous_files.items() if name not in {"summary.json", "summary.md"}}

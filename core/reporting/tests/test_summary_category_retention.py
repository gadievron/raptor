"""Bounded quick-view categories retain the complete committed population."""
from io import StringIO
import json

import pytest

from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context


@pytest.mark.parametrize("count", [20, 22], ids=["boundary", "overflow"])
def test_saved_status_and_tool_categories_survive_quick_view_caps(tmp_path, count):
    findings = [{"occurrence_ref": f"fixture:{index}", "tool": f"fixture-tool-{index:02d}",
                 "status": f"Recorded status {index:02d}", "file": f"file-{index}.c", "line": 1}
                for index in range(count)]
    source = tmp_path / "context.json"
    context = ReportContext("fixture", "saved", state="unknown", findings=findings,
                            artifacts=[{"path": str(source)}])
    source.write_text(json.dumps(context.to_dict()))
    source_bytes = source.read_bytes()
    context = load_context(source)
    original = context.to_dict()
    output = tmp_path / "report"
    stream = StringIO()
    result = complete_reporting(context, output, options=ReportOptions(("json", "markdown")), stream=stream)
    assert not result.errors and result.publication and result.publication.committed
    restored, document, manifest = load_committed_report(output)
    expected_counts = {f"Recorded status {index:02d}": 1 for index in range(count)}
    expected_tools = {f"fixture-tool-{index:02d}": 1 for index in range(count)}
    assert result.summary.total == count
    assert result.summary.counts == expected_counts and result.summary.tools == expected_tools
    assert document.summary == {"Captured findings": count, **expected_counts}
    assert context.to_dict() == restored.to_dict() == original
    assert restored.findings == findings
    generation = output / ".reporting" / manifest["generation"]
    for home in (output, generation):
        summary = json.loads((home / "summary.json").read_bytes())
        assert summary == result.summary.to_dict() == document.extensions["raptor.summary"]
        assert summary["counts"] == expected_counts and summary["tools"] == expected_tools
        text = (home / "summary.md").read_text()
        for shown in (text, stream.getvalue()):
            assert "Recorded status 19: 1" in shown and "fixture-tool-19=1" in shown
            assert "Recorded status 20: 1" not in shown and "fixture-tool-20=1" not in shown
            assert ("additional status categories retained in summary.json" in shown) is (count > 20)
            assert ("additional categories retained in summary.json" in shown) is (count > 20)
            if count > 20:
                assert "2 additional status categories" in shown and "2 additional categories" in shown
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    full = (generation / "report.md").read_text()
    assert f"Recorded status {count - 1:02d}" in full and f"fixture-tool-{count - 1:02d}" in full
    assert (output / "report.md").read_text() == full
    assert source.read_bytes() == source_bytes

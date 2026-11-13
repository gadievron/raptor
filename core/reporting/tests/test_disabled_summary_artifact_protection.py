"""Disabled full exports still preserve artifacts overlapping summary paths."""
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext, encode
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_context


@pytest.mark.parametrize("filename", ["summary.json", "summary.md"])
@pytest.mark.parametrize("protected", [False, True], ids=["healthy", "protected"])
def test_disabled_summary_preserves_captured_artifact_and_exposes_refusal(tmp_path, filename, protected):
    output = tmp_path / "report"
    output.mkdir()
    source = output / (filename if protected else "evidence" + filename[filename.index("."):])
    source.write_bytes(b'{"source":"retained owned evidence"}')
    source_bytes = source.read_bytes()
    context = ReportContext("fixture", "saved", target="owned", state="unknown",
                            findings=native_findings([{"id": "F", "message": "captured observation"}],
                                                     run_id="saved", producer="fixture", triage=True),
                            artifacts=[{"path": str(source)}])
    capture = tmp_path / "saved-context.json"
    capture.write_bytes(encode({**context.to_dict(), "snapshot_id": context.snapshot_id}))
    capture_bytes = capture.read_bytes()
    context = load_context(capture)
    original = context.to_dict()
    console = StringIO()
    result = complete_reporting(context, output, options=ReportOptions(enabled=False), stream=console)
    assert result.publication is None
    assert result.summary.total == 1 and result.summary.counts == {"Unconfirmed": 1}
    assert result.summary.state == "unknown" and "Captured findings: 1" in console.getvalue()
    assert context.to_dict() == original and source.read_bytes() == source_bytes
    assert capture.read_bytes() == capture_bytes
    assert not any((output / name).exists() for name in (
        "reporting-manifest.json", "report-context.json", "report-document.json", "report.json", "report.md"))
    if protected:
        message = "Report persistence failed (ValueError); analysis results are retained"
        assert result.errors == [message] and message in result.summary.diagnostics
        assert message in console.getvalue()
        other = output / ("summary.md" if filename == "summary.json" else "summary.json")
        assert not other.exists()
    else:
        assert result.errors == [] and result.diagnostics == []
        assert json.loads((output / "summary.json").read_bytes()) == result.summary.to_dict()
        markdown = (output / "summary.md").read_text(encoding="utf-8")
        assert "Captured findings: 1" in markdown and "Unconfirmed" in markdown
        assert "persistence failed" not in console.getvalue()

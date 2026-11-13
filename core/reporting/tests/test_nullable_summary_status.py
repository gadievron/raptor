"""Accepted saved contexts retain unknown status without breaking quick views."""
import io
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_context


def _saved_context(tmp_path, status):
    context = ReportContext("validate", "saved", state="completed")
    context.findings = native_findings(
        [{"id": "known", "file": "a.c", "line": 1, "final_status": "confirmed"},
         {"id": "unknown", "file": "b.c", "line": 2}],
        run_id=context.run_id, producer="validate",
    )
    data = context.to_dict()
    if status == "absent":
        data["findings"][1].pop("status")
    else:
        data["findings"][1]["status"] = status
    source = tmp_path / "captured-context.json"
    source.write_text(json.dumps(data))
    return source


@pytest.mark.parametrize("status", [None, "absent"], ids=["null", "absent"])
def test_saved_unknown_status_keeps_mixed_summary_available(tmp_path, status):
    source = _saved_context(tmp_path, status)
    original = source.read_bytes()
    context = load_context(source)
    captured = context.to_dict()
    stream = io.StringIO()
    output = tmp_path / "output"
    result = complete_reporting(context, output, options=ReportOptions(enabled=False), stream=stream)
    assert not result.errors
    assert result.summary.counts == {"Confirmed": 1, "Unknown": 1}
    assert [row["status"] for row in result.summary.rows] == ["Confirmed", "Unknown"]
    assert "Unknown: 1" in stream.getvalue()
    saved = json.loads((output / "summary.json").read_text())
    assert saved["counts"] == result.summary.counts
    assert saved["total"] == 2
    assert "Unknown" in (output / "summary.md").read_text()
    assert source.read_bytes() == original
    assert context.to_dict() == captured


def test_nonstring_saved_status_still_refused(tmp_path):
    source = _saved_context(tmp_path, 7)
    original = source.read_bytes()
    with pytest.raises(ValueError, match="Invalid normalized finding status"):
        load_context(source)
    assert source.read_bytes() == original

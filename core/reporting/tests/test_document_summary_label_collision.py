"""Accepted status labels cannot replace the document's captured total."""
from collections import Counter
from io import StringIO
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report, load_context


@pytest.mark.parametrize("statuses", [
    ["Captured findings", "Unconfirmed"],
    ["Captured findings", "Status: Captured findings", "Unconfirmed"],
    ["Unconfirmed", "Unknown"],
], ids=["reserved", "prefix-neighbor", "ordinary"])
def test_saved_status_counts_cannot_replace_captured_total(tmp_path, statuses):
    context = ReportContext("fixture", "saved", state="completed", findings=native_findings(
        [{"id": f"F{index}", "file": "a.c", "line": index + 1} for index in range(len(statuses))],
        run_id="saved", producer="fixture", triage=True))
    captured = context.to_dict()
    for finding, status in zip(captured["findings"], statuses, strict=True):
        finding["status"] = status
    source = tmp_path / "context.json"
    source.write_text(json.dumps(captured), encoding="utf-8")
    original = source.read_bytes()
    context = load_context(source)
    output = tmp_path / "report"
    result = complete_reporting(context, output, stream=StringIO(),
                                options=ReportOptions(formats=("json", "markdown")))
    assert not result.errors and result.publication is not None and result.publication.committed
    restored, document, _ = load_committed_report(output)
    counts = dict(Counter(statuses))
    assert result.summary.total == len(statuses) and result.summary.counts == counts
    assert document.summary["Captured findings"] == len(statuses)
    expected_counts = {f"Status: {label}": count for label, count in counts.items()} \
        if "Captured findings" in counts else counts
    assert document.summary == {"Captured findings": len(statuses), **expected_counts}
    assert json.loads((output / "report.json").read_bytes())["summary"] == document.summary
    markdown = (output / "report.md").read_text(encoding="utf-8")
    assert f"| Captured findings | {len(statuses)} |" in markdown
    for label, count in expected_counts.items():
        assert f"| {label} | {count} |" in markdown
    assert document.extensions["raptor.summary"]["counts"] == counts
    assert restored.to_dict() == context.to_dict() == captured
    assert [finding["status"] for finding in restored.findings] == statuses
    assert restored.completion_state == result.summary.state == "completed"
    assert source.read_bytes() == original

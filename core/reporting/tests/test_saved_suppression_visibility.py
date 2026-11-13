"""Quick-view suppression visibility never drops saved full-report findings."""
import io
import json

import pytest

from core.reporting.adapters import native_findings
from core.reporting.document import ReportContext
from core.reporting.options import ReportOptions
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("show", [False, True], ids=["hidden", "shown"])
def test_saved_suppression_visibility_preserves_full_population(tmp_path, show):
    raw = [{"id": "suppressed", "suppressed": True, "severity": "critical", "title": "suppressed observation"},
           {"id": "active", "suppressed": False, "severity": "low", "title": "active observation"}]
    source = tmp_path / "native.json"
    source.write_text(json.dumps(raw))
    source_bytes = source.read_bytes()
    findings = native_findings(json.loads(source_bytes), run_id="saved", producer="fixture", triage=True)
    context = ReportContext("scan", "saved", state="unknown", findings=findings,
                            artifacts=[{"path": str(source)}], extensions={"fixture.raw": json.loads(source_bytes)})
    saved = tmp_path / "saved-context.json"
    saved.write_text(json.dumps(context.to_dict()))
    saved_bytes = saved.read_bytes()
    context = ReportContext.from_dict(json.loads(saved_bytes))
    original = context.to_dict()
    output = tmp_path / "report"
    stream = io.StringIO()
    result = complete_reporting(context, output, options=ReportOptions(("json", "markdown")),
                                show_suppressed=show, stream=stream)
    assert not result.errors and result.publication and result.publication.committed
    restored, document, manifest = load_committed_report(output)
    assert context.to_dict() == restored.to_dict() == original
    assert restored.extensions["fixture.raw"] == raw
    summary = json.loads((output / "summary.json").read_text())
    assert summary == result.summary.to_dict() == document.extensions["raptor.summary"]
    assert summary["total"] == 2 and summary["counts"] == {"Unconfirmed": 2}
    assert [row["ref"] for row in summary["rows"]] == (["F00001", "F00002"] if show else ["F00002"])
    assert all(row["occurrence_ref"] == findings[int(row["ref"][1:]) - 1]["occurrence_ref"] for row in summary["rows"])
    assert any(("shown" if show else "hidden from quick view") in note for note in summary["diagnostics"])
    assert f"Showing {2 if show else 1} of 2 captured findings" in stream.getvalue()
    table = next(block for block in document.blocks if block.title == "Findings")
    assert [row[0] for row in table.rows] == ["F00001", "F00002"]
    assert [row[table.columns.index("Suppressed")] for row in table.rows] == [True, False]
    assert document.summary == {"Captured findings": 2, "Unconfirmed": 2}
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_text()) == document.to_dict()
    assert (generation / "report.md").read_bytes() == (output / "report.md").read_bytes()
    assert b"F00001" in (generation / "report.md").read_bytes()
    assert source.read_bytes() == source_bytes and saved.read_bytes() == saved_bytes

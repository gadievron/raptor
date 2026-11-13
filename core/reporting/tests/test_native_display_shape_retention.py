"""Typed native display projections leave the original captured evidence intact."""
from copy import deepcopy
from io import StringIO
import json

import pytest

from core.reporting.options import ReportOptions
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("malformed", [False, True], ids=["healthy", "unsupported-shapes"])
def test_native_display_shapes_keep_raw_evidence_through_publication(tmp_path, malformed):
    finding = {"id": "F", "message": "captured message", "final_status": "confirmed",
               "file": {"path": "a.c"} if malformed else "a.c",
               "line": True if malformed else 4,
               "level": ["warning"] if malformed else "warning",
               "severity": {"band": "high"} if malformed else "high"}
    source = tmp_path / "native.json"
    source.write_text(json.dumps({"findings": [finding], "recorded": {"zero": 0, "available": False, "unknown": None}}),
                      encoding="utf-8")
    source_bytes = source.read_bytes()
    payload = json.loads(source_bytes)
    original = deepcopy(payload)
    console = StringIO()
    output = tmp_path / "report"
    result = complete_native_result(
        NativeResult("fixture", "captured", "saved", payload, findings=payload["findings"],
                     triage=True, state="unknown", artifacts=[{"path": str(source)}]),
        output, stem="native", options=ReportOptions(formats=("json", "markdown")), stream=console)
    assert not result.errors and result.publication.committed
    context, document, manifest = load_committed_report(output)
    assert context.extensions["raptor.result"] == original == payload
    assert source.read_bytes() == source_bytes
    normalized = context.findings[0]
    assert normalized["native"] == original["findings"][0]
    assert normalized["file"] == ("" if malformed else "a.c")
    assert normalized["line"] == (None if malformed else 4)
    assert normalized["scanner_level"] == (None if malformed else "warning")
    assert normalized["severity"] == (None if malformed else "high")
    assert normalized["status"] == "Unconfirmed" and normalized["verdict_origin"] == "none"
    expected_notes = ["Unsupported security severity shape retained in native evidence"] if malformed else []
    assert normalized["diagnostics"] == expected_notes
    assert result.summary.total == 1 and result.summary.counts == {"Unconfirmed": 1}
    assert result.summary.state == context.completion_state == "unknown"
    assert result.summary.rows[0]["location"] == ("unknown" if malformed else "a.c:4")
    assert result.summary.security_severities == ({} if malformed else {"high": 1})
    table = next(block for block in document.blocks if block.title == "Findings")
    assert table.rows[0][3:7] == (["unknown", "Unconfirmed", None, None] if malformed
                                 else ["a.c:4", "Unconfirmed", "warning", "high"])
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "native.json").read_bytes()) == document.to_dict()
    markdown = (generation / "native.md").read_text(encoding="utf-8")
    assert "Unconfirmed" in markdown and "Captured findings: 1" in console.getvalue()
    assert (expected_notes[0] in markdown) if malformed else "Unsupported security severity" not in markdown

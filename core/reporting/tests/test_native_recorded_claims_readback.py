"""Explicit recorded verdict display remains an imported, incomplete claim."""
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("recorded", [False, True], ids=["default-triage", "recorded-claims"])
def test_native_recorded_claims_flag_preserves_provenance_through_readback(tmp_path, recorded):
    payload = {"findings": [{"finding_id": "F", "file": "captured.c", "line": 3,
                             "title": "saved source claim", "is_true_positive": True, "is_exploitable": True}],
               "source_metadata": {"zero": 0, "available": False, "unknown": None}}
    source = tmp_path / "native.json"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    output = tmp_path / "report"
    argv = ["native", str(source), "--out", str(output), "--run-id", "saved",
            "--report-format", "json", "--report-format", "markdown"]
    if recorded:
        argv += ["--recorded-verdicts"]
    assert main(argv) == 0
    context, document, manifest = load_committed_report(output)
    expected_status = "Exploitable" if recorded else "Unconfirmed"
    assert context.state == context.completion_state == "unknown"
    assert context.run_id == "saved" and context.stages == []
    assert context.extensions["raptor.imported"] == payload
    assert len(context.findings) == 1
    finding = context.findings[0]
    assert finding["native"] == payload["findings"][0]
    assert finding["status"] == expected_status
    assert finding["verdict_origin"] == ("imported" if recorded else "none")
    caveat = "Imported workflow data; recorded verdicts, when requested, are source claims, not local validation."
    assert caveat in context.diagnostics and caveat in document.diagnostics
    assert document.summary == {"Captured findings": 1, expected_status: 1}
    table = next(block for block in document.blocks if block.title == "Findings")
    assert table.rows[0][table.columns.index("Status")] == expected_status
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["state"] == "unknown" and summary["counts"] == {expected_status: 1}
    assert caveat in summary["diagnostics"]
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    for filename in ("report.md", "summary.md"):
        text = (output / filename).read_text()
        assert expected_status in text and "source claims, not local validation" in text
        assert (generation / filename).read_text() == text
    assert source.read_bytes() == original
    assert not (tmp_path / "captured.c").exists()

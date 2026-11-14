"""Conflicting saved claims keep existing display precedence and provenance."""
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("claims,expected", [
    pytest.param({"error": "saved failure", "error_type": "saved-failure", "is_true_positive": True,
                  "is_exploitable": True, "final_status": "confirmed"}, "Error (saved-failure)", id="error-first"),
    pytest.param({"is_true_positive": True, "is_exploitable": False,
                  "ruling": {"status": "ruled_out_unverified", "reason": "saved source ruling"}},
                 "Ruled Out (Unverified)", id="security-ruling"),
])
def test_saved_conflicting_claims_keep_display_precedence_and_imported_origin(tmp_path, claims, expected):
    payload = {"findings": [{"id": "F", "file": "captured.c", "line": 2, **claims}]}
    source = tmp_path / "saved.json"
    source.write_text(json.dumps(payload))
    original = source.read_bytes()
    output = tmp_path / "output"
    assert main(["native", str(source), "--out", str(output), "--recorded-verdicts",
                 "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, manifest = load_committed_report(output)
    assert context.state == "unknown" and context.stages == []
    assert context.extensions["raptor.imported"] == payload
    finding, = context.findings
    assert finding["native"] == payload["findings"][0]
    assert finding["status"] == expected and finding["verdict_origin"] == "imported"
    assert document.summary == {"Captured findings": 1, expected: 1}
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["state"] == "unknown" and summary["counts"] == {expected: 1}
    caveat = "Imported workflow data; recorded verdicts, when requested, are source claims, not local validation."
    assert caveat in context.diagnostics and caveat in document.diagnostics and caveat in summary["diagnostics"]
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    for name in ("report.md", "summary.md"):
        text = (output / name).read_text()
        assert expected in text and "source claims, not local validation" in text
        assert (generation / name).read_text() == text
    assert source.read_bytes() == original and not (tmp_path / "captured.c").exists()

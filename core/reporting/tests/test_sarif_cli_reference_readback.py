"""Offline SARIF CLI retains indexed references as Unconfirmed saved claims."""
import hashlib
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("indexed", [False, True], ids=["explicit-uri", "indexed-artifact"])
def test_sarif_cli_reference_capture_survives_committed_readback(tmp_path, indexed):
    location = {"index": 1} if indexed else {"uri": "captured-second.c"}
    payload = {"version": "2.1.0", "runs": [{
        "tool": {"driver": {"name": "fixture", "rules": [{"id": "same",
                 "defaultConfiguration": {"level": "error"}, "properties": {"security-severity": "7.2"}}]}},
        "artifacts": [{"location": {"uri": "captured-first.c"}}, {"location": {"uri": "captured-second.c"}}],
        "results": [{"rule": {"id": "same/subrule", "index": 0},
                     "message": {"markdown": "captured *source*"},
                     "properties": {"raptor": {"verdict": "confirmed"}},
                     "locations": [{"physicalLocation": {"artifactLocation": location, "region": {"startLine": 4}}}]}]}]}
    source = tmp_path / "captured.sarif"
    source.write_text(json.dumps(payload))
    source_bytes = source.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    output = tmp_path / "report"
    assert main(["sarif", str(source), "--out", str(output), "--run-id", "saved",
                 "--report-format", "json", "--report-format", "markdown"]) == 0
    context, document, manifest = load_committed_report(output)
    assert context.run_id == "saved" and context.state == "unknown"
    assert len(context.findings) == 1
    finding = context.findings[0]
    expected_ref = f"sarif:{digest}:0:0"
    assert finding["occurrence_ref"] == expected_ref
    assert finding["rule_id"] == "same/subrule" and finding["tool"] == "fixture"
    assert finding["file"] == "captured-second.c" and finding["line"] == 4
    assert finding["message"] == "captured *source*"
    assert finding["scanner_level"] == "error" and finding["security_score"] == "7.2"
    assert finding["severity"] is None
    assert finding["status"] == "Unconfirmed" and finding["verdict_origin"] == "none"
    assert context.artifacts[0]["path"] == str(source)
    assert context.artifacts[0]["digest"] == digest and context.artifacts[0]["digest_kind"] == "sha256-bytes"
    assert document.extensions["raptor.references"] == {"F00001": expected_ref}
    assert document.summary == {"Captured findings": 1, "Unconfirmed": 1}
    summary = json.loads((output / "summary.json").read_bytes())
    assert summary["counts"] == {"Unconfirmed": 1}
    assert summary["scanner_levels"] == {"error": 1} and summary["security_severities"] == {}
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    markdown = (generation / "report.md").read_text()
    assert "same/subrule" in markdown and "captured-second.c:4" in markdown and "Unconfirmed" in markdown
    assert (output / "report.md").read_text() == markdown
    assert source.read_bytes() == source_bytes
    assert not (tmp_path / "captured-first.c").exists() and not (tmp_path / "captured-second.c").exists()

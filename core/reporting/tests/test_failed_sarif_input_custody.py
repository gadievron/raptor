"""Failed explicit SARIF reads remain protected without becoming captures."""
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("raw", [b'{"version":"not-sarif","runs":[]}', b'{invalid JSON'],
                         ids=["invalid-version", "malformed-json"])
def test_export_cannot_replace_failed_sarif_input(tmp_path, raw):
    source = tmp_path / "rejected.json"
    source.write_bytes(raw)
    output = tmp_path / "output"
    assert main(["sarif", str(source), "--out", str(output), "--report-format", "json",
                 "--report-output", str(source)]) == 1
    assert source.read_bytes() == raw
    assert not (output / "reporting-manifest.json").exists()


def test_disabled_summary_cannot_replace_failed_sarif_input(tmp_path):
    source = tmp_path / "summary.json"
    raw = b'{"version":"not-sarif","runs":[]}'
    source.write_bytes(raw)
    assert main(["sarif", str(source), "--out", str(tmp_path), "--no-report"]) == 1
    assert source.read_bytes() == raw
    assert not (tmp_path / "summary.md").exists()
    assert not (tmp_path / "reporting-manifest.json").exists()


@pytest.mark.parametrize("valid_sibling", [False, True], ids=["all-invalid", "mixed"])
def test_source_refs_do_not_change_failed_capture_exit_or_grant_digest(tmp_path, valid_sibling):
    source = tmp_path / "rejected.json"
    raw = b'{"version":"not-sarif","runs":[]}'
    source.write_bytes(raw)
    paths = [source]
    if valid_sibling:
        valid = tmp_path / "valid.json"
        valid.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}},
                         "results": [{"ruleId": "saved-rule", "message": {"text": "owned saved observation"}}]}]}))
        paths.insert(0, valid)
    original = {str(path): path.read_bytes() for path in paths}
    output = tmp_path / "output"
    assert main(["sarif", *(str(path) for path in paths), "--out", str(output),
                 "--report-format", "json", "--report-format", "markdown"]) == (0 if valid_sibling else 1)
    context, document, manifest = load_committed_report(output)
    assert context.state == "partial"
    assert len(context.findings) == int(valid_sibling)
    assert [artifact for artifact in context.artifacts if artifact["path"] == str(source)] == [{"path": str(source)}]
    assert len([artifact for artifact in context.artifacts if "canonical_digest" in artifact]) == int(valid_sibling)
    assert document.extensions["raptor.artifacts"] == context.artifacts
    assert context.snapshot_id == document.snapshot_id == document.extensions["raptor.summary"]["snapshot_id"]
    assert any("could not capture SARIF" in note for note in context.diagnostics)
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    assert {str(path): path.read_bytes() for path in paths} == original

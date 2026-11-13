"""Offline imports count only the explicitly selected native finding array."""
import json

import pytest

from core.reporting.__main__ import main
from core.reporting.writer import load_committed_report


@pytest.mark.parametrize("case", ["root-array", "named-field", "empty-field"])
def test_native_cli_keeps_explicit_population_and_complete_payload(tmp_path, capsys, case):
    selected = [{"id": "selected", "message": "selected observation",
                 "related": [{"id": "nested-decoy"}]}]
    if case == "root-array":
        payload, key = selected, "."
    else:
        if case == "empty-field":
            selected = []
        payload = {"chosen": selected, "findings": [{"id": "default-decoy"}],
                   "other": [{"id": "other-decoy"}]}
        key = "chosen"
    source = tmp_path / "source.json"
    source.write_text(json.dumps(payload), encoding="utf-8")
    original = source.read_bytes()
    output = tmp_path / "report"
    assert main(["native", str(source), "--findings-key", key, "--out", str(output),
                 "--run-id", "saved", "--report-format", "json", "--report-format", "markdown"]) == 0
    console = capsys.readouterr()
    context, document, manifest = load_committed_report(output)
    assert context.extensions["raptor.imported"] == payload
    assert context.extensions["raptor.findings_available"] is True
    assert [finding["native"] for finding in context.findings] == selected
    assert [finding["source_id"] for finding in context.findings] == [row["id"] for row in selected]
    assert all(finding["status"] == "Unconfirmed" for finding in context.findings)
    assert context.completion_state == "unknown"
    summary = document.extensions["raptor.summary"]
    assert summary["total"] == len(selected) and summary["findings_available"] is True
    assert summary["counts"] == ({"Unconfirmed": 1} if selected else {})
    assert f"Captured findings: {len(selected)}" in console.out and not console.err
    generation = output / ".reporting" / manifest["generation"]
    assert json.loads((generation / "report.json").read_bytes()) == document.to_dict()
    markdown = (generation / "report.md").read_text(encoding="utf-8")
    assert ("Finding details" in markdown) is bool(selected)
    if case != "root-array":
        assert "default-decoy" in markdown and "other-decoy" in markdown
    assert source.read_bytes() == original


def test_native_cli_refuses_nonarray_selected_field_without_falling_back(tmp_path, capsys):
    source = tmp_path / "source.json"
    source.write_text(json.dumps({"chosen": {"id": "not an array"},
                                  "findings": [{"id": "default-decoy"}]}), encoding="utf-8")
    original = source.read_bytes()
    output = tmp_path / "report"
    assert main(["native", str(source), "--findings-key", "chosen", "--out", str(output),
                 "--report-format", "json"]) == 1
    console = capsys.readouterr()
    assert "Selected workflow findings field is not an array" in console.err and not console.out
    assert not output.exists() and source.read_bytes() == original

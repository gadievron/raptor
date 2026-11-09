"""Opt-in comparison exports preserve native CI output and domain gates."""
import json

import pytest

from packages.sca import diff
from packages.sca.diff_reporting import build_diff_document
from core.reporting.renderers import render_document


def _inputs(tmp_path):
    baseline, current = tmp_path / "before.json", tmp_path / "after.json"
    baseline.write_text("[]")
    current.write_text(json.dumps([{"id": "test", "vuln_type": "sca:vulnerable_dependency", "severity": "high",
                                   "sca": {"ecosystem": "npm", "name": "owned", "version": "1", "advisory": {"id": "TEST-1"}}}]))
    return baseline, current


@pytest.mark.parametrize("format_name,suffix", [("markdown", "md"), ("json", "json"), ("xml", "xml")])
def test_opt_in_export_keeps_native_json_and_gate(tmp_path, capsys, format_name, suffix):
    baseline, current = _inputs(tmp_path)
    original = current.read_bytes()
    output = tmp_path / ("comparison." + suffix)
    assert diff.main([str(baseline), str(current), "--json", "--report-format", format_name,
                      "--report-output", str(output)]) == 1
    streams = capsys.readouterr()
    assert json.loads(streams.out)["summary"]["new"] == 1
    assert "Summary" in streams.err
    assert output.is_file() and current.read_bytes() == original
    if format_name == "json":
        report = json.loads(output.read_text())
        assert report["summary"]["new"] == 1
    else:
        assert "owned" in output.read_text()


def test_default_and_no_report_do_not_write_companions(tmp_path, capsys):
    baseline, current = _inputs(tmp_path)
    expected = set(tmp_path.iterdir())
    for extra in ([], ["--no-report"]):
        assert diff.main([str(baseline), str(current), *extra]) == 1
        assert set(tmp_path.iterdir()) == expected
        assert capsys.readouterr().err == ""


def test_report_preflight_precedes_reading_missing_inputs(tmp_path, capsys):
    with pytest.raises(SystemExit) as error:
        diff.main([str(tmp_path / "missing"), str(tmp_path / "also-missing"), "--report-format", "json"])
    assert error.value.code == 2
    assert "requires --report-output" in capsys.readouterr().err


def test_bounded_comparison_discloses_absence_and_escapes_untrusted_fields(monkeypatch):
    from packages.sca import diff_reporting
    monkeypatch.setattr(diff_reporting, "DETAIL_LIMIT", 1)
    row = {"severity": "high", "suppression_reason": "operator decision", "sca": {"name": "</table><script>bad()</script>|x", "epss": 0.5, "advisory": {"id": "TEST"}}}
    delta = diff.DeltaResult(new=[row, row], resolved=[], suppression_added=[], suppression_lifted=[], persistent=[row])
    context, document = build_diff_document(delta, baseline="before", current="after", threshold="high",
                                            include_suppressed=False, show_persistent=False, exit_code=1)
    assert document.summary["new"] == 2 and document.summary["persistent"] == 1
    assert any("showing 1 of 2" in note for note in context.diagnostics)
    assert any("does not establish remediation" in note for note in context.diagnostics)
    assert not any(block.title == "Persistent" for block in document.blocks)
    table = next(block for block in document.blocks if block.title == "New")
    assert table.rows[0][-2:] == ["0.5", "operator decision"]
    text = render_document(document, "markdown").content.decode()
    assert "<script>" not in text


def test_report_write_failure_retains_machine_output_and_gate(tmp_path, capsys):
    baseline, current = _inputs(tmp_path)
    blocker = tmp_path / "file"
    blocker.write_text("retained")
    assert diff.main([str(baseline), str(current), "--json", "--report-output", str(blocker / "result.md")]) == 1
    streams = capsys.readouterr()
    assert json.loads(streams.out)["summary"]["new"] == 1
    assert "persistence failed" in streams.err
    assert blocker.read_text() == "retained"


def test_report_destination_cannot_replace_input_findings(tmp_path, capsys):
    baseline, current = _inputs(tmp_path)
    original = current.read_bytes()
    assert diff.main([str(baseline), str(current), "--json", "--report-format", "json",
                      "--report-output", str(current)]) == 1
    streams = capsys.readouterr()
    assert json.loads(streams.out)["summary"]["new"] == 1
    assert "failed" in streams.err.lower()
    assert current.read_bytes() == original


def test_snapshot_identity_binds_displayed_rows_with_equal_category_counts():
    def capture(name):
        delta = diff.DeltaResult(new=[{"severity": "high", "sca": {"name": name}}], resolved=[],
                                 suppression_added=[], suppression_lifted=[])
        return build_diff_document(delta, baseline="before", current="after", threshold="high",
                                   include_suppressed=False, show_persistent=False, exit_code=1)
    first, first_document = capture("one")
    second, second_document = capture("two")
    assert first_document.summary == second_document.summary
    assert first.snapshot_id != second.snapshot_id
    assert first_document.snapshot_id == first.snapshot_id
    assert second_document.snapshot_id == second.snapshot_id
    assert first.extensions["raptor.result_sections"] != second.extensions["raptor.result_sections"]


def test_nullable_advisory_metadata_preserves_display_fallbacks_and_gate_selection():
    rows = [{"vuln_type": "nullable-advisory", "severity": "high", "sca": {"name": "owned", "advisory": None}},
            {"vuln_type": "nullable-sca", "sca": None},
            {"vuln_type": "scalar-advisory", "sca": {"advisory": "invalid"}},
            {"sca": {"advisory": {"id": "CVE-2099-12345"}}}]
    delta = diff.DeltaResult(new=rows, resolved=[], suppression_added=[], suppression_lifted=[])
    context, document = build_diff_document(delta, baseline="before", current="after", threshold="high",
                                            include_suppressed=False, show_persistent=False, exit_code=1)
    table = next(block for block in document.blocks if block.title == "New")
    assert [row[3] for row in table.rows] == ["nullable-advisory", "nullable-sca", "scalar-advisory", "CVE-2099-12345"]
    assert table.rows[0][0:3] == ["unknown", "owned", "unknown"]
    assert table.rows[1][0:3] == ["unknown", "unknown", "unknown"]
    assert document.summary["new"] == 4 and context.extensions["raptor.selection"]["gate_exit_code"] == 1
    assert context.extensions["raptor.metrics"]["new"] == 4

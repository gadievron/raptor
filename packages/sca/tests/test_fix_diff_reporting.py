"""Fix discovery receipts capture native outcomes without further agent calls."""
import json

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.sca import fix_diff
from packages.sca.fix_diff_reporting import fix_diff_result


@isolated_cli_logging()
def test_fix_diff_receipt_keeps_cap_failures_and_native_summary(tmp_path, monkeypatch, capsys):
    calls = []

    def completed(cve, output, **kwargs):
        calls.append(cve)
        return {"ok": cve.endswith("10000"), "cve_id": cve,
                "fix_commit": "a" * 40 if cve.endswith("10000") else None,
                "error_class": None if cve.endswith("10000") else "NoSummary"}

    monkeypatch.setattr(fix_diff, "run_one", completed)
    output = tmp_path / "native"
    args = ["--cve", "CVE-2099-10000", "--cve", "CVE-2099-10001", "--cve", "CVE-2099-10002",
            "--max-cves", "2", "--output-dir", str(output), "--report-format", "json",
            "--report-output", str(tmp_path / "receipt.json")]
    assert fix_diff.main(args) == 1
    assert calls == ["CVE-2099-10000", "CVE-2099-10001"]
    native = json.loads((output / "summary.json").read_text())
    assert native["dropped_over_cap"] == 1 and len(native["results"]) == 2
    context, _, _ = load_committed_report(tmp_path / ".receipt-report")
    assert context.state == "partial" and context.extensions["raptor.result"]["results"] == native["results"]
    assert context.extensions["raptor.metrics"]["Unattempted over cap"] == 1
    assert any("native summary.json retains" in note for note in context.diagnostics)
    streams = capsys.readouterr()
    assert "1/2 CVEs resolved" in streams.out and "Summary" in streams.err


@isolated_cli_logging()
def test_empty_selection_report_is_noop_without_agent_or_native_directory(tmp_path, monkeypatch):
    monkeypatch.setattr(fix_diff, "run_one", lambda *args, **kwargs: pytest.fail("no selection must not spend"))
    findings = tmp_path / "findings.json"
    findings.write_text("[]")
    assert fix_diff.main([str(findings), "--report-format", "json", "--report-output", str(tmp_path / "empty.json")]) == 0
    assert not (tmp_path / "fix-diffs").exists()
    context, _, _ = load_committed_report(tmp_path / ".empty-report")
    assert context.extensions["raptor.metrics"]["Attempted CVE entries"] == 0
    assert context.extensions["raptor.findings_available"] is False
    assert any("not a clean" in note for note in context.diagnostics)
    assert not any("native summary.json retains" in note for note in context.diagnostics)
    assert any("no native discovery summary was recorded" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_missing_input_receipt_keeps_error_status_and_no_agent(tmp_path, monkeypatch):
    monkeypatch.setattr(fix_diff, "run_one", lambda *args, **kwargs: pytest.fail("invalid input must not spend"))
    assert fix_diff.main([str(tmp_path / "missing.json"), "--report-format", "json",
                          "--report-output", str(tmp_path / "failed.json")]) == 2
    context, _, _ = load_committed_report(tmp_path / ".failed-report")
    assert context.state == "failed" and context.extensions["raptor.result"]["results"] == []
    assert not any("native summary.json retains" in note for note in context.diagnostics)
    assert any("no native discovery summary was recorded" in note for note in context.diagnostics)


@isolated_cli_logging()
def test_fix_diff_report_cannot_replace_findings_input(tmp_path, monkeypatch, capsys):
    source = tmp_path / "findings.json"
    source.write_text("[]")
    monkeypatch.setattr(fix_diff, "run_one", lambda *args, **kwargs: pytest.fail("must not spend"))
    assert fix_diff.main([str(source), "--report-format", "json", "--report-output", str(source)]) == 0
    assert source.read_text() == "[]"
    assert "Report persistence failed" in capsys.readouterr().err


def test_fix_diff_capture_bounds_and_redacts_without_mutating_results(monkeypatch):
    from packages.sca import fix_diff_reporting
    rows = [{"ok": False, "cve_id": "CVE-2099-10000", "error_detail": "https://user:owned-secret@example.invalid\x1b[31m"},
            {"ok": True, "cve_id": "CVE-2099-10001"}]
    monkeypatch.setattr(fix_diff_reporting, "DETAIL_LIMIT", 1)
    context, _ = fix_diff_result(rows).build()
    captured = context.extensions["raptor.result"]["results"]
    assert len(captured) == 1 and context.extensions["raptor.metrics"]["Attempted CVE entries"] == 2
    assert "owned-secret" not in captured[0]["error_detail"] and "\x1b" not in captured[0]["error_detail"]
    assert "owned-secret" in rows[0]["error_detail"]


def test_report_preflight_precedes_discovery(monkeypatch):
    monkeypatch.setattr(fix_diff, "run_one", lambda *args, **kwargs: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        fix_diff.main(["--cve", "CVE-2099-10000", "--report-format", "json"])
    assert error.value.code == 2


def test_successful_discovery_without_pointer_stays_unavailable():
    context, _ = fix_diff_result([{"ok": True, "cve_id": "CVE-2099-10000"}]).build()
    metrics = context.extensions["raptor.metrics"]
    assert metrics["Successful discovery entries"] == 1 and metrics["Recorded fix pointers"] == 0
    assert context.state == "partial" and any("missing pointers" in note for note in context.diagnostics)

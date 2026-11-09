"""Suppression reports reuse native groups and preserve failure distinctions."""
import argparse
import json

import pytest

from core.reporting.writer import load_committed_report
from core.testing.logging_state import isolated_cli_logging
from packages.sca import suppress_cli
from packages.sca.suppression_reporting import suppression_result
from packages.sca.suppressions import SUPPRESS_FILENAME, SuppressionEntry


def _overlay(tmp_path, entries):
    path = tmp_path / SUPPRESS_FILENAME
    path.write_text(json.dumps({"version": 1, "suppressions": entries}))
    return path


@isolated_cli_logging()
def test_suppression_check_captures_native_groups_without_reloading(tmp_path, monkeypatch, capsys):
    _overlay(tmp_path, [{"advisory_id": "GHSA-OWNED", "reason": "reviewed"},
                        {"advisory_id": "GHSA-ORPHAN", "reason": "historical"},
                        {"advisory_id": "GHSA-EXPIRED", "reason": "expired", "expires": "2000-01-01"}])
    findings = tmp_path / "findings.json"
    findings.write_text(json.dumps([{"sca": {"advisory": {"id": "GHSA-OWNED", "aliases": []}}}]))
    calls = []
    native_loader = suppress_cli.load

    def counted(path):
        calls.append(path)
        return native_loader(path)

    monkeypatch.setattr(suppress_cli, "load", counted)
    assert suppress_cli.main(["check", "--target", str(tmp_path), "--findings", str(findings),
                              "--report-format", "json", "--report-output", str(tmp_path / "check.json")]) == 1
    assert len(calls) == 1
    context, _, _ = load_committed_report(tmp_path / ".check-report")
    result = context.extensions["raptor.result"]
    assert result["recorded counts"] == {"entries": 3, "matched": 1, "orphan": 1, "expired": 1}
    assert result["finding count checked"] == 1 and result["evaluation date"]
    assert context.state == "completed" and result["native exit status"] == 1
    assert "1 orphan" in capsys.readouterr().out


@isolated_cli_logging()
def test_suppression_list_retains_native_json(tmp_path, capsys):
    _overlay(tmp_path, [{"advisory_id": "GHSA-OWNED", "reason": "owned"}])
    assert suppress_cli.main(["list", "--target", str(tmp_path), "--json", "--report-format", "json",
                              "--report-output", str(tmp_path / "list.json")]) == 0
    native = json.loads(capsys.readouterr().out)
    context, _, _ = load_committed_report(tmp_path / ".list-report")
    assert context.extensions["raptor.result"]["entries"] == native
    assert context.extensions["raptor.result"]["finding count checked"] is None


@pytest.mark.parametrize("has_overlay,expected", [(False, 1), (True, 2)])
@isolated_cli_logging()
def test_suppression_missing_inputs_retain_nonzero_status(tmp_path, has_overlay, expected):
    if has_overlay:
        _overlay(tmp_path, [{"advisory_id": "GHSA-OWNED", "reason": "owned"}])
    assert suppress_cli.main(["check", "--target", str(tmp_path), "--findings", str(tmp_path / "missing.json"),
                              "--report-format", "json", "--report-output", str(tmp_path / "missing-report.json")]) == expected
    context, _, _ = load_committed_report(tmp_path / ".missing-report-report")
    assert context.state == "failed" and context.extensions["raptor.result"]["finding count checked"] is None


@isolated_cli_logging()
def test_suppression_report_cannot_replace_overlay(tmp_path, capsys):
    path = _overlay(tmp_path, [])
    before = path.read_bytes()
    output = tmp_path / "overlay-copy.json"
    output.symlink_to(path)
    assert suppress_cli.main(["list", "--target", str(tmp_path), "--report-format", "json",
                              "--report-output", str(output)]) == 0
    assert path.read_bytes() == before and "Report persistence failed" in capsys.readouterr().err


def test_suppression_capture_bounds_and_redacts_without_mutation(tmp_path, monkeypatch):
    from packages.sca import suppression_reporting
    entry = SuppressionEntry(reason="https://user:owned-secret@[invalid", advisory_id="GHSA-OWNED")
    monkeypatch.setattr(suppression_reporting, "DETAIL_LIMIT", 1)
    context, _ = suppression_result(argparse.Namespace(target=str(tmp_path), action="list"),
                                    {"entries": [entry, entry]}, 0).build()
    payload = context.extensions["raptor.result"]
    assert payload["recorded counts"]["entries"] == 2 and len(payload["entries"]) == 1
    assert "owned-secret" not in payload["entries"][0]["reason"] and "owned-secret" in entry.reason


def test_suppression_report_preflight_before_loader(monkeypatch, tmp_path):
    monkeypatch.setattr(suppress_cli, "load", lambda path: pytest.fail("must preflight"))
    with pytest.raises(SystemExit) as error:
        suppress_cli.main(["list", "--target", str(tmp_path), "--report-format", "json"])
    assert error.value.code == 2

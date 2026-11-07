"""Findings regeneration preserves the previous handoff until publication."""

import json
from pathlib import Path

import pytest

from core.project import report


@pytest.mark.parametrize("stage", ["aggregate", "finding", "json"])
@pytest.mark.parametrize("cancel", [False, True])
def test_generation_failure_preserves_previous_report(tmp_path, monkeypatch, stage, cancel):
    previous = tmp_path / "findings"
    previous.mkdir()
    marker = previous / "previous-report"
    marker.write_bytes(b"published report")
    finding = {"id": "F-1", "title": "Example", "status": "confirmed"}

    def fail(*args, **kwargs):
        if cancel:
            raise KeyboardInterrupt("generation cancelled")
        raise OSError("generation failed")

    target = {"aggregate": "render_grouped_findings_markdown",
              "finding": "render_finding_markdown", "json": "save_json"}[stage]
    monkeypatch.setattr(report, target, fail)
    with pytest.raises(KeyboardInterrupt if cancel else OSError):
        report.export_findings_directory([finding], tmp_path)
    assert marker.read_bytes() == b"published report"
    assert list(previous.iterdir()) == [marker]
    assert not list(tmp_path.glob(".findings-stage-*"))


@pytest.mark.parametrize("fail_at", [1, 2])
@pytest.mark.parametrize("cancel", [False, True])
def test_swap_failure_restores_previous_report(tmp_path, monkeypatch, fail_at, cancel):
    previous = tmp_path / "findings"
    previous.mkdir()
    marker = previous / "old"
    marker.write_text("previous report")
    rename = report.rename_without_replace
    calls = 0

    def fail_once(path, destination):
        nonlocal calls
        calls += 1
        if calls == fail_at:
            if cancel:
                raise KeyboardInterrupt("swap cancelled")
            raise OSError("swap failed")
        return rename(path, destination)

    monkeypatch.setattr(report, "rename_without_replace", fail_once)
    with pytest.raises(KeyboardInterrupt if cancel else OSError):
        report.export_findings_directory([], tmp_path)
    assert marker.read_text() == "previous report"
    assert not list(tmp_path.glob(".findings-stage-*"))


def test_failed_rollback_retains_recovery_copy(tmp_path, monkeypatch, caplog):
    previous = tmp_path / "findings"
    previous.mkdir()
    (previous / "old").write_text("recover me")
    rename = report.rename_without_replace
    calls = 0

    def fail_publish_and_restore(path, destination):
        nonlocal calls
        calls += 1
        if calls >= 2:
            raise OSError("publication failed")
        return rename(path, destination)

    monkeypatch.setattr(report, "rename_without_replace", fail_publish_and_restore)
    with pytest.raises(OSError, match="publication failed"):
        report.export_findings_directory([], tmp_path)
    roots = list(tmp_path.glob(".findings-stage-*"))
    assert len(roots) == 1
    assert (roots[0] / "previous" / "old").read_text() == "recover me"
    assert not (roots[0] / "next").exists()
    assert str(roots[0]) in caplog.text


def test_first_export_failure_leaves_no_partial_report(tmp_path, monkeypatch):
    def fail(*args, **kwargs):
        raise ValueError("render failed")

    monkeypatch.setattr(report, "render_grouped_findings_markdown", fail)
    with pytest.raises(ValueError, match="render failed"):
        report.export_findings_directory([], tmp_path)
    assert not (tmp_path / "findings").exists()
    assert not list(tmp_path.glob(".findings-stage-*"))


def test_manifest_and_result_paths_name_published_files(tmp_path):
    findings = [{"id": "F-1", "title": "First", "status": "confirmed"},
                {"id": "F-2", "title": "Second", "status": "ruled_out"}]
    result = report.export_findings_directory(findings, tmp_path, project_name="test project")
    final = tmp_path / "findings"
    assert Path(result["findings_dir"]) == final
    assert Path(result["aggregate_markdown"]).is_file()
    manifest = json.loads((final / "manifest.json").read_text())
    records = [json.loads(line) for line in (final / "findings.jsonl").read_text().splitlines()]
    assert len(manifest["findings"]) == len(records) == 2
    for record in manifest["findings"]:
        assert record["markdown"].startswith("findings/")
        assert record["json"].startswith("findings/")
        assert (tmp_path / record["markdown"]).is_file()
        assert (tmp_path / record["json"]).is_file()
    assert not list(tmp_path.glob(".findings-stage-*"))


@pytest.mark.parametrize("dangling", [False, True])
def test_old_report_symlink_never_modifies_target(tmp_path, dangling):
    output = tmp_path / "output"
    output.mkdir()
    target = tmp_path / "external"
    if not dangling:
        target.mkdir()
        (target / "keep").write_text("external data")
    (output / "findings").symlink_to(target, target_is_directory=True)
    report.export_findings_directory([], output)
    assert (output / "findings").is_dir()
    assert not (output / "findings").is_symlink()
    if dangling:
        assert not target.exists()
    else:
        assert (target / "keep").read_text() == "external data"
    assert not list(output.glob(".findings-stage-*"))


@pytest.mark.parametrize("mode", [0o000, 0o555])
def test_restricted_old_reports_are_reclaimed(tmp_path, mode):
    previous = tmp_path / "findings"
    previous.mkdir()
    nested = previous / "locked"
    nested.mkdir()
    (nested / "old").write_text("old report")
    nested.chmod(mode)
    report.export_findings_directory([], tmp_path)
    assert not (tmp_path / "findings" / "locked").exists()
    assert not list(tmp_path.glob(".findings-stage-*"))


def test_successful_regeneration_removes_stale_files(tmp_path):
    report.export_findings_directory([{"id": "F-1", "title": "Gone", "status": "confirmed"}], tmp_path)
    assert list((tmp_path / "findings" / "confirmed").glob("*.json"))
    report.export_findings_directory([], tmp_path)
    assert not (tmp_path / "findings" / "confirmed").exists()
    assert json.loads((tmp_path / "findings" / "manifest.json").read_text()) == {"findings": []}
    assert not list(tmp_path.glob(".findings-stage-*"))


def test_export_refuses_unavailable_lock(tmp_path):
    (tmp_path / "findings").mkdir()
    marker = tmp_path / "findings" / "old"
    marker.write_text("previous report")
    (tmp_path / ".findings-export.lock").symlink_to("missing")
    with pytest.raises(OSError):
        report.export_findings_directory([], tmp_path)
    assert marker.read_text() == "previous report"
    assert not list(tmp_path.glob(".findings-stage-*"))


@pytest.mark.parametrize("cancel_cleanup", [False, True])
def test_cleanup_failure_preserves_generation_error(tmp_path, monkeypatch, caplog, cancel_cleanup):
    previous = tmp_path / "findings"
    previous.mkdir()
    (previous / "old").write_text("published")

    def fail_render(*args, **kwargs):
        raise ValueError("primary rendering failure")

    def fail_cleanup(path):
        if cancel_cleanup:
            raise KeyboardInterrupt("secondary cleanup cancellation")
        raise OSError("secondary cleanup failure")

    with monkeypatch.context() as faults:
        faults.setattr(report, "render_grouped_findings_markdown", fail_render)
        faults.setattr(report, "_clear_generated_findings_dir", fail_cleanup)
        with pytest.raises(ValueError, match="primary rendering failure"):
            report.export_findings_directory([], tmp_path)
    assert (previous / "old").read_text() == "published"
    roots = list(tmp_path.glob(".findings-stage-*"))
    assert roots and str(roots[0]) in caplog.text
    for root in roots:
        report._clear_generated_findings_dir(root)

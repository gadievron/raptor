"""Projects retain SBOM evidence per snapshot without additive inventory claims."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.project.report import generate_project_report
from core.project.sbom_reports import capture_sbom_reports, sbom_evidence_delta
from core.reporting.builders import build_document
from core.reporting.document import ReportContext
from core.reporting.writer import load_committed_report, publish_report


def capture(directory, *, kind="sca", packages=3, source="a", notice="not_verified", extra=None):
    data = {"source_sha256": source * 64, "source_format": "CycloneDX", "summary": {"packages": packages, "unresolved_declarations": 1},
            "notice_verification": notice, "selected_records": packages, "captured_records": packages}
    if extra:
        data.update(extra)
    context = ReportContext(kind, "run", state="completed", extensions={"raptor.sbom": data, "raptor.findings_available": False})
    publish_report(context, build_document(context), directory)
    return context


def test_project_freezes_nested_inventory_metadata_and_keeps_populations_separate(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    first.mkdir(); second.mkdir()
    capture(first / "sca", packages=3)
    capture(second / "report", kind="sbom-inspect", packages=3, source="b")
    project = SimpleNamespace(name="demo", output_path=tmp_path, get_run_dirs=lambda **kwargs: [second, first])
    stats = generate_project_report(project)
    assert stats["runs"] == 2
    context, document, _ = load_committed_report(tmp_path / "_report")
    rows = context.extensions["raptor.sbom_reports"]
    assert len(rows) == 2 and [row["summary"]["packages"] for row in rows] == [3, 3]
    assert context.findings == []
    assert any(block.title == "Selected SBOM evidence" for block in document.blocks)
    frozen = deepcopy(rows)
    capture(first / "sca", packages=9, source="c")
    # Already-captured project observations do not change as child files change.
    assert load_committed_report(tmp_path / "_report")[0].extensions["raptor.sbom_reports"] == frozen


def test_imported_snapshot_stays_a_claim_and_exact_copies_are_not_added(tmp_path):
    run = tmp_path / "run"
    context = capture(run)
    # Same committed capture at a child boundary must not add its population.
    publish_report(context, build_document(context), run / "sca")
    rows, notes = capture_sbom_reports([run], {str(run): context}, {str(run): True})
    assert len(rows) == 1 and rows[0]["imported"] is True
    assert rows[0]["notice_verification"] == "not_verified"
    assert not notes


def test_root_rejected_by_project_is_not_rediscovered(tmp_path):
    capture(tmp_path)
    rows, notes = capture_sbom_reports([tmp_path], {}, {})
    assert rows == [] and notes == []


def test_corrupt_nested_report_never_falls_back_to_live_inventory(tmp_path):
    root = tmp_path / "sca"
    capture(root)
    (root / "reporting-manifest.json").write_text("not JSON")
    (root / "sbom.cdx.json").write_text('{"components":[]}')
    rows, notes = capture_sbom_reports([tmp_path], {}, {})
    assert not rows and any("capture unavailable" in note for note in notes)


@pytest.mark.parametrize("relative", ["sca", "report", "sca/report"])
def test_nested_output_symlinks_cannot_escape_selected_run(tmp_path, relative):
    run, outside = tmp_path / "run", tmp_path / "outside"
    run.mkdir()
    capture(outside)
    target = run / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.symlink_to(outside, target_is_directory=True)
    rows, notes = capture_sbom_reports([run], {}, {})
    assert rows == [] and notes
    with pytest.raises((ValueError, OSError)):
        load_committed_report(target, root=run)


def test_changed_selections_are_observations_not_package_resolution(tmp_path):
    run = tmp_path / "run"
    context = capture(run / "report", kind="sbom-inspect")
    before_rows, _ = capture_sbom_reports([run], {}, {})
    before = ReportContext("project", "demo", extensions={"raptor.sbom_reports": before_rows})
    capture(run / "report", kind="sbom-inspect", packages=1, source="b")
    after_rows, _ = capture_sbom_reports([run], {}, {})
    after = ReportContext("project", "demo", extensions={"raptor.sbom_reports": after_rows})
    rows, blocks = sbom_evidence_delta(before, after)
    assert rows == [["run/report", "selected capture changed", context.snapshot_id, after_rows[0]["snapshot_id"]]]
    assert "not package-removal or remediation verdicts" in blocks[1].text
    absent = ReportContext("project", "demo")
    assert sbom_evidence_delta(after, absent)[0][0][1] == "capture no longer selected"


def test_project_baseline_keeps_sbom_capture_delta_separate(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    capture(run / "sca")
    project = SimpleNamespace(name="demo", output_path=tmp_path, get_run_dirs=lambda **kwargs: [run])
    generate_project_report(project)
    baseline = tmp_path / "_report"
    capture(run / "sca", packages=5, source="b")
    generate_project_report(project, baseline=baseline)
    delta, document, _ = load_committed_report(tmp_path / "_report/delta")
    assert delta.extensions["raptor.sbom_evidence_changes"][0][1] == "selected capture changed"
    assert any(block.title == "SBOM evidence selection changes" for block in document.blocks)


def test_imported_summary_fields_are_bounded_and_never_coerced(tmp_path):
    extra = {"summary": {"packages": "100", "unresolved_declarations": {"forged": 0}, "unknown": "x" * 10000},
             "notice_verification": {"forged": "verified"}, "source_sha256": "x" * 10000}
    context = capture(tmp_path, extra=extra)
    rows, _ = capture_sbom_reports([tmp_path], {str(tmp_path): context}, {str(tmp_path): True})
    assert rows[0]["summary"] == {}
    assert rows[0]["source_sha256"] == ""
    assert rows[0]["notice_verification"] == "not_recorded"


def test_malformed_baseline_metadata_does_not_create_selection_changes():
    baseline = ReportContext("project", "demo", extensions={"raptor.sbom_reports": [{"selection": {}, "snapshot_id": "forged"}]})
    current = ReportContext("project", "demo")
    changes, blocks = sbom_evidence_delta(baseline, current)
    assert changes == [] and "comparison unavailable" in blocks[0].text

"""Project capture respects explicit native report producer identities."""

import pytest

from core.json import save_json
from core.reporting.builders import build_document
from core.project.project import Project
from core.project.report import generate_project_report
from core.reporting.document import StageEnvelope
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report, publish_report
from core.run.report_identity import fresh_identity
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def isolated_user_state(tmp_path):
    with pytest.MonkeyPatch.context() as patch:
        pin_user_state_dirs(patch, tmp_path)
        yield


def _capture_project(tmp_path, *, kind="binary-map", producer="understand"):
    output = tmp_path / "project"
    run = output / "captured-run"
    run.mkdir(parents=True)
    identity = fresh_identity()
    metadata = {"command": producer, "status": "completed", "reporting_identity": identity,
                "manifest": {"target": {"sha256": "a" * 64}}}
    save_json(run / ".raptor-run.json", metadata)
    result = NativeResult(kind, "captured target", "unknown", {"captured count": 2}, state="completed",
                          stages=[StageEnvelope("captured stage", "completed")], lifecycle_dir=run,
                          lifecycle_producer=producer, lifecycle_metadata=metadata)
    publication = complete_native_result(result, run, stem="native-report")
    assert not publication.errors
    captured, _, _ = load_committed_report(run)
    project = Project(name="captured", target=str(tmp_path / "target"), output_dir=str(output))
    return project, run, captured, metadata


def test_project_keeps_current_snapshot_with_explicit_producer_alias(tmp_path):
    project, run, captured, metadata = _capture_project(tmp_path)
    original = (run / ".raptor-run.json").read_bytes()
    generate_project_report(project)
    merged, _, _ = load_committed_report(project.output_path / "_report")
    selected = merged.extensions["raptor.project"]["selection"]
    assert len(selected) == 1
    assert selected[0]["snapshot_id"] == captured.snapshot_id
    assert selected[0]["lifecycle"] == metadata["reporting_identity"]
    assert captured.snapshot_id in merged.parents
    assert not any("earlier execution" in note for note in merged.diagnostics)
    assert (run / ".raptor-run.json").read_bytes() == original


@pytest.mark.parametrize("kind, producer", [("analysis", "analyze"), ("scan", "scan")])
def test_other_explicit_producers_keep_the_matching_snapshot(tmp_path, kind, producer):
    project, run, captured, _ = _capture_project(tmp_path, kind=kind, producer=producer)
    generate_project_report(project)
    merged, _, _ = load_committed_report(project.output_path / "_report")
    assert merged.extensions["raptor.project"]["selection"][0]["snapshot_id"] == captured.snapshot_id
    assert captured.snapshot_id in merged.parents


@pytest.mark.parametrize("marker", [None, "", "wrong", {"command": "understand"}, "missing"])
def test_missing_or_malformed_alias_does_not_infer_a_producer(tmp_path, marker):
    project, run, captured, _ = _capture_project(tmp_path)
    if marker == "missing":
        captured.extensions.pop("raptor.lifecycle.producer_command")
    else:
        captured.extensions["raptor.lifecycle.producer_command"] = marker
    publish_report(captured, build_document(captured), run, stem="native-report")
    generate_project_report(project)
    merged, _, _ = load_committed_report(project.output_path / "_report")
    assert merged.extensions["raptor.project"]["selection"][0]["snapshot_id"] is None
    assert captured.snapshot_id not in merged.parents
    assert any("earlier execution" in note for note in merged.diagnostics)


@pytest.mark.parametrize("component", ["run_id", "pass_id", "attempt_id", "command"])
def test_producer_alias_cannot_bypass_current_execution_identity(tmp_path, component):
    project, run, captured, metadata = _capture_project(tmp_path)
    if component == "command":
        metadata["command"] = "scan"
    else:
        metadata["reporting_identity"][component] = fresh_identity()[component]
    save_json(run / ".raptor-run.json", metadata)
    generate_project_report(project)
    merged, _, _ = load_committed_report(project.output_path / "_report")
    assert merged.extensions["raptor.project"]["selection"][0]["snapshot_id"] is None
    assert captured.snapshot_id not in merged.parents


def test_canonical_producer_without_alias_marker_remains_compatible(tmp_path):
    project, run, captured, _ = _capture_project(tmp_path, kind="scan", producer="scan")
    captured.extensions.pop("raptor.lifecycle.producer_command")
    publish_report(captured, build_document(captured), run, stem="native-report")
    generate_project_report(project)
    merged, _, _ = load_committed_report(project.output_path / "_report")
    assert merged.extensions["raptor.project"]["selection"][0]["snapshot_id"] == captured.snapshot_id

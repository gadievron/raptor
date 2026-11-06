"""Explicit lifecycle, import, project grouping, and delta contracts."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from core.json import save_json
from core.reporting.adapters import context_from_sarif, native_findings
from core.reporting.document import ReportContext
from core.reporting.lifecycle import apply_lifecycle, apply_input_selection, find_input_snapshot, write_input_selection
from core.reporting.service import complete_reporting
from core.reporting.writer import load_committed_report
from core.reporting.delta import build_delta
from core.run.metadata import start_run, fail_run, resume_run, load_run_metadata


@pytest.fixture(autouse=True)
def owner_environment(monkeypatch, tmp_path):
    from core.testing.state_isolation import pin_user_state_dirs
    from core.run import metadata, provenance
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    monkeypatch.setattr(metadata, "_get_session_pid", lambda: None)
    monkeypatch.setattr(provenance, "build_start_manifest", lambda **kwargs: {"target": {"source": "directory"}})


def sarif(directory):
    directory.mkdir(exist_ok=True, parents=True)
    data = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "fixture"}}, "results": [
        {"ruleId": "fixture/command-injection", "level": "warning", "message": {"text": "scanner claim"},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.c"}, "region": {"startLine": 2}}}]}]}]}
    source = directory / "combined.sarif"
    save_json(source, data)
    return source, data


def scan(directory, count=1):
    start_run(directory, "scan", target="src")
    source, data = sarif(directory)
    if count > 1:
        extra = deepcopy(data["runs"][0]["results"][0])
        extra["locations"][0]["physicalLocation"]["region"]["startLine"] = 9
        data["runs"][0]["results"].append(extra)
        save_json(source, data)
    context = context_from_sarif([source], target="src", run_id=directory.name)
    apply_lifecycle(context, directory, scope={"mode": "scanner-invocation", "target": "src"})
    complete_reporting(context, directory)
    fail_run(directory, error="fixture stop")
    return context, source, data


def test_reentrant_start_and_resume_preserve_attempt_but_pin_checkpoint(tmp_path):
    directory = tmp_path / "run"
    initial, _, _ = scan(directory)
    assert resume_run(directory) == 2
    identity = load_run_metadata(directory)["reporting_identity"]
    assert identity["continuation"]["snapshot_id"] == initial.snapshot_id
    start_run(directory, "scan", target="src")
    after = load_run_metadata(directory)
    assert after["reporting_identity"] == identity
    assert len(after["extra"]["resumes"]) == 1
    assert identity["run_id"] == initial.run_id and identity["attempt_id"] == initial.attempt_id
    source, _ = sarif(directory)
    current = context_from_sarif([source], target="src", run_id="ignored")
    apply_lifecycle(current, directory)
    assert initial.snapshot_id in current.parents
    assert current.attempt_id == initial.attempt_id


def test_explicit_retry_is_a_new_attempt_not_inferred_supersession(tmp_path):
    initial, _, _ = scan(tmp_path / "first")
    start_run(tmp_path / "retry", "scan", target="src", retry_of=tmp_path / "first")
    identity = load_run_metadata(tmp_path / "retry")["reporting_identity"]
    assert identity["pass_id"] == initial.pass_id
    assert identity["run_id"] != initial.run_id and identity["attempt_id"] != initial.attempt_id
    assert identity["retry_of"]["checkpoint"]["snapshot_id"] == initial.snapshot_id
    assert "supersedes" not in identity
    start_run(tmp_path / "fresh", "scan", target="src")
    assert load_run_metadata(tmp_path / "fresh")["reporting_identity"]["pass_id"] != initial.pass_id


def test_ordinary_restart_does_not_reuse_observation_identity(tmp_path):
    directory = tmp_path / "same-output"
    before, source, _ = scan(directory)
    start_run(directory, "scan", target="src")
    after = context_from_sarif([source], target="src", run_id=directory.name)
    apply_lifecycle(after, directory)
    assert before.attempt_id != after.attempt_id
    assert before.findings[0]["occurrence_ref"] != after.findings[0]["occurrence_ref"]
    assert not after.parents


def validate_import(directory, source, data, selected=None):
    from packages.exploitability_validation.orchestrator import convert_sarif_data
    start_run(directory, "validate", target="src")
    binding = find_input_snapshot(source, data)
    assert binding
    payload = convert_sarif_data(data, "src", source_binding=binding)
    if selected is not None:
        payload["findings"] = [payload["findings"][index] for index in selected]
    write_input_selection(directory, payload, binding)
    for finding in payload["findings"]:
        finding.update(status="confirmed", final_status="confirmed", function="parse")
    save_json(directory / "findings.json", payload)
    context = ReportContext("validate", directory.name, target="src", state="completed",
                            findings=native_findings(payload["findings"], run_id=directory.name, producer="validate"))
    context.extensions["raptor.validation"] = payload
    apply_lifecycle(context, directory)
    apply_input_selection(context, directory)
    complete_reporting(context, directory)
    fail_run(directory, error="fixture stop")
    return context


def test_scan_to_validation_records_selected_occurrences_and_verdict_delta(tmp_path):
    baseline, source, data = scan(tmp_path / "scan")
    candidate = validate_import(tmp_path / "validation", source, data)
    assert baseline.snapshot_id in candidate.parents
    link = candidate.extensions["raptor.lineage"][candidate.findings[0]["occurrence_ref"]]
    assert link["occurrence_ref"] == baseline.findings[0]["occurrence_ref"]
    delta, _ = build_delta(baseline, candidate)
    changes = delta.extensions["raptor.delta"]["changes"]
    assert len(changes) == 1 and changes[0][1].startswith("changed:")
    assert changes[0][2:] == ["Unconfirmed", "Confirmed"]
    assert candidate.extensions["raptor.scope"]["mode"] == "selected-findings"


def test_changed_input_and_forged_inline_relationships_do_not_match(tmp_path):
    _, source, data = scan(tmp_path / "scan")
    altered = deepcopy(data)
    altered["runs"][0]["results"][0]["message"]["text"] = "different input"
    assert find_input_snapshot(source, altered) is None
    from core.reporting.lifecycle import bind_native_input
    rows = {"findings": [{"id": "F", "_reporting_source": {"snapshot_id": "forged", "occurrence_ref": "forged"}}]}
    bind_native_input(rows, None)
    assert "_reporting_source" not in rows["findings"][0]


def test_project_counts_scan_and_targeted_validation_once(tmp_path, monkeypatch):
    import core.project.report as reports
    baseline, source, data = scan(tmp_path / "scan")
    candidate = validate_import(tmp_path / "validation", source, data)
    project = SimpleNamespace(name="P", output_path=tmp_path / "project", get_run_dirs=lambda **kwargs: [tmp_path / "validation", tmp_path / "scan"])
    monkeypatch.setattr(reports, "gather_project_annotations", lambda _: [])
    stats = reports.generate_project_report(project)
    assert stats["findings"] == 1
    context, _, _ = load_committed_report(project.output_path / "_report")
    assert context.findings[0]["status"] == "Confirmed"
    assert set(context.parents) == {baseline.snapshot_id, candidate.snapshot_id}
    selection = context.extensions["raptor.project"]["selection"]
    assert all(s["lifecycle"]["pass_id"] for s in selection)


def test_resume_verdict_delta_uses_same_attempt_producer_identity(tmp_path):
    directory = tmp_path / "validation"
    start_run(directory, "validate", target="src")
    first = ReportContext("validate", "placeholder", target="src", state="completed",
                          findings=native_findings([{"id": "FIND-1", "file": "a.c", "line": 2, "status": "not_disproven"}], producer="validate", run_id="placeholder"))
    apply_lifecycle(first, directory)
    complete_reporting(first, directory)
    fail_run(directory, error="interrupted")
    resume_run(directory)
    second = ReportContext("validate", "placeholder", target="src", state="completed",
                           findings=native_findings([{"id": "FIND-1", "file": "a.c", "line": 2, "status": "confirmed"}], producer="validate", run_id="placeholder"))
    apply_lifecycle(second, directory)
    assert second.attempt_id == first.attempt_id
    delta, _ = build_delta(first, second)
    assert delta.extensions["raptor.delta"]["changes"][0][1].startswith("changed:")


def test_unmanaged_python_reporting_does_not_create_a_lifecycle(tmp_path):
    context = ReportContext("scan", "explicit", target="src")
    apply_lifecycle(context, tmp_path)
    assert not (tmp_path / ".raptor-run.json").exists()
    assert context.run_id == "explicit" and not context.pass_id
    assert any("unknown" in d for d in context.diagnostics)


def project_view(tmp_path, monkeypatch, directories):
    import core.project.report as reports
    project = SimpleNamespace(name="P", output_path=tmp_path / "project", get_run_dirs=lambda **kwargs: directories)
    monkeypatch.setattr(reports, "gather_project_annotations", lambda _: [])
    stats = reports.generate_project_report(project)
    context, _, _ = load_committed_report(project.output_path / "_report")
    return stats, context


@pytest.mark.parametrize("relocate", [False, True])
def test_same_directory_targeted_validation_keeps_unselected_scan_observations(tmp_path, monkeypatch, relocate):
    directory = tmp_path / "run"
    baseline, source, data = scan(directory, count=2)
    candidate = validate_import(directory, source, data, selected=[0])
    if relocate:
        moved = tmp_path / "moved"
        directory.rename(moved)
        directory = moved
    stats, context = project_view(tmp_path, monkeypatch, [directory])
    assert stats["runs"] == 1 and stats["historical_snapshots"] == 1
    assert stats["findings"] == 2
    assert {f["line"]: f["status"] for f in context.findings} == {2: "Confirmed", 9: "Unconfirmed"}
    assert set(context.parents) == {baseline.snapshot_id, candidate.snapshot_id}
    assert any(s["historical"] for s in context.extensions["raptor.project"]["selection"])


def test_project_uses_captured_rows_instead_of_later_live_changes(tmp_path, monkeypatch):
    _, source, data = scan(tmp_path / "scan")
    directory = tmp_path / "validation"
    validate_import(directory, source, data)
    save_json(directory / "findings.json", {"findings": []})
    stats, context = project_view(tmp_path, monkeypatch, [directory])
    assert stats["findings"] == 1 and context.findings[0]["status"] == "Confirmed"


def test_missing_history_is_diagnosed_without_discovering_other_generations(tmp_path, monkeypatch):
    from core.project import report_lineage
    directory = tmp_path / "run"
    _, source, data = scan(directory, count=2)
    candidate = validate_import(directory, source, data, selected=[0])
    monkeypatch.setattr("core.reporting.writer.load_report_generation", lambda *args: (_ for _ in ()).throw(ValueError("missing")))
    history, diagnostics = report_lineage.local_history(directory, candidate)
    assert not history and any("unavailable" in note for note in diagnostics)


def test_new_execution_can_record_same_directory_predecessor(tmp_path):
    directory = tmp_path / "run"
    previous, _, _ = scan(directory)
    start_run(directory, "validate", target="src", parent_run=directory)
    identity = load_run_metadata(directory)["reporting_identity"]
    assert identity["run_id"] != previous.run_id
    assert identity["parent_execution"]["checkpoint"]["snapshot_id"] == previous.snapshot_id
    with pytest.raises(ValueError, match="own parent"):
        start_run(directory, "validate", target="src", parent_run=directory)


def test_owner_projection_is_idempotent(tmp_path):
    context, _, _ = scan(tmp_path / "scan")
    snapshot = context.snapshot_id
    apply_lifecycle(context, tmp_path / "scan")
    assert context.snapshot_id == snapshot


def test_stale_input_selection_does_not_attach_to_a_new_attempt(tmp_path):
    _, source, data = scan(tmp_path / "scan")
    directory = tmp_path / "validation"
    previous = validate_import(directory, source, data)
    start_run(directory, "validate", target="src")
    context = ReportContext("validate", "new", findings=deepcopy(previous.findings))
    apply_lifecycle(context, directory)
    apply_input_selection(context, directory)
    assert "raptor.lineage" not in context.extensions
    assert any("another lifecycle" in note for note in context.diagnostics)


def test_delta_explicit_alias_cannot_double_consume_exact_match():
    baseline = ReportContext("validate", "before", findings=native_findings([{"id": "one", "status": "not_disproven"}], run_id="before", producer="validate"))
    original = baseline.findings[0]
    candidate = ReportContext("validate", "after", findings=[deepcopy(original), {**deepcopy(original), "occurrence_ref": "new", "status": "Confirmed"}])
    delta, _ = build_delta(baseline, candidate, lineage={"new": original["occurrence_ref"]})
    assert all(row[1] == "uncertain match" for row in delta.extensions["raptor.delta"]["changes"])


def test_conflicting_recorded_lineage_does_not_choose_a_parent():
    baseline = ReportContext("validate", "before", findings=native_findings([{"id": "one"}, {"id": "two"}], run_id="before", producer="validate"))
    candidate = ReportContext("validate", "after", findings=[{**deepcopy(baseline.findings[0]), "occurrence_ref": "new"}])
    for field, finding in zip(("raptor.lineage", "raptor.continuation_lineage"), baseline.findings):
        candidate.extensions[field] = {"new": {"snapshot_id": baseline.snapshot_id, "occurrence_ref": finding["occurrence_ref"]}}
    delta, _ = build_delta(baseline, candidate)
    assert delta.extensions["raptor.delta"]["changes"][0][1] == "uncertain match"


def test_retry_bootstrap_preserves_existing_attempt(tmp_path):
    _, _, _ = scan(tmp_path / "first")
    directory = tmp_path / "retry"
    start_run(directory, "scan", target="src", retry_of=tmp_path / "first")
    initial = load_run_metadata(directory)["reporting_identity"]
    start_run(directory, "scan", target="src", retry_of=tmp_path / "first")
    assert load_run_metadata(directory)["reporting_identity"] == initial
    with pytest.raises(ValueError, match="cannot change"):
        start_run(directory, "scan", target="src", retry_of=tmp_path / "other")


def test_selection_sidecar_cannot_replace_input_evidence(tmp_path):
    source = tmp_path / "reporting-input.json"
    original = b'{"findings": []}'
    source.write_bytes(original)
    with pytest.raises(ValueError, match="source findings"):
        write_input_selection(tmp_path, {"findings": []}, None, source_path=source)
    assert source.read_bytes() == original


def test_duplicate_snapshot_copy_is_not_another_population(tmp_path, monkeypatch):
    import shutil
    scan(tmp_path / "scan")
    shutil.copytree(tmp_path / "scan", tmp_path / "copy")
    stats, context = project_view(tmp_path, monkeypatch, [tmp_path / "copy", tmp_path / "scan"])
    assert stats["runs"] == 1 and stats["findings"] == 1
    assert any("duplicate captured" in d for d in context.diagnostics)


def test_imported_snapshot_does_not_pull_local_history(tmp_path, monkeypatch):
    directory = tmp_path / "imported"
    _, source, data = scan(directory, count=2)
    validate_import(directory, source, data, selected=[0])
    save_json(directory / ".raptor-imported.json", {"imported": True})
    stats, context = project_view(tmp_path, monkeypatch, [directory])
    assert stats["historical_snapshots"] == 0
    assert context.extensions["raptor.project"]["selection"][0]["imported"]


def test_agentic_child_has_explicit_parent_execution_identity(tmp_path):
    directory = tmp_path / "agentic"
    start_run(directory, "agentic", target="src")
    parent = load_run_metadata(directory)["reporting_identity"]
    start_run(tmp_path / "child", "validate", target="src", parent_run=directory)
    child = load_run_metadata(tmp_path / "child")["reporting_identity"]
    assert child["parent_execution"]["run_id"] == parent["run_id"]
    assert child["pass_id"] != parent["pass_id"]
    assert child["parent_execution"]["checkpoint"] is None


def test_unmanaged_capture_cannot_reuse_owned_input_selection(tmp_path):
    _, source, data = scan(tmp_path / "scan")
    directory = tmp_path / "validation"
    validate_import(directory, source, data)
    context = ReportContext("agentic", "unmanaged")
    apply_input_selection(context, directory)
    assert "raptor.input_selection" not in context.extensions
    assert any("another lifecycle" in note for note in context.diagnostics)


def test_inventory_invocation_clears_prior_selection_without_following_links(tmp_path):
    from core.reporting.lifecycle import clear_input_selection
    target = tmp_path / "evidence.json"
    target.write_text("retained evidence")
    (tmp_path / "reporting-input.json").symlink_to(target)
    clear_input_selection(tmp_path)
    assert target.read_text() == "retained evidence"
    context = ReportContext("validate", "inventory")
    apply_input_selection(context, tmp_path)
    assert "raptor.input_selection" not in context.extensions


@pytest.mark.parametrize("has_native", [False, True])
def test_project_does_not_attribute_a_prior_report_to_a_new_execution(tmp_path, monkeypatch, has_native):
    directory = tmp_path / "run"
    scan(directory)
    start_run(directory, "scan", target="src")
    if has_native:
        save_json(directory / "findings.json", {"findings": [{"id": "fresh", "file": "new.c", "line": 4, "status": "not_disproven"}]})
    fail_run(directory, error="fixture reporting unavailable")
    stats, context = project_view(tmp_path, monkeypatch, [directory])
    assert stats["findings"] == int(has_native)
    assert not context.parents
    assert any("earlier execution" in d for d in context.diagnostics)
    if has_native:
        assert context.findings[0]["file"] == "new.c"


def test_project_lineage_cycles_do_not_choose_an_ancestor():
    from core.project.report_lineage import grouping_keys
    rows = {name: [{"id": name, "file": "a.c", "line": 1, "function": name}] for name in ("a", "b")}
    contexts = {name: ReportContext("validate", name, findings=native_findings(records, producer="validate", run_id=name)) for name, records in rows.items()}
    refs = {name: context.findings[0]["occurrence_ref"] for name, context in contexts.items()}
    # Snapshot hashes include lineage, so a cyclic snapshot relationship cannot
    # be self-consistently constructed. An invalid parent hash must be refused.
    contexts["a"].extensions["raptor.lineage"] = {refs["a"]: {"snapshot_id": contexts["b"].snapshot_id, "occurrence_ref": refs["b"]}}
    contexts["b"].extensions["raptor.lineage"] = {refs["b"]: {"snapshot_id": contexts["a"].snapshot_id, "occurrence_ref": refs["a"]}}
    keys, diagnostics = grouping_keys(rows, contexts, {"a": False, "b": False})
    assert any("outside the selected" in d for d in diagnostics)
    # Refusal must not erase observations, even when another valid link exists.
    assert len(keys) == 2

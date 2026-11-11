"""Real claim observation, publisher and saved comparison inputs; no analysis dispatch."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json

import pytest

from core.audit import claim_comparison_inputs as module
from core.audit.check_trace import CLAIM_OBSERVATIONS_FILENAME, record_claim_observations
from core.audit.claim_adjudication import SHADOW_FILENAME
from core.audit.claim_verification import ClaimVerification
from core.audit.findings_export import export_findings, write_graded_findings
from core.audit.record import AUDIT_LOG_FILENAME
from .test_claim_comparison_inputs import history_case  # noqa: F401 -- imported pytest fixture


def _publish(tmp_path, case, *, clean=False):
    outcome, revision, history = case
    if clean:
        outcome.status = "clean"
    out = tmp_path / "out"
    out.mkdir()
    record_claim_observations(out, file=revision.file, function=revision.function,
                              line_start=revision.line_start,
                              verifications=[ClaimVerification(revision.hypothesis, claim_revision=revision)])
    export = export_findings([outcome])
    before = asdict(outcome), deepcopy(export["stats"]), (out / AUDIT_LOG_FILENAME).read_bytes()
    write_graded_findings(export, out)
    return outcome, revision, history, out, export, before


@pytest.mark.parametrize("clean", [False, True])
def test_actual_publisher_pairs_exact_definition_without_changing_assessment(tmp_path, history_case, clean):  # noqa: F811 -- imported fixture
    outcome, revision, _, out, export, before = _publish(tmp_path, history_case, clean=clean)
    payload = json.loads((out / module.FILENAME).read_bytes())
    observations = json.loads((out / CLAIM_OBSERVATIONS_FILENAME).read_bytes())
    shadow = json.loads((out / SHADOW_FILENAME).read_bytes())
    pair, = payload["pairs"]
    assert pair["claim_reference"] == revision.event_reference()
    assert pair["definition_sha256"] == observations["claim_index"]["claims"][0]["definition_sha256"]
    assert pair["shadow_state"] == shadow["claims"][0]["state"]
    assert pair["legacy_status"] == ("clean" if clean else "suspicious")
    assert pair["legacy_pointer"]["collection"] == ("clean_review_traces" if clean else "findings")
    assert pair["review_status"] == "manual_review_required" and pair["authoritative"] is False
    assert pair["current_context_correspondence"] == "not_evaluated"
    assert payload["history_complete"] is False and payload["unavailable"] == []
    for filename in (CLAIM_OBSERVATIONS_FILENAME, SHADOW_FILENAME):
        assert payload["inputs"][filename]["sha256"] == hashlib.sha256((out / filename).read_bytes()).hexdigest()
    assert (asdict(outcome), export["stats"], (out / AUDIT_LOG_FILENAME).read_bytes()) == before
    assert json.loads((out / "findings-graded.json").read_bytes())["stats"] == before[1]


@pytest.mark.parametrize("changed", ["digest", "missing_digest", "shadow_conflict", "index_owner", "shadow_owner", "malformed_owner"])
def test_mismatched_or_ambiguous_counterpart_cannot_join(tmp_path, history_case, changed):  # noqa: F811 -- imported fixture
    _, _, _, out, export, _ = _publish(tmp_path, history_case)
    path = out / (SHADOW_FILENAME if changed in {"shadow_conflict", "shadow_owner"} else CLAIM_OBSERVATIONS_FILENAME)
    value = json.loads(path.read_bytes())
    if changed in {"index_owner", "shadow_owner", "malformed_owner"}:
        rows = value["claims"] if changed == "shadow_owner" else value["claim_index"]["claims"]
        conflicting = deepcopy(rows[0])
        reference = conflicting if changed == "shadow_owner" else conflicting["claim_reference"]
        reference["claim_id"] = "not-an-id" if changed == "malformed_owner" else "1" * 32
        rows.append(conflicting)
    elif changed == "shadow_conflict":
        conflicting = deepcopy(value["claims"][0])
        conflicting["state"] = "supported"
        value["claims"].append(conflicting)
    elif changed == "missing_digest":
        value["claim_index"]["claims"][0].pop("definition_sha256")
    else:
        value["claim_index"]["claims"][0]["definition_sha256"] = "0" * 64
    path.write_text(json.dumps(value))
    metadata = module.write_comparison_inputs(export, out)
    payload = json.loads((out / module.FILENAME).read_bytes())
    assert metadata["status"] == "recorded" and payload["pairs"] == []
    assert len(payload["unavailable"]) == 1


@pytest.mark.parametrize("failed", ["observations", "shadow"])
def test_current_export_failure_does_not_revive_stale_artifacts(tmp_path, history_case, monkeypatch, failed):  # noqa: F811 -- imported fixture
    _, _, _, out, export, _ = _publish(tmp_path, history_case)
    previous = (out / module.FILENAME).read_bytes()
    from core.audit import check_trace

    original_save = check_trace.save_json
    fail_name = CLAIM_OBSERVATIONS_FILENAME if failed == "observations" else SHADOW_FILENAME

    def fail_current(path, *args, **kwargs):
        if path.name == fail_name:
            raise OSError("owned current export failed")
        return original_save(path, *args, **kwargs)

    monkeypatch.setattr(check_trace, "save_json", fail_current)

    def forbidden(*args):
        pytest.fail("stale comparison files were read after this export failed")

    monkeypatch.setattr(module, "_read_input", forbidden)
    write_graded_findings(export, out)
    assert export["claim_comparison_inputs"]["status"] == "unavailable"
    actual = json.loads((out / "findings-graded.json").read_bytes())
    assert actual["claim_comparison_inputs"]["status"] == "unavailable"
    assert (out / module.FILENAME).read_bytes() == previous


def test_comparison_write_failure_preserves_native_export_and_marks_unavailable(tmp_path, history_case, monkeypatch):  # noqa: F811 -- imported fixture
    _, _, _, out, export, before = _publish(tmp_path, history_case)
    previous = (out / module.FILENAME).read_bytes()
    native = deepcopy(export["findings"])

    def fail(*args, **kwargs):
        raise OSError("owned comparison output unavailable")

    monkeypatch.setattr(module, "save_json", fail)
    write_graded_findings(export, out)
    actual = json.loads((out / "findings-graded.json").read_bytes())
    assert actual["claim_comparison_inputs"]["status"] == "unavailable"
    assert actual["stats"] == before[1] and actual["findings"] == native
    assert (out / module.FILENAME).read_bytes() == previous
    assert (out / AUDIT_LOG_FILENAME).read_bytes() == before[2]


def test_bounded_pairs_disclose_omissions(tmp_path, history_case, monkeypatch):  # noqa: F811 -- imported fixture
    _, _, _, out, export, _ = _publish(tmp_path, history_case)
    export["findings"] *= 3
    before = deepcopy(export)
    monkeypatch.setattr(module, "MAX_ROWS", 2)
    module.write_comparison_inputs(export, out)
    payload = json.loads((out / module.FILENAME).read_bytes())
    assert len(payload["pairs"]) == 2 and payload["observed_legacy_records"] == 3
    assert payload["omitted_legacy_records"] == 1
    assert export == before


def test_relative_output_and_input_caps_use_owned_complete_bytes(tmp_path, history_case, monkeypatch):  # noqa: F811 -- imported fixture
    _, _, _, out, export, _ = _publish(tmp_path, history_case)
    monkeypatch.chdir(tmp_path)
    assert module.write_comparison_inputs(export, out.relative_to(tmp_path))["status"] == "recorded"
    monkeypatch.setattr(module, "MAX_INPUT_BYTES", 16)
    assert module.write_comparison_inputs(export, out)["status"] == "unavailable"


def test_actual_intake_allocates_the_compared_identity_without_analysis_dispatch(tmp_path, history_case):  # noqa: F811 -- imported fixture
    from core.audit import orchestrator as orch
    from core.audit.record import load_verified_audit_log
    from core.testing.module_views import module_function_view

    outcome, old_revision, _ = history_case
    out = tmp_path / "live-intake"
    out.mkdir()
    config = orch.OrchestratorConfig(tmp_path, out)
    reached = []

    def no_chain(*args, **kwargs):
        reached.append("mapped")
        return []

    def forbidden(*args, **kwargs):
        pytest.fail("comparison control dispatched analysis or a model")

    view = module_function_view(orch, bindings={
        "_hypothesis_to_tool_chain": no_chain,
        "_get_llm_client": lambda *args: None,
        "_gather_library_candidates": lambda *args: [],
        "_correlated_mech_detector_tool": lambda *args: None,
        "_ihv_context_gate": lambda *args, **kwargs: None,
        "_run_tool_chain": forbidden,
    })
    view._verify_hypotheses_immediate(outcome, config, orch.OrchestratorResult(),
                                      source=(tmp_path / "unit.c").read_text())
    assert reached == ["mapped"]
    events = load_verified_audit_log(out)
    intake, = [row for row in events if row.get("action") == "ihv_claim_observations"]
    reference = {key: intake["claim_revisions"][0][key] for key in ("claim_id", "revision_id")}
    assert reference != old_revision.event_reference()
    before = (out / AUDIT_LOG_FILENAME).read_bytes()
    status = outcome.status
    export = export_findings([outcome])
    stats = deepcopy(export["stats"])
    write_graded_findings(export, out)
    payload = json.loads((out / module.FILENAME).read_bytes())
    pair, = payload["pairs"]
    assert pair["claim_reference"] == reference
    assert pair["legacy_status"] == status
    assert outcome.status == status and export["stats"] == stats
    assert (out / AUDIT_LOG_FILENAME).read_bytes() == before


@pytest.mark.parametrize("changed", ["symlink", "duplicate_key", "schema_bool"])
def test_comparison_requires_complete_regular_unambiguous_json(tmp_path, history_case, changed):  # noqa: F811 -- imported fixture
    _, _, _, out, export, _ = _publish(tmp_path, history_case)
    path = out / CLAIM_OBSERVATIONS_FILENAME
    before = path.read_bytes()
    if changed == "symlink":
        saved = out / "saved-observations.json"
        saved.write_bytes(before)
        path.unlink()
        path.symlink_to(saved)
    elif changed == "duplicate_key":
        value = json.loads(before)
        path.write_text('{"schema_version":1,' + json.dumps(value)[1:])
    else:
        value = json.loads(before)
        value["schema_version"] = True
        path.write_text(json.dumps(value))
    assert module.write_comparison_inputs(export, out)["status"] == "unavailable"


def test_comparison_does_not_copy_private_history_context(tmp_path, history_case):  # noqa: F811 -- imported fixture
    history_case[2]["reference_inputs"] = {"question": "PRIVATE_HISTORY_CONTEXT_NOT_FOR_COMPARISON"}
    _, _, _, out, _, _ = _publish(tmp_path, history_case)
    for filename in (module.FILENAME, "findings-graded.json"):
        assert b"PRIVATE_HISTORY_CONTEXT_NOT_FOR_COMPARISON" not in (out / filename).read_bytes()

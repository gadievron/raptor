"""Native aliases bind explicit producer identities before snapshot construction."""
from copy import deepcopy

import pytest

from core.json import save_json
from core.reporting.document import ReportContext, StageEnvelope
from core.reporting.lifecycle import apply_lifecycle
from core.reporting.results import NativeResult, complete_native_result
from core.reporting.writer import load_committed_report
from core.run.report_identity import fresh_identity


def _metadata(tmp_path, command="understand"):
    identity = fresh_identity()
    save_json(tmp_path / ".raptor-run.json", {"command": command, "reporting_identity": identity,
                                               "manifest": {"target": {"sha256": "a" * 64}}})
    return identity


def test_native_alias_binds_actual_identity_before_document_digest_without_mutating_stages(tmp_path):
    identity = _metadata(tmp_path)
    stage = StageEnvelope("mechanical map", "completed", run_id="producer-local")
    result = NativeResult("binary-map", "target", "unknown", {}, stages=[stage], lifecycle_dir=tmp_path,
                          lifecycle_producer="understand")
    context, document = result.build()
    assert (context.run_id, context.pass_id, context.attempt_id) == tuple(identity[key] for key in ("run_id", "pass_id", "attempt_id"))
    assert document.snapshot_id == context.snapshot_id
    assert context.stages[0].run_id == identity["run_id"] and stage.run_id == "producer-local"
    assert context.extensions["raptor.lifecycle.producer_command"] == "understand"
    assert context.extensions["raptor.source_identity"] == {"sha256": "a" * 64}


def test_native_alias_does_not_adopt_a_different_producer_metadata(tmp_path):
    _metadata(tmp_path, command="scan")
    context, _ = NativeResult("binary-map", "target", "unknown", {}, lifecycle_dir=tmp_path,
                              lifecycle_producer="understand").build()
    assert context.run_id == "unknown" and context.pass_id == context.attempt_id == ""
    assert "raptor.lifecycle" not in context.extensions
    assert any("lineage is unknown" in note for note in context.diagnostics)


def test_alias_is_not_inferred_from_directory_or_report_kind(tmp_path):
    _metadata(tmp_path)
    context, _ = NativeResult("binary-map", "target", "unknown", {}, lifecycle_dir=tmp_path).build()
    assert context.pass_id == "" and "raptor.lifecycle" not in context.extensions


def test_native_lifecycle_omission_keeps_existing_pure_build_behavior(tmp_path):
    _metadata(tmp_path)
    context, _ = NativeResult("understand", "target", "caller-id", {}).build()
    assert context.run_id == "caller-id" and not context.diagnostics


def test_explicit_alias_preserves_input_metadata_and_rejects_empty_command(tmp_path):
    identity = fresh_identity()
    metadata = {"command": "understand", "reporting_identity": identity}
    before = deepcopy(metadata)
    context = ReportContext("binary-map", "unknown")
    apply_lifecycle(context, tmp_path, metadata=metadata, producer_command="understand")
    assert metadata == before
    with pytest.raises(ValueError, match="nonempty"):
        apply_lifecycle(ReportContext("binary-map", "unknown"), tmp_path, metadata=metadata, producer_command="")


def test_published_native_alias_context_and_document_share_bound_snapshot(tmp_path):
    identity = _metadata(tmp_path)
    result = NativeResult("binary-map", "target", "unknown", {"native count": 2}, lifecycle_dir=tmp_path,
                          lifecycle_producer="understand")
    publication = complete_native_result(result, tmp_path, stem="binary-map")
    assert not publication.errors
    context, document, _ = load_committed_report(tmp_path)
    assert context.run_id == identity["run_id"] and context.snapshot_id == document.snapshot_id

"""Persist delivery separately from assessments and verification authority."""

import json

from core.audit.tests.test_knowledge_runtime_coordinator import _runtime


def test_trace_retains_omission_and_failure_without_claiming_model_use(tmp_path):
    runtime, ctx = _runtime(tmp_path)
    reservation = runtime.ready_continuations(admission=lambda: True)[0]
    request_id = reservation.packet.references[0].request_id
    ctx["language_reference_delivery"] = [{"request_id": request_id, "delivered": False,
                                           "reason": "token_budget"}]
    assert runtime.enrich_context(ctx, reservation)
    assert runtime.fail(reservation, "scripted_failure", ctx)
    out = tmp_path / "out"
    out.mkdir()
    runtime.write_artifacts(out)
    payload = json.loads((out / "knowledge-results.json").read_text())
    assert payload["role"] == "context_provenance_not_verification_evidence"
    prompt = [row for row in payload["events"] if row["event"] == "review_prompt_context"][0]
    assert prompt["records"][0]["delivered"] is False
    assert prompt["records"][0]["request_id"] == request_id
    failed = [row for row in payload["events"] if row["event"] == "continuation_failed"][0]
    assert failed["pass_id"] == reservation.packet.pass_id
    assert failed["published_status"] == ""
    before = (out / "audit-log.jsonl").read_bytes() if (out / "audit-log.jsonl").exists() else None
    runtime.write_artifacts(out)
    if before is not None:
        assert (out / "audit-log.jsonl").read_bytes() == before

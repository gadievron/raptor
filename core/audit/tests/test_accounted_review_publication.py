"""Actual SDK accounting remains joined to continuation publication."""

import hashlib
import json

import pytest

from core.audit import capabilities, orchestrator
from core.audit.llm_review import REVIEW_SCHEMA, make_review_fn
from core.audit.journal import load_entries
from core.audit.record import load_verified_audit_log
from core.audit.review_claims import read_history
from core.audit.orchestrator import OrchestratorConfig, run_orchestrator
from core.inventory import save_checklist
from core.llm.tests.test_prepared_attempt_reservation import sdk_clients as sdk_clients


@pytest.mark.slow
@pytest.mark.parametrize("journal_failure,omit_options,source_race",
                         [(False, False, False), (True, False, False), (False, True, False), (False, False, True)],
                         ids=["published", "journal-refused", "optional-omissions", "source-restored"])
def test_sdk_charge_and_continuation_share_durable_review_pass(tmp_path, monkeypatch, sdk_clients, journal_failure, omit_options, source_race):
    # This boundary is the real ready graph, Runtime and SDK request hook.
    # Optional detector/server/study work is outside this direct-review case.
    monkeypatch.setattr(orchestrator, "_run_mechanical_detectors", lambda *a, **k: ({}, set()))
    monkeypatch.setattr(capabilities, "probe_capabilities", lambda *a, **k: capabilities.AuditCapabilities())
    monkeypatch.setattr(orchestrator, "_study_consumer", lambda *a, **k: None)
    monkeypatch.setattr(orchestrator, "_check_layer_disagreement", lambda *a, **k: None)

    target, out = tmp_path / "target", tmp_path / "out"
    target.mkdir()
    source = "int f(int x) { return x; }\n"
    path = target / "unit.c"
    path.write_text(source)
    save_checklist(out, {"target_path": str(target), "files": [{"path": "unit.c", "language": "c",
        "items": [{"name": "f", "kind": "function", "line_start": 1, "line_end": 1}]}]})
    bundle = sdk_clients(cap=20.0, token_cap=1000000, run_dir=out)
    payloads = [
        {"status": "clean", "body": "Initial conditional assessment", "language_reference_requests": [
            {"topic": "integer shifts", "entry_id": "c.integer-shift", "needed_for": "Interpret shift preconditions", "priority": "normal"}]},
        {"status": "clean", "body": "Reviewed with delivered shift reference", "language_reference_requests": []},
    ]

    if omit_options:
        request = payloads[0]["language_reference_requests"][0]
        del request["entry_id"]
        del request["priority"]

    def response(row):
        payload = payloads[len(bundle.state["requests"]) - 1]
        message = row["choices"][0]["message"]
        if message.get("tool_calls"):
            message["tool_calls"][0]["function"]["arguments"] = json.dumps(payload)
        else:
            message["content"] = json.dumps(payload)
        return row

    admitted_before_wire = []

    def check_prepared_admission(request):
        rows = [r for r in load_verified_audit_log(out) if r.get("stage") == "admitted"]
        assert len(rows) == len(bundle.state["requests"])
        admitted_before_wire.append(rows[-1]["attempt"])
        if source_race and len(bundle.state["requests"]) == 2:
            # Real bytes return to their original digest, but the owned
            # physical source observation must remain invalidated.
            path.write_text(source + "/* changed during request */\n")
            path.write_text(source)

    bundle.state["handler"] = check_prepared_admission
    bundle.state["transform"] = response
    schema = {"type": "object", "properties": {
        key: REVIEW_SCHEMA["properties"][key] for key in ("status", "body", "language_reference_requests")},
        "required": ["status", "body", "language_reference_requests"]}
    review = make_review_fn(bundle.client, schema=schema,
                            system_prompt="Review the owned function.", escalate_clean=False)
    config = OrchestratorConfig(target_path=target, out_dir=out, review_passes=1,
        resume=False, max_workers=1, batch_sloc_threshold=0, prefilter=False,
        prefilter_skip=False, triage=False, vendored_triage=False,
        validate=False, sweep_validate_findings=False, deepen_suspicious=False,
        clean_check=False, adversarial=False, enable_session_context=False,
        propagate_constraints=False, on_demand_synthesis=False, open_discovery=False,
        joern_overrides={"enabled": False}, no_binary_oracle=True,
        iris=False, sage_recall=False, domain_model_import=False,
        dynamic_validation=False, library_replay=False, cross_run_import=False,
        annotations_read=False, llm_budget_client=bundle.client)
    if journal_failure:
        from core.audit import collector
        append = collector.append_entry
        writes = []

        def append_initial_only(*args, **kwargs):
            writes.append(1)
            if len(writes) == 2:
                raise OSError("owned continuation journal unavailable")
            return append(*args, **kwargs)

        monkeypatch.setattr(collector, "append_entry", append_initial_only)
    result = run_orchestrator(config, review)
    history = json.loads((out / "knowledge-results.json").read_text())
    completed = [e for e in history["events"] if e["event"] == "continuation_completed"]
    assert len(bundle.state["requests"]) == 2
    reserved = [e for e in history["events"] if e["event"] == "continuation_reserved"]
    assert len(reserved) == 1
    pass_id = reserved[0]["pass_id"]
    if journal_failure or source_race:
        assert completed == []
        failures = [e for e in history["events"] if e["event"] == "continuation_failed"]
        assert len(failures) == 1 and failures[0]["pass_id"] == pass_id
        assert failures[0]["reason"] == ("source_changed" if source_race else "candidate_journal_write_failed")
    else:
        assert len(completed) == 1
        assert completed[0]["published_status"] == "clean"
        assert completed[0]["delivered_request_ids"]
    signed = load_verified_audit_log(out)
    admitted = [r for r in signed if r.get("stage") == "admitted"]
    reported = [r for r in signed if r.get("stage") == "reported"]
    assert len(admitted) == len(reported) == 2
    assert {r["attempt"]["attempt_id"] for r in admitted} == {r["attempt"]["attempt_id"] for r in reported}
    assert admitted_before_wire == [r["attempt"] for r in admitted]
    continuation_attempt, = [r["attempt"] for r in admitted if r["attempt"]["work_id"] == "review:" + pass_id]
    assert continuation_attempt["beneficiaries"] == [pass_id]
    assert len({r["attempt"]["call_id"] for r in admitted}) == 2
    assert all(r["tokens_in"] == r["tokens_out"] == 3 and r["tokens_total"] == 6 for r in reported)
    assert bundle.client._governed_calls == 2
    assert bundle.client.pending_usage_reservations == []
    assert bundle.client.reported_spend_usd > 0
    assert result.total_cost_usd == pytest.approx(bundle.client.reported_spend_usd)
    entries = load_entries(out)
    assert len(entries) == (1 if journal_failure or source_race else 2)
    # A clean continuation adds delivered context/history; it does not
    # replace the previous assessment merely because another call ran.
    assert result.outcomes[0].body == payloads[0]["body"]
    history_rows = read_history(entries[-1].review_claims)
    assert history_rows == read_history(result.outcomes[0].review_result["review_claims"])
    reviews = [i["review"] for i in history_rows["intakes"] if i.get("review")]
    if history_rows.get("review"):
        reviews.append(history_rows["review"])
    assert (pass_id in {r["origin"]["pass_id"] for r in reviews}) is (not (journal_failure or source_race))
    from core.audit.source_anchor import parse_source_anchor
    assert parse_source_anchor(entries[-1].source_hash)[0] == hashlib.sha256(source.encode()).hexdigest()
    costs = json.loads((out / "cost-breakdown.json").read_text())
    projected = costs["attempt_accounting"]["attempts"]
    assert costs["attempt_accounting"]["status"] == "projected"
    assert costs["attempt_accounting"]["gaps"] == []
    assert len(projected) == 2
    assert {r["attempt_id"] for r in projected} == {r["attempt"]["attempt_id"] for r in admitted}
    assert sum(r["cost_usd"] for r in projected) == pytest.approx(bundle.client.reported_spend_usd)
    from core.audit.attempt_reservations import AttemptReservations
    before = load_verified_audit_log(out)
    recovered = AttemptReservations(out, resume=True)
    assert not recovered.gap and recovered.pending() == []
    assert len(recovered.reported()) == 2
    assert recovered.known_spend_usd == pytest.approx(bundle.client.reported_spend_usd)
    assert load_verified_audit_log(out) == before
    assert len(bundle.state["requests"]) == 2
    assert not result.publication_failures
    assert path.read_text() == source

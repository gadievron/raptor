"""Same-run recovery keeps unknown usage separate from billed spend."""
import json

import httpx
import pytest

from core.audit import pipeline
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, _persist_spend_floor
from core.audit.resume import resolve_prior_spend
from core.json.utils import save_json
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm import detection, http_pool, providers
from core.llm.prepared_admission import WIRE_HEADER
from core.run.report_identity import fresh_identity


@pytest.fixture
def setup_run(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from core.llm import transcript
    out = tmp_path / "run"
    out.mkdir()
    save_json(out / ".raptor-run.json", {"command": "audit", "status": "running",
        "reporting_identity": fresh_identity()})
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.setattr(providers, "_stream_transport_enabled", lambda: False)
    monkeypatch.setattr(detection, "detect_llm_availability", lambda: SimpleNamespace(external_llm=True))
    factory, opened = {}, []
    monkeypatch.setattr(http_pool, "_keepalive_transport_and_mounts",
        lambda **kwargs: (httpx.MockTransport(factory["respond"]), {}))

    def build(*args, **kwargs):
        state = {"requests": [], "handler": None,
                 "usage": {"prompt_tokens": 4, "completion_tokens": 2, "total_tokens": 6}}

        def respond(request):
            assert WIRE_HEADER not in request.headers
            state["requests"].append(request)
            if state["handler"] is not None:
                state["handler"](request)
            body = json.loads(request.content)
            return httpx.Response(200, request=request, json={
                "id": "captured-response", "object": "chat.completion", "created": 0,
                "model": body["model"], "choices": [{"index": 0,
                    "message": {"role": "assistant", "content": "captured"}, "finish_reason": "stop"}],
                "usage": state["usage"]})

        factory["respond"] = respond
        cfg = LLMConfig(primary_model=ModelConfig(provider="openai", model_name="gpt-4o",
            api_key="inert", api_base="https://scripted.invalid/v1", max_tokens=16),
            enable_caching=False, enable_fallback=False, max_retries=1, scorecard_enabled=False,
            cache_dir=tmp_path / "unused-cache", scorecard_path=tmp_path / "unused-scorecard")
        cfg.max_cost_per_scan = kwargs["config"].max_cost_per_scan
        client = LLMClient(cfg)
        opened.append(client.primary_provider)
        client._captured_wire = state
        return client

    monkeypatch.setattr(transcript, "build_llm_client", build)
    monkeypatch.setattr(pipeline, "_ensure_dispatcher_route", lambda *a, **k: None)
    try:
        yield out
    finally:
        for provider in opened:
            provider.client.close()


def test_same_run_unknown_hold_survives_client_reconstruction(setup_run, monkeypatch):
    out = setup_run
    client, _, _ = pipeline._make_llm_client(pipeline.AuditPipelineOpts(
        out_dir=out, max_cost_usd=1.0))
    _unknown(client)
    row, = client.pending_usage_reservations
    proposed = 1.0 - row["reservation_usd"] / 2
    assert not client._check_budget(proposed)
    config = OrchestratorConfig(target_path=out.parent, out_dir=out, llm_budget_client=client)
    _persist_spend_floor(config, OrchestratorResult(), force=True)
    billed, _ = resolve_prior_spend(out)
    assert billed == 0.0, "unknown reservations must not become reported spend"
    resumed, _, _ = pipeline._make_llm_client(pipeline.AuditPipelineOpts(
        out_dir=out, max_cost_usd=1.0 - billed, prior_booked_spend_usd=billed,
        same_run_reuse=True, resume_segment=2))
    assert not resumed._check_budget(proposed)
    assert resumed.pending_usage_reservations[0]["attempt_id"] == row["attempt_id"]
    assert resumed.total_cost == 0.0


def _make(out, **kwargs):
    return pipeline._make_llm_client(pipeline.AuditPipelineOpts(
        out_dir=out, max_cost_usd=1.0 - kwargs.get("prior_booked_spend_usd", 0), **kwargs))[0]


def _usage_cost(client, tokens_in=4, tokens_out=2):
    return client.primary_provider._calculate_cost_split(tokens_in, tokens_out)


def _unknown(client, *, provider_cost=0.0):
    def fail(request):
        client.primary_provider.total_cost += provider_cost
        raise httpx.ReadError("captured response body ended", request=request)
    client._captured_wire["handler"] = fail
    with pytest.raises(RuntimeError):
        client.generate("captured", call_class="review")
    return client.pending_usage_reservations[0]


def test_admission_is_durable_before_interrupted_provider(setup_run, monkeypatch):
    from core.audit.record import load_verified_audit_log
    client = _make(setup_run)
    admitted = []
    def interrupted(*args, **kwargs):
        rows = load_verified_audit_log(setup_run)
        row, = [r for r in rows if r.get("stage") == "admitted"]
        admitted.append(row["attempt"]["attempt_id"])
        raise KeyboardInterrupt("captured producer cancellation")
    client._captured_wire["handler"] = interrupted
    with pytest.raises(KeyboardInterrupt):
        client.generate("captured", call_class="review")
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    assert [r["attempt_id"] for r in resumed.pending_usage_reservations] == admitted
    assert resumed.total_cost == 0


def test_late_usage_is_idempotent_across_another_resume(setup_run, monkeypatch):
    client = _make(setup_run)
    cost = _usage_cost(client)
    row = _unknown(client)
    receipt = {"cost_usd": cost, "tokens_in": 4, "tokens_out": 2, "tokens_total": 6}
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    assert resumed.reconcile_pending_usage(row["attempt_id"], **receipt)
    assert not resumed.reconcile_pending_usage(row["attempt_id"], **receipt)
    assert resumed.total_cost == pytest.approx(cost) and resumed.pending_usage_reservations == []
    billed, _ = resolve_prior_spend(setup_run)
    assert billed == pytest.approx(cost)
    again = _make(setup_run, same_run_reuse=True, resume_segment=3, prior_booked_spend_usd=billed)
    baseline_cost = again.total_cost
    assert baseline_cost == pytest.approx(0, abs=1e-18)
    assert not again.reconcile_pending_usage(row["attempt_id"], **receipt)
    assert again.total_cost == baseline_cost
    with pytest.raises(ValueError, match="conflicting"):
        again.reconcile_pending_usage(row["attempt_id"], **{**receipt, "cost_usd": cost * 2})
    assert again.total_cost == baseline_cost


def test_failed_admission_write_refuses_before_provider(setup_run, monkeypatch):
    from core.audit import attempt_reservations as consumer
    client = _make(setup_run)
    calls = client._captured_wire["requests"]
    def unavailable(*args, **kwargs):
        raise OSError("captured disk write failure")
    monkeypatch.setattr(consumer, "_append_jsonl_bytes", unavailable)
    with pytest.raises(RuntimeError, match="accounting admission unavailable"):
        client.generate("captured")
    assert calls == [] and client.total_cost == 0
    assert client.reported_spend_usd == 0
    assert client.is_budget_exhausted()


def test_committed_admission_uses_the_verified_token_once(setup_run, monkeypatch):
    from core.audit import record
    client = _make(setup_run)
    original = record.stamp_audit_log_row
    mints = []
    def once(row, out_dir):
        # Every transition needs its own signature. Only the admission token
        # must be minted exactly once and reused by its verified append.
        if row.get("stage") != "admitted":
            return original(row, out_dir)
        mints.append(row)
        return original(row, out_dir) if len(mints) == 1 else dict(row)
    monkeypatch.setattr(record, "stamp_audit_log_row", once)
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("captured producer cancellation")
    client._captured_wire["handler"] = interrupted
    with pytest.raises(KeyboardInterrupt):
        client.generate("captured")
    assert len(mints) == 1
    assert len([r for r in record.load_verified_audit_log(setup_run)
                if r.get("stage") == "admitted"]) == 1


@pytest.mark.parametrize("suffix", [b"{", b"{broken}\n", b"\xff\n", b"[]\n"])
def test_corrupt_tail_is_not_an_absent_reservation(setup_run, suffix):
    from core.audit import record
    _make(setup_run)
    with record.audit_log_append_path(setup_run).open("ab") as stream:
        stream.write(suffix)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    with pytest.raises(RuntimeError, match="accounting recovery incomplete"):
        resumed.generate("captured")
    assert resumed.get_stats()["attempt_accounting_recovery"]["status"] == "incomplete"


def test_signed_admission_tampering_cannot_release_hold(setup_run, monkeypatch):
    from core.audit import record
    client = _make(setup_run)
    _unknown(client)
    path = record.audit_log_append_path(setup_run)
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    for row in rows:
        if row.get("stage") == "admitted":
            row["attempt"]["reservation_usd"] = 0
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    with pytest.raises(RuntimeError, match="unverified_attempt_recovery_row"):
        resumed.generate("captured")


def test_provider_floor_overlap_keeps_late_usage_unresolved(setup_run, monkeypatch):
    client = _make(setup_run)
    cost = _usage_cost(client)
    row = _unknown(client, provider_cost=cost)
    _persist_spend_floor(OrchestratorConfig(target_path=setup_run.parent,
        out_dir=setup_run, llm_budget_client=client), OrchestratorResult(), force=True)
    billed, _ = resolve_prior_spend(setup_run)
    assert billed == pytest.approx(cost)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2, prior_booked_spend_usd=billed)
    with pytest.raises(ValueError, match="ambiguous_prior_floor_usage"):
        resumed.reconcile_pending_usage(row["attempt_id"], cost_usd=cost,
            tokens_in=4, tokens_out=2, tokens_total=6)
    assert resumed.total_cost == 0 and len(resumed.pending_usage_reservations) == 1
    assert resolve_prior_spend(setup_run)[0] == pytest.approx(cost)


def test_later_known_floor_carries_without_losing_new_charge(setup_run, monkeypatch):
    from core.run.resume import persist_spend_floor
    client = _make(setup_run)
    cost = _usage_cost(client)
    row = _unknown(client)
    client.reconcile_pending_usage(row["attempt_id"], cost_usd=cost,
        tokens_in=4, tokens_out=2, tokens_total=6)
    # An existing non-attributed producer contributed another known floor.
    floor = cost * 2
    persist_spend_floor(setup_run, floor)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2, prior_booked_spend_usd=floor)
    response = resumed.generate("captured")
    assert response.cost == pytest.approx(cost)
    assert resolve_prior_spend(setup_run)[0] == pytest.approx(floor + response.cost)


def test_legacy_corpus_client_without_lifecycle_keeps_dispatch(setup_run, monkeypatch):
    (setup_run / ".raptor-run.json").unlink()
    client = _make(setup_run)
    client._captured_wire["usage"] = {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    response = client.generate("captured")
    assert len(client._captured_wire["requests"]) == 1
    assert response.cost == response.tokens_used == 0
    assert client.get_stats()["attempt_accounting_recovery"] == {
        "status": "unavailable", "reason": "lifecycle_not_bound"}


def test_reasoning_tokens_remain_governed_after_resume(setup_run, monkeypatch):
    # Admission must cover the permitted envelope, not only its later reported
    # ten tokens. Recovery still enforces the original ten-token exhausted cap.
    client = _make(setup_run, max_tokens=10000)
    client._captured_wire["usage"] = {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10,
        "completion_tokens_details": {"reasoning_tokens": 4}}
    response = client.generate("captured")
    assert response.tokens_used == client._governed_tokens == 10
    assert response.input_tokens + response.output_tokens == 6
    billed, _ = resolve_prior_spend(setup_run)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2,
        prior_booked_spend_usd=billed, max_tokens=10)
    assert resumed._governed_tokens == 10
    with pytest.raises(RuntimeError, match="token limit"):
        resumed._check_governor()


def test_inflight_hold_is_not_a_billed_resume_floor(setup_run, monkeypatch):
    from core.audit.orchestrator import _reconcile_cost_ledgers
    from core.llm import telemetry
    from core.testing.module_state import isolated_module_state
    client = _make(setup_run)
    result = OrchestratorResult()
    config = OrchestratorConfig(target_path=setup_run.parent, out_dir=setup_run,
        llm_budget_client=client)
    observed = []
    def interrupted(*args, **kwargs):
        # Poll while the real client's prepared hold is still active, before
        # any reported provider usage or terminal accounting transition.
        _persist_spend_floor(config, result, force=True)
        _reconcile_cost_ledgers(config, result)
        observed.append((resolve_prior_spend(setup_run)[0], result.llm_spend_usd,
                         client._check_budget(1.0)))
        raise KeyboardInterrupt("captured generation interruption")
    client._captured_wire["handler"] = interrupted
    with isolated_module_state(telemetry, {"_sink": None}, lock=telemetry._sink_lock):
        with pytest.raises(KeyboardInterrupt):
            client.generate("captured")
    assert observed == [(0.0, 0.0, False)]


def test_completed_usage_stays_separate_from_another_active_hold(setup_run, monkeypatch):
    from core.llm import telemetry
    from core.testing.module_state import isolated_module_state
    client = _make(setup_run)
    config = OrchestratorConfig(target_path=setup_run.parent, out_dir=setup_run,
        llm_budget_client=client)
    result = OrchestratorResult()
    observed = []
    inner_cost = _usage_cost(client)
    outer_cost = _usage_cost(client, 4, 6)

    def generate(request):
        prompt = json.loads(request.content)["messages"][0]["content"]
        if prompt == "outer":
            client.generate("inner")
            _persist_spend_floor(config, result, force=True)
            observed.append((resolve_prior_spend(setup_run)[0], client.reported_spend_usd,
                             client._check_budget(1.0)))
            client._captured_wire["usage"] = {"prompt_tokens": 4, "completion_tokens": 6, "total_tokens": 10}
    client._captured_wire["handler"] = generate
    with isolated_module_state(telemetry, {"_sink": None}, lock=telemetry._sink_lock):
        client.generate("outer")
    assert observed[0][0] == pytest.approx(inner_cost)
    assert observed[0][1] == pytest.approx(inner_cost)
    assert observed[0][2] is False
    assert client.reported_spend_usd == pytest.approx(inner_cost + outer_cost)
    assert resolve_prior_spend(setup_run)[0] == pytest.approx(inner_cost + outer_cost)

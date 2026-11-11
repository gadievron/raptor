"""Same-run recovery keeps unknown usage separate from billed spend."""
from types import SimpleNamespace
import json

import pytest

from core.audit import pipeline
from core.audit.orchestrator import OrchestratorConfig, OrchestratorResult, _persist_spend_floor
from core.audit.resume import resolve_prior_spend
from core.json.utils import save_json
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
import core.llm.dispatcher.client as dispatcher
from core.run.report_identity import fresh_identity
from core.llm.providers import LLMResponse


@pytest.fixture
def setup_run(tmp_path, monkeypatch):
    from core.llm import transcript
    out = tmp_path / "run"
    out.mkdir()
    save_json(out / ".raptor-run.json", {"command": "audit", "status": "running",
        "reporting_identity": fresh_identity()})
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    def build(*args, **kwargs):
        cfg = LLMConfig(primary_model=ModelConfig(provider="anthropic",
            model_name="resume-stub", api_key="inert"), enable_caching=False,
            enable_fallback=False, max_retries=1)
        cfg.max_cost_per_scan = kwargs["config"].max_cost_per_scan
        return LLMClient(cfg)
    monkeypatch.setattr(transcript, "build_llm_client", build)
    monkeypatch.setattr(pipeline, "_ensure_dispatcher_route", lambda *a, **k: None)
    monkeypatch.setattr(dispatcher._attempt_state, "response_started", False, raising=False)
    return out


def test_same_run_unknown_hold_survives_client_reconstruction(setup_run, monkeypatch):
    out = setup_run
    client, _, _ = pipeline._make_llm_client(pipeline.AuditPipelineOpts(
        out_dir=out, max_cost_usd=1.0))
    def fail(*args, **kwargs):
        dispatcher._attempt_state.response_started = True
        raise ConnectionError("captured response body ended")
    provider = SimpleNamespace(generate=fail, total_cost=0.0, total_tokens=0)
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    with pytest.raises(RuntimeError):
        client.generate("captured", call_class="review")
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


def _unknown(client, monkeypatch, *, provider_cost=0.0):
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0)
    def fail(*args, **kwargs):
        provider.total_cost += provider_cost
        dispatcher._attempt_state.response_started = True
        raise ConnectionError("captured response body ended")
    provider.generate = fail
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
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
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(generate=interrupted))
    with pytest.raises(KeyboardInterrupt):
        client.generate("captured", call_class="review")
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    assert [r["attempt_id"] for r in resumed.pending_usage_reservations] == admitted
    assert resumed.total_cost == 0


def test_late_usage_is_idempotent_across_another_resume(setup_run, monkeypatch):
    client = _make(setup_run)
    row = _unknown(client, monkeypatch)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2)
    assert resumed.reconcile_pending_usage(row["attempt_id"], cost_usd=0.25, tokens_in=4, tokens_out=2)
    assert not resumed.reconcile_pending_usage(row["attempt_id"], cost_usd=0.25, tokens_in=4, tokens_out=2)
    assert resumed.total_cost == 0.25 and resumed.pending_usage_reservations == []
    billed, _ = resolve_prior_spend(setup_run)
    assert billed == 0.25
    again = _make(setup_run, same_run_reuse=True, resume_segment=3, prior_booked_spend_usd=billed)
    assert not again.reconcile_pending_usage(row["attempt_id"], cost_usd=0.25, tokens_in=4, tokens_out=2)
    assert again.total_cost == 0
    with pytest.raises(ValueError, match="conflicting"):
        again.reconcile_pending_usage(row["attempt_id"], cost_usd=0.3, tokens_in=4, tokens_out=2)
    assert again.total_cost == 0


def test_failed_admission_write_refuses_before_provider(setup_run, monkeypatch):
    from core.audit import attempt_reservations as consumer
    client = _make(setup_run)
    calls = []
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(
        generate=lambda *a, **k: calls.append(1)))
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
        mints.append(row)
        return original(row, out_dir) if len(mints) == 1 else dict(row)
    monkeypatch.setattr(record, "stamp_audit_log_row", once)
    def interrupted(*args, **kwargs):
        raise KeyboardInterrupt("captured producer cancellation")
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(generate=interrupted))
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
    _unknown(client, monkeypatch)
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
    row = _unknown(client, monkeypatch, provider_cost=0.25)
    _persist_spend_floor(OrchestratorConfig(target_path=setup_run.parent,
        out_dir=setup_run, llm_budget_client=client), OrchestratorResult(), force=True)
    billed, _ = resolve_prior_spend(setup_run)
    assert billed == 0.25
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2, prior_booked_spend_usd=billed)
    with pytest.raises(ValueError, match="ambiguous_prior_floor_usage"):
        resumed.reconcile_pending_usage(row["attempt_id"], cost_usd=0.25)
    assert resumed.total_cost == 0 and len(resumed.pending_usage_reservations) == 1
    assert resolve_prior_spend(setup_run)[0] == 0.25


def test_later_known_floor_carries_without_losing_new_charge(setup_run, monkeypatch):
    from core.run.resume import persist_spend_floor
    client = _make(setup_run)
    row = _unknown(client, monkeypatch)
    client.reconcile_pending_usage(row["attempt_id"], cost_usd=0.25)
    # An existing non-attributed producer contributed another known floor.
    persist_spend_floor(setup_run, 0.5)
    resumed = _make(setup_run, same_run_reuse=True, resume_segment=2, prior_booked_spend_usd=0.5)
    def success(*args, **kwargs):
        return LLMResponse(content="captured", model="resume-stub", provider="anthropic",
            finish_reason="complete", cost=0.1, tokens_used=0)
    monkeypatch.setattr(resumed, "_get_provider", lambda _: SimpleNamespace(generate=success))
    resumed.generate("captured")
    assert resolve_prior_spend(setup_run)[0] == pytest.approx(0.6)


def test_legacy_corpus_client_without_lifecycle_keeps_dispatch(setup_run, monkeypatch):
    (setup_run / ".raptor-run.json").unlink()
    client = _make(setup_run)
    calls = []
    def generate(*args, **kwargs):
        calls.append(1)
        return LLMResponse(content="captured", model="resume-stub", provider="anthropic",
            finish_reason="complete", cost=0, tokens_used=0)
    monkeypatch.setattr(client, "_get_provider", lambda _: SimpleNamespace(generate=generate))
    client.generate("captured")
    assert calls == [1]
    assert client.get_stats()["attempt_accounting_recovery"] == {
        "status": "unavailable", "reason": "lifecycle_not_bound"}


def test_reasoning_tokens_remain_governed_after_resume(setup_run, monkeypatch):
    from core.llm import transcript
    from core.llm.providers import OpenAICompatibleProvider
    model = ModelConfig(provider="openai", model_name="reasoning-stub", api_key="inert")
    def build(*args, **kwargs):
        return LLMClient(LLMConfig(primary_model=model, enable_caching=False,
            enable_fallback=False, max_retries=1,
            max_cost_per_scan=kwargs["config"].max_cost_per_scan))
    monkeypatch.setattr(transcript, "build_llm_client", build)
    provider = OpenAICompatibleProvider(model)
    usage = SimpleNamespace(prompt_tokens=4, completion_tokens=6,
        completion_tokens_details=SimpleNamespace(reasoning_tokens=4),
        prompt_tokens_details=None)
    def generate(**kwargs):
        return SimpleNamespace(model="captured", usage=usage, choices=[SimpleNamespace(
            finish_reason="stop", message=SimpleNamespace(content="captured"))])
    monkeypatch.setattr(provider, "client", SimpleNamespace(chat=SimpleNamespace(
        completions=SimpleNamespace(create=generate))))
    monkeypatch.setattr(provider, "_calculate_cost_split", lambda *a, **k: 0.25)
    client = _make(setup_run, max_tokens=10)
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
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
        # Poll while the real client's pre-debit is still active, before
        # any reported provider usage or terminal accounting transition.
        _persist_spend_floor(config, result, force=True)
        _reconcile_cost_ledgers(config, result)
        observed.append((resolve_prior_spend(setup_run)[0], result.llm_spend_usd,
                         client._check_budget(1.0)))
        raise KeyboardInterrupt("captured generation interruption")
    provider = SimpleNamespace(generate=interrupted, total_cost=0.0)
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
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
    provider = SimpleNamespace(total_cost=0.0, total_tokens=0)
    def generate(prompt, *args, **kwargs):
        if prompt == "outer":
            client.generate("inner")
            _persist_spend_floor(config, result, force=True)
            observed.append((resolve_prior_spend(setup_run)[0], client.reported_spend_usd,
                             client._check_budget(1.0)))
        cost = 0.3 if prompt == "outer" else 0.1
        provider.total_cost += cost
        return LLMResponse(content="captured", model="resume-stub", provider="anthropic",
            finish_reason="complete", cost=cost, tokens_used=0)
    provider.generate = generate
    client.providers["scripted"] = provider
    monkeypatch.setattr(client, "_get_provider", lambda _: provider)
    with isolated_module_state(telemetry, {"_sink": None}, lock=telemetry._sink_lock):
        client.generate("outer")
    assert observed[0][0] == pytest.approx(0.1)
    assert observed[0][1] == pytest.approx(0.1)
    assert observed[0][2] is False
    assert client.reported_spend_usd == pytest.approx(0.4)
    assert resolve_prior_spend(setup_run)[0] == pytest.approx(0.4)

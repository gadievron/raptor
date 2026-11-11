"""Prepared SDK envelopes share the real client token and dollar ledger."""
from concurrent.futures import ThreadPoolExecutor
import json
from threading import Event
from types import SimpleNamespace

import httpx
import pytest

from core.audit.attempt_reservations import AttemptReservations
from core.audit.cost_tracker import PhaseCostLedger
from core.audit.record import load_verified_audit_log
from core.json.utils import save_json
from core.llm import detection, http_pool, providers, telemetry
from core.llm.budget_errors import LLMCallAdmissionRefused, LLMBudgetExceededError, LLMGovernorExceededError
from core.llm.client import LLMClient
from core.llm.config import LLMConfig, ModelConfig
from core.llm.prepared_admission import WIRE_HEADER
from core.llm.prepared_budget import quote_prepared_request
from core.run.report_identity import fresh_identity
from core.testing.module_state import isolated_module_state


SCHEMA = {"type": "object", "properties": {"answer": {"type": "string"}}, "required": ["answer"]}


@pytest.fixture
def sdk_clients(monkeypatch, tmp_path):
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "private"))
    monkeypatch.setattr(providers, "_stream_transport_enabled", lambda: False)
    monkeypatch.setattr(detection, "detect_llm_availability", lambda: SimpleNamespace(external_llm=True))
    factory = {}
    opened = []
    sink = telemetry.TelemetrySink(tmp_path / "attempts.jsonl")
    monkeypatch.setattr(http_pool, "_keepalive_transport_and_mounts",
                        lambda **kwargs: (httpx.MockTransport(factory["respond"]), {}))

    def make(kind="openai", *, cap=0.12, token_cap=10000, run_dir=None, resume=False,
             usage="known", prepared=True, max_calls=20, retries=1):
        state = {"requests": [], "usage": usage, "handler": None, "cache_read": 0, "cache_write": 0}

        def respond(request):
            assert WIRE_HEADER not in request.headers
            body = json.loads(request.content)
            state["requests"].append(request)
            if state["handler"] is not None:
                state["handler"](request)
            tool = next(iter(body.get("tools", [])), None)
            n = 0 if state["usage"] == "zero" else 3
            if kind == "openai":
                message = {"role": "assistant", "content": '{"answer":"captured"}'}
                if tool:
                    message = {"role": "assistant", "content": None, "tool_calls": [{
                        "id": "captured-tool", "type": "function", "function": {
                            "name": tool["function"]["name"], "arguments": '{"answer":"captured"}'}}]}
                response = {"id": "captured-response", "object": "chat.completion", "created": 0,
                    "model": body["model"], "choices": [{"index": 0, "message": message,
                        "finish_reason": "tool_calls" if tool else "stop"}],
                    "usage": None if state["usage"] == "missing" else {
                        "prompt_tokens": n, "completion_tokens": n, "total_tokens": 2 * n}}
            else:
                content = [{"type": "text", "text": '{"answer":"captured"}'}]
                if tool:
                    content = [{"type": "tool_use", "id": "captured-tool", "name": tool["name"],
                                "input": {"answer": "captured"}}]
                response = {"id": "captured-message", "type": "message", "role": "assistant",
                    "model": body["model"], "content": content, "stop_reason": "tool_use" if tool else "end_turn",
                    "stop_sequence": None, "usage": None if state["usage"] == "missing" else {
                        "input_tokens": n, "output_tokens": n, "cache_read_input_tokens": state["cache_read"],
                        "cache_creation_input_tokens": state["cache_write"]}}
            if state.get("transform") is not None:
                response = state["transform"](response)
            return httpx.Response(200, request=request, json=response)

        factory["respond"] = respond
        model = ModelConfig(provider=kind, model_name="gpt-4o" if kind == "openai" else "claude-sonnet-4-6",
            api_key="inert", api_base="https://scripted.invalid/v1", max_tokens=16)
        client = LLMClient(LLMConfig(primary_model=model, fallback_models=[], enable_fallback=False,
            max_retries=retries, enable_caching=False, max_cost_per_scan=cap,
            max_tokens_per_scan=token_cap, max_calls_per_scan=max_calls, scorecard_enabled=False,
            cache_dir=tmp_path / "unused-cache", scorecard_path=tmp_path / "unused-scorecard"))
        provider = client.primary_provider
        opened.append(provider)
        if run_dir is not None:
            run_dir.mkdir(exist_ok=True)
            if not (run_dir / ".raptor-run.json").exists():
                save_json(run_dir / ".raptor-run.json", {"command": "audit", "status": "running",
                    "reporting_identity": fresh_identity()})
            client.bind_attempt_reservations(AttemptReservations(run_dir, resume=resume))
        if prepared:
            client.enable_prepared_admission()
        return SimpleNamespace(client=client, provider=provider, state=state, sink=sink)

    with isolated_module_state(telemetry, {"_sink": sink}, lock=telemetry._sink_lock):
        try:
            yield make
        finally:
            for provider in opened:
                provider.client.close()


def _generate(bundle, structured=False, *, prompt="captured"):
    kwargs = {"accounting_work_id": "study:owned", "accounting_beneficiaries": ("first", "second")}
    if structured:
        return bundle.client.generate_structured(prompt, SCHEMA, **kwargs)
    return bundle.client.generate(prompt, **kwargs)


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_known_usage_releases_exact_identified_hold(sdk_clients, kind, structured, tmp_path):
    out = tmp_path / "run"
    b = sdk_clients(kind, run_dir=out)
    def verify_admitted(request):
        row, = [r for r in load_verified_audit_log(out) if r.get("stage") == "admitted"]
        payload = json.loads(request.content)
        assert row["attempt"]["reservation_tokens"] == len(request.content) + payload["max_tokens"]
        assert b.client.reported_spend_usd == 0
    b.state["handler"] = verify_admitted
    response = _generate(b, structured)
    assert response.usage_reported is True
    assert len(b.state["requests"]) == 1 and b.client._governed_tokens == 6
    assert b.client.pending_usage_reservations == [] and b.client._prepared_resource_reservations == {}
    assert b.client.reported_spend_usd == pytest.approx(response.cost)
    row, = b.sink.attempt_projection()["attempts"]
    assert row["work_id"] == "study:owned" and set(row["beneficiaries"]) == {"first", "second"}


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_missing_success_usage_survives_resume_and_reconciles_as_success(sdk_clients, structured, tmp_path):
    out = tmp_path / "run"
    b = sdk_clients(run_dir=out, usage="missing")
    response = _generate(b, structured)
    assert response.usage_reported is False and response.cost == 0
    pending, = b.client.pending_usage_reservations
    assert pending["reservation_tokens"] > 16 and pending["outcome_event"] == "call"
    resumed = sdk_clients(run_dir=out, resume=True)
    assert resumed.client.pending_usage_reservations == b.client.pending_usage_reservations
    assert resumed.client._governed_tokens == 0
    with pytest.raises(ValueError, match="explicit token total"):
        resumed.client.reconcile_pending_usage(pending["attempt_id"], cost_usd=0.0000375, tokens_in=3, tokens_out=3)
    assert resumed.client.reconcile_pending_usage(pending["attempt_id"], cost_usd=0.0000375,
        tokens_in=3, tokens_out=3, tokens_total=6)
    assert not resumed.client.reconcile_pending_usage(pending["attempt_id"], cost_usd=0.0000375,
        tokens_in=3, tokens_out=3, tokens_total=6)
    assert resumed.client._governed_tokens == 6 and resumed.client.pending_usage_reservations == []
    ledger = PhaseCostLedger()
    ledger.project_attempts(b.sink.attempt_projection(), authoritative_spend=resumed.client.reported_spend_usd)
    assert ledger.total_spend_usd == pytest.approx(0.0000375)
    assert ledger.total_failed_attempts_cost_usd == 0


@pytest.mark.parametrize("resource", ["tokens", "usd"])
def test_concurrent_permitted_envelopes_fit_one_global_cap(sdk_clients, resource):
    b = sdk_clients()
    payload = {"model": "gpt-4o", "messages": [{"role": "user", "content": "captured"}],
               "max_tokens": 16, "temperature": 0.7}
    expected = httpx.Request("POST", "https://scripted.invalid/v1/chat/completions", json=payload)
    quote = quote_prepared_request(expected, b.provider)
    if resource == "tokens":
        b.client.config.max_tokens_per_scan = 2 * quote.reservation_tokens - 1
    else:
        b.client.config.max_cost_per_scan = quote.reservation_usd * 1.5
    entered, release = Event(), Event()
    def block_first(request):
        body = json.loads(request.content)
        assert body["messages"] in ([{"role": "user", "content": "captured"}],
                                     [{"role": "user", "content": "separate"}])
        assert {**body, "messages": payload["messages"]} == payload
        assert len(request.content) == len(expected.content)
        if len(b.state["requests"]) == 1:
            entered.set()
            assert release.wait(5)
    b.state["handler"] = block_first
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(_generate, b)
        try:
            if not entered.wait(5):
                first.result(timeout=1)
                pytest.fail("first request did not reach scripted transport")
            second = pool.submit(_generate, b, prompt="separate")
            with pytest.raises(LLMGovernorExceededError if resource == "tokens" else LLMBudgetExceededError):
                second.result(timeout=5)
        finally:
            release.set()
        first.result(timeout=5)
    assert len(b.state["requests"]) == 1
    assert b.client._prepared_resource_reservations == {} and b.client._governed_tokens == 6
    _generate(b)
    assert len(b.state["requests"]) == 2 and b.client._governed_tokens == 12


def test_small_token_cap_refuses_before_wire_without_changing_the_limit(sdk_clients):
    b = sdk_clients(token_cap=6)
    with pytest.raises(LLMGovernorExceededError):
        _generate(b)
    assert b.state["requests"] == [] and b.client.config.max_tokens_per_scan == 6
    assert b.client.reported_spend_usd == 0 and b.client.pending_usage_reservations == []


def test_unsupported_provider_is_unavailable_without_dispatch(sdk_clients, monkeypatch):
    b = sdk_clients()
    def forbidden(*args, **kwargs):
        pytest.fail("unsupported generation executed")
    monkeypatch.setattr(b.client, "_get_provider", lambda _: SimpleNamespace(generate=forbidden))
    with pytest.raises(LLMCallAdmissionRefused, match="unavailable"):
        _generate(b)
    assert b.state["requests"] == []


def test_anthropic_cache_tokens_are_governed_once(sdk_clients):
    b = sdk_clients("anthropic")
    b.state.update(cache_read=5, cache_write=7)
    response = _generate(b)
    assert response.tokens_used == b.client._governed_tokens == 18
    assert response.input_tokens == response.output_tokens == 3


def test_pipeline_lifecycle_binding_requires_prepared_sdk_admission(sdk_clients, tmp_path, monkeypatch):
    from core.audit import pipeline
    from core.llm import transcript
    b = sdk_clients(prepared=False)
    out = tmp_path / "factory-run"
    out.mkdir()
    save_json(out / ".raptor-run.json", {"command": "audit", "status": "running",
        "reporting_identity": fresh_identity()})
    monkeypatch.setattr(transcript, "build_llm_client", lambda **kwargs: b.client)
    monkeypatch.setattr(pipeline, "_ensure_dispatcher_route", lambda *args, **kwargs: None)
    client, _, _ = pipeline._make_llm_client(pipeline.AuditPipelineOpts(
        out_dir=out, max_cost_usd=0.12, max_tokens=10000, max_calls=2))
    assert client is b.client and client._prepared_admission_enabled
    _generate(b)
    row, = [r for r in load_verified_audit_log(out) if r.get("stage") == "admitted"]
    assert row["attempt"]["reservation_kind"] == "prepared"
    assert row["attempt"]["reservation_tokens"] > 16


def test_metadata_free_factory_retains_explicit_legacy_accounting(sdk_clients, tmp_path, monkeypatch):
    from core.audit import pipeline
    from core.llm import transcript
    b = sdk_clients(prepared=False)
    out = tmp_path / "library-output"
    out.mkdir()
    monkeypatch.setattr(transcript, "build_llm_client", lambda **kwargs: b.client)
    monkeypatch.setattr(pipeline, "_ensure_dispatcher_route", lambda *args, **kwargs: None)
    client, _, _ = pipeline._make_llm_client(pipeline.AuditPipelineOpts(out_dir=out, max_cost_usd=0.12))
    assert not client._prepared_admission_enabled
    assert client.get_stats()["attempt_accounting_recovery"]["status"] == "unavailable"
    _generate(b)
    assert len(b.state["requests"]) == 1


def test_interrupted_late_receipt_does_not_charge_replay(sdk_clients, tmp_path, monkeypatch):
    b = sdk_clients(run_dir=tmp_path / "run", usage="missing")
    _generate(b)
    row, = b.client.pending_usage_reservations
    original = b.client._record_governed_tokens
    interrupted = []
    def cancel_once(tokens):
        if not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt("captured receipt cancellation")
        return original(tokens)
    monkeypatch.setattr(b.client, "_record_governed_tokens", cancel_once)
    receipt = dict(cost_usd=0.0000375, tokens_in=3, tokens_out=3, tokens_total=6)
    with pytest.raises(KeyboardInterrupt):
        b.client.reconcile_pending_usage(row["attempt_id"], **receipt)
    b.client.reconcile_pending_usage(row["attempt_id"], **receipt)
    assert b.client.reported_spend_usd == pytest.approx(0.0000375)
    assert b.client._governed_tokens == 6 and b.client.pending_usage_reservations == []


def test_interrupted_known_settlement_does_not_become_a_second_charge(sdk_clients, tmp_path, monkeypatch):
    out = tmp_path / "run"
    b = sdk_clients(run_dir=out)
    original = b.client._release_prepared_active
    interrupted = []
    def cancel_once(hold):
        if not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt("captured settlement cancellation")
        return original(hold)
    monkeypatch.setattr(b.client, "_release_prepared_active", cancel_once)
    with pytest.raises(KeyboardInterrupt):
        _generate(b)
    rows = b.client.pending_usage_reservations
    if rows:
        attempt_id = rows[0]["attempt_id"]
    else:
        store = b.client._attempt_reservation_store
        attempt_id = store.reported()[0]["attempt_id"]
    b.client.reconcile_pending_usage(attempt_id, cost_usd=0.0000375,
        tokens_in=3, tokens_out=3, tokens_total=6)
    assert len(b.state["requests"]) == 1
    assert b.client.reported_spend_usd == pytest.approx(0.0000375)
    assert b.client._governed_tokens == 6 and b.client.pending_usage_reservations == []


def test_unknown_writer_cannot_resurrect_a_settled_hold(sdk_clients, tmp_path, monkeypatch):
    b = sdk_clients(run_dir=tmp_path / "run", usage="missing")
    _generate(b)
    row, = b.client.pending_usage_reservations
    store = b.client._attempt_reservation_store
    original = store.pending
    snapshotted, release = Event(), Event()
    def paused_snapshot():
        rows = original()
        snapshotted.set()
        assert release.wait(5)
        return rows
    monkeypatch.setattr(store, "pending", paused_snapshot)
    with ThreadPoolExecutor(max_workers=2) as pool:
        unknown = pool.submit(b.client._persist_attempt_usage, row["attempt_id"],
            cost_usd=None, outcome_event="call")
        try:
            assert snapshotted.wait(5)
            late = pool.submit(b.client.reconcile_pending_usage, row["attempt_id"],
                cost_usd=0.0000375, tokens_in=3, tokens_out=3, tokens_total=6)
            # Force the stale writer to run last whenever the implementation
            # permits that order; a serialized implementation releases first.
            unlocked = b.client._stats_lock.acquire(blocking=False)
            if unlocked:
                b.client._stats_lock.release()
                late.result(timeout=5)
        finally:
            release.set()
        unknown.result(timeout=5)
        late.result(timeout=5)
    assert b.client.pending_usage_reservations == []
    assert b.client.reported_spend_usd == pytest.approx(0.0000375)


def test_persistence_refusal_survives_secondary_cleanup_cancellation(sdk_clients, tmp_path, monkeypatch):
    b = sdk_clients(run_dir=tmp_path / "run")
    def refuse_admission(row):
        raise ValueError("captured durable admission refusal")
    monkeypatch.setattr(b.client._attempt_reservation_store, "admit", refuse_admission)
    original = b.client._release_prepared_active
    interrupted = []
    def cancel_once(hold):
        if not interrupted:
            interrupted.append(True)
            raise KeyboardInterrupt("secondary cleanup cancellation")
        return original(hold)
    monkeypatch.setattr(b.client, "_release_prepared_active", cancel_once)
    observed = None
    try:
        _generate(b)
    except BaseException as error:
        observed = error
    assert isinstance(observed, LLMBudgetExceededError)
    assert b.state["requests"] == [] and b.client.reported_spend_usd == 0


def test_completed_receipt_replay_does_not_charge_or_reclassify_success(sdk_clients, tmp_path):
    b = sdk_clients(run_dir=tmp_path / "run")
    response = _generate(b)
    row, = b.sink.attempt_projection()["attempts"]
    assert not b.client.reconcile_pending_usage(row["attempt_id"], cost_usd=response.cost,
        tokens_in=response.input_tokens, tokens_out=response.output_tokens, tokens_total=response.tokens_used)
    assert b.client.reported_spend_usd == pytest.approx(response.cost)
    assert b.client._governed_tokens == response.tokens_used
    ledger = PhaseCostLedger()
    ledger.project_attempts(b.sink.attempt_projection(), authoritative_spend=b.client.reported_spend_usd)
    assert ledger.total_spend_usd == pytest.approx(response.cost)
    assert ledger.total_failed_attempts_cost_usd == 0


def test_late_overrun_preserves_actual_usage_and_allows_existing_holds_to_drain(sdk_clients, tmp_path):
    b = sdk_clients(run_dir=tmp_path / "run", usage="missing")
    _generate(b, prompt="first")
    _generate(b, prompt="second")
    first, second = b.client.pending_usage_reservations
    paid = first["reservation_usd"] * 2
    assert b.client.reconcile_pending_usage(first["attempt_id"], cost_usd=paid,
        tokens_in=3, tokens_out=3, tokens_total=6)
    assert b.client._attempt_recovery_gap == "prepared_usage_exceeded_reservation"
    assert b.client.reconcile_pending_usage(second["attempt_id"], cost_usd=0.0000375,
        tokens_in=3, tokens_out=3, tokens_total=6)
    assert b.client.pending_usage_reservations == []
    assert b.client.reported_spend_usd == pytest.approx(paid + 0.0000375)
    assert b.client._governed_tokens == 12
    with pytest.raises(LLMBudgetExceededError, match="accounting recovery incomplete"):
        _generate(b, prompt="third")
    assert len(b.state["requests"]) == 2


@pytest.mark.parametrize("failure", ["malformed", "truncated"])
def test_consumed_invalid_generation_keeps_one_prepared_charge(sdk_clients, tmp_path, failure):
    b = sdk_clients(run_dir=tmp_path / "run", retries=2)
    def invalid(response):
        choice = response["choices"][0]
        if failure == "truncated":
            choice["finish_reason"] = "length"
        else:
            choice["message"]["tool_calls"][0]["function"]["arguments"] = "{"
        return response
    b.state["transform"] = invalid
    with pytest.raises(RuntimeError):
        _generate(b, structured=True)
    assert len(b.state["requests"]) == 1
    assert b.client._governed_tokens == 6
    paid = b.provider._calculate_cost_split(3, 3)
    assert b.client.reported_spend_usd == pytest.approx(paid)
    assert b.client.pending_usage_reservations == []
    row, = b.sink.attempt_projection()["attempts"]
    assert row["event"] == "attempt_failed" and row["billing_state"] == "reported"
    ledger = PhaseCostLedger()
    ledger.project_attempts(b.sink.attempt_projection(), authoritative_spend=b.client.reported_spend_usd)
    assert ledger.total_spend_usd == pytest.approx(paid)
    assert ledger.total_failed_attempts_cost_usd == pytest.approx(paid)


def test_outer_retry_keeps_unknown_hold_and_reconciles_each_attempt_once(sdk_clients, tmp_path, monkeypatch):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", lambda _: None)
    b = sdk_clients(run_dir=tmp_path / "run", retries=2)
    def interrupted_first(request):
        if len(b.state["requests"]) == 1:
            raise httpx.ReadError("captured first attempt lost its response", request=request)
    b.state["handler"] = interrupted_first
    response = _generate(b)
    assert len(b.state["requests"]) == b.client._governed_calls == 2
    rows = b.sink.attempt_projection()["attempts"]
    assert len(rows) == len({row["attempt_id"] for row in rows}) == 2
    assert len({row["call_id"] for row in rows}) == 1
    assert all(row["work_id"] == "study:owned" and set(row["beneficiaries"]) == {"first", "second"}
               for row in rows)
    pending, = b.client.pending_usage_reservations
    assert pending["reservation_tokens"] > response.tokens_used
    receipt = dict(cost_usd=response.cost, tokens_in=response.input_tokens,
                   tokens_out=response.output_tokens, tokens_total=response.tokens_used)
    assert b.client.reconcile_pending_usage(pending["attempt_id"], **receipt)
    assert not b.client.reconcile_pending_usage(pending["attempt_id"], **receipt)
    assert b.client.reported_spend_usd == pytest.approx(2 * response.cost)
    assert b.client._governed_tokens == 2 * response.tokens_used
    assert b.client.pending_usage_reservations == []
    ledger = PhaseCostLedger()
    ledger.project_attempts(b.sink.attempt_projection(), authoritative_spend=b.client.reported_spend_usd)
    assert ledger.total_spend_usd == pytest.approx(2 * response.cost)
    assert ledger.total_failed_attempts_cost_usd == pytest.approx(response.cost)


@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
def test_closed_owned_scope_refuses_after_sdk_preparation_before_wire(sdk_clients, structured):
    from core.audit.knowledge_calls import observed_client, owned_call_scope
    b = sdk_clients(max_calls=1)
    entered, release = Event(), Event()
    admissions = []
    def admit(purpose, method):
        admissions.append((purpose, method))
        return True
    def wait_before_wire_admission(request):
        entered.set()
        assert release.wait(5)
    b.provider.client._client.event_hooks["request"].insert(0, wait_before_wire_admission)
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with owned_call_scope(admit, work_id="review:closed", beneficiaries=("owned",)):
                view = observed_client(b.client, purpose="review")
                future = (pool.submit(view.generate_structured, "captured", SCHEMA) if structured
                          else pool.submit(view.generate, "captured"))
                assert entered.wait(5)
            # The request has passed the outer call boundary, but its owner
            # is now closed before the actual SDK wire-admission hook.
        finally:
            release.set()
        with pytest.raises(LLMCallAdmissionRefused, match="scope_closed"):
            future.result(timeout=5)
    assert len(admissions) == 1
    assert b.state["requests"] == [] and b.client.reported_spend_usd == 0
    assert b.client.pending_usage_reservations == []
    assert b.client._governed_calls == 0 and not b.client.is_budget_exhausted()
    # A refused task must leave the single global attempt available to another.
    _generate(b)
    assert len(b.state["requests"]) == b.client._governed_calls == 1


def test_prepared_retries_preserve_owned_attempt_limit_and_first_credit(sdk_clients, monkeypatch):
    from core.audit.knowledge_calls import observed_client, owned_call_scope
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    patch_module_attribute(monkeypatch, consumer, "time", "sleep", lambda _: None)
    b = sdk_clients(retries=3)
    admitted = []
    def admit(purpose, method):
        if len(admitted) >= 2:
            return False
        admitted.append((purpose, method))
        return True
    def lost(request):
        raise httpx.ReadError("captured response lost", request=request)
    b.state["handler"] = lost
    with owned_call_scope(admit, work_id="review:bounded", beneficiaries=("owned",)):
        view = observed_client(b.client, purpose="review")
        with pytest.raises(LLMCallAdmissionRefused, match="unit_admission"):
            view.generate("captured")
    assert len(admitted) == len(b.state["requests"]) == 2
    assert len(b.client.pending_usage_reservations) == 2
    assert b.client.reported_spend_usd == 0
    assert not b.client.is_budget_exhausted()


@pytest.mark.parametrize("kind", ["openai", "anthropic"])
@pytest.mark.parametrize("structured", [False, True], ids=["text", "structured"])
@pytest.mark.parametrize("remaining", [None, 4.0], ids=["stage", "remaining-window"])
def test_prepared_sdk_timeout_fits_existing_stage_and_window(sdk_clients, monkeypatch, kind, structured, remaining):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients(kind)
    if remaining is not None:
        b.client.config.max_seconds_per_scan = 30
        b.client._run_start = 100.0
        patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: 130.0 - remaining)
    allowed = min(17.0, remaining) if remaining is not None else 17.0
    def bounded(request):
        timeout = request.extensions["timeout"]
        assert set(timeout) == {"connect", "read", "write", "pool"}
        assert all(value is not None and 0 <= value <= allowed for value in timeout.values())
    b.state["handler"] = bounded
    if structured:
        b.client.generate_structured("captured", SCHEMA, timeout_s=17.0)
    else:
        b.client.generate("captured", timeout_s=17.0)
    assert len(b.state["requests"]) == 1


def test_prepared_timeout_preserves_stricter_sdk_phases(sdk_clients):
    b = sdk_clients()
    def existing(request):
        request.extensions["timeout"] = {"connect": 0.5, "read": 2.0, "write": 0.0, "pool": None}
    b.provider.client._client.event_hooks["request"].insert(0, existing)
    def bounded(request):
        assert request.extensions["timeout"] == {"connect": 0.5, "read": 2.0, "write": 0.0, "pool": 17.0}
    b.state["handler"] = bounded
    b.client.generate("captured", timeout_s=17.0)
    assert len(b.state["requests"]) == 1


def test_unlimited_prepared_request_retains_existing_sdk_timeouts(sdk_clients):
    b = sdk_clients()
    before = []
    def existing(request):
        before.append(dict(request.extensions["timeout"]))
    b.provider.client._client.event_hooks["request"].insert(0, existing)
    def unchanged(request):
        assert request.extensions["timeout"] == before[0]
    b.state["handler"] = unchanged
    _generate(b)
    assert len(b.state["requests"]) == 1


@pytest.mark.parametrize("after_admission", [129.0, 131.0], ids=["remaining", "expired"])
def test_prepared_timeout_rechecks_window_after_durable_admission(sdk_clients, tmp_path, monkeypatch, after_admission):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients(run_dir=tmp_path / "run")
    now = [126.0]
    b.client.config.max_seconds_per_scan = 30.0
    b.client._run_start = 100.0
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: now[0])
    store = b.client._attempt_reservation_store
    original = store.admit
    def committed(row):
        result = original(row)
        now[0] = after_admission
        return result
    monkeypatch.setattr(store, "admit", committed)
    if after_admission >= 130.0:
        with pytest.raises(LLMGovernorExceededError, match="wall-clock"):
            b.client.generate("captured", timeout_s=17.0)
        assert b.state["requests"] == [] and b.client.reported_spend_usd == 0
        assert b.client.pending_usage_reservations == []
        assert store.pending() == []
    else:
        def bounded(request):
            assert all(0 <= value <= 130.0 - after_admission
                       for value in request.extensions["timeout"].values())
        b.state["handler"] = bounded
        b.client.generate("captured", timeout_s=17.0)
        assert len(b.state["requests"]) == 1


def test_absolute_deadline_does_not_restart_at_first_model_attempt(sdk_clients, monkeypatch):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients()
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: 200.0)
    b.client.config.max_seconds_per_scan = 30.0
    b.client.bind_run_deadline(201.0)
    def bounded(request):
        assert all(0 <= value <= 1.0 for value in request.extensions["timeout"].values())
    b.state["handler"] = bounded
    _generate(b)
    assert len(b.state["requests"]) == 1


def test_expired_absolute_deadline_refuses_first_model_attempt(sdk_clients, monkeypatch):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients()
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: 202.0)
    b.client.bind_run_deadline(201.0)
    with pytest.raises(LLMGovernorExceededError, match="run deadline"):
        _generate(b)
    assert b.state["requests"] == [] and b.client._governed_calls == 0
    assert b.client.reported_spend_usd == 0 and b.client.pending_usage_reservations == []


def test_rebinding_absolute_deadline_cannot_extend_allowance(sdk_clients, monkeypatch):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients()
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: 200.0)
    b.client.bind_run_deadline(201.0)
    b.client.bind_run_deadline(211.0)
    assert b.client._bound_run_deadline == 201.0
    b.client.bind_run_deadline(199.0)
    with pytest.raises(LLMGovernorExceededError, match="run deadline"):
        _generate(b)
    assert b.state["requests"] == []


@pytest.mark.parametrize("invalid", [True, False, None, float("nan"), float("inf"), -float("inf"), 10 ** 1000], ids=["true", "false", "none", "nan", "infinity", "negative-infinity", "huge-int"])
def test_absolute_deadline_protocol_rejects_invalid_bound_without_dispatch(sdk_clients, invalid):
    b = sdk_clients()
    assert type(b.client._run_deadline_protocol) is int and b.client._run_deadline_protocol == 1
    with pytest.raises(ValueError, match="finite monotonic"):
        b.client.bind_run_deadline(invalid)
    assert b.client._bound_run_deadline is None and b.state["requests"] == []


@pytest.mark.parametrize("after_commit", [200.75, 202.0], ids=["remaining", "expired"])
def test_absolute_deadline_rechecked_after_durable_admission(sdk_clients, tmp_path, monkeypatch, after_commit):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients(run_dir=tmp_path / "run")
    now = [200.0]
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: now[0])
    b.client.bind_run_deadline(201.0)
    store = b.client._attempt_reservation_store
    original = store.admit
    def commit(row):
        result = original(row)
        now[0] = after_commit
        return result
    monkeypatch.setattr(store, "admit", commit)
    if after_commit >= 201.0:
        with pytest.raises(LLMGovernorExceededError, match="run deadline"):
            _generate(b)
        assert b.state["requests"] == [] and b.client.reported_spend_usd == 0
        assert b.client.pending_usage_reservations == [] and store.pending() == []
        row, = store.reported()
        assert row["cost_usd"] == row["tokens_total"] == 0
    else:
        def bounded(request):
            assert all(0 <= value <= 201.0 - after_commit for value in request.extensions["timeout"].values())
        b.state["handler"] = bounded
        _generate(b)
        assert len(b.state["requests"]) == 1


def test_absolute_deadline_keeps_usage_from_an_already_dispatched_call(sdk_clients, monkeypatch):
    import core.llm.client as consumer
    from core.testing.module_bindings import patch_module_attribute
    b = sdk_clients()
    now = [200.0]
    patch_module_attribute(monkeypatch, consumer, "time", "monotonic", lambda: now[0])
    b.client.bind_run_deadline(201.0)
    def completes_after_deadline(request):
        now[0] = 202.0
    b.state["handler"] = completes_after_deadline
    response = _generate(b)
    assert b.client.reported_spend_usd == pytest.approx(response.cost)
    assert response.cost > 0 and b.client._governed_tokens == response.tokens_used == 6
    with pytest.raises(LLMGovernorExceededError, match="run deadline"):
        _generate(b, prompt="later")
    assert len(b.state["requests"]) == 1 and b.client.pending_usage_reservations == []


def test_prepared_fallback_prices_each_identified_attempt_once(sdk_clients, tmp_path):
    b = sdk_clients(run_dir=tmp_path / "run")
    fallback = ModelConfig(provider="openai", model_name="gpt-4o-mini", api_key="inert",
        api_base="https://scripted.invalid/v1", max_tokens=16)
    b.client.config.enable_fallback = True
    b.client.config.fallback_models = [fallback]
    alternate = b.client._get_provider(fallback)
    def first_response_lost(request):
        if json.loads(request.content)["model"] == "gpt-4o":
            raise httpx.ReadError("captured primary response lost", request=request)
    b.state["handler"] = first_response_lost
    try:
        response = _generate(b)
        assert response.model == "gpt-4o-mini"
        assert len(b.state["requests"]) == b.client._governed_calls == 2
        pending, = b.client.pending_usage_reservations
        assert pending["model"] == "gpt-4o"
        assert pending["reservation_usd"] > 0 and pending["reservation_tokens"] > 16
        first_cost = b.provider._calculate_cost_split(3, 3)
        second_cost = alternate._calculate_cost_split(3, 3)
        assert first_cost != second_cost and response.cost == pytest.approx(second_cost)
        receipt = dict(cost_usd=first_cost, tokens_in=3, tokens_out=3, tokens_total=6)
        assert b.client.reconcile_pending_usage(pending["attempt_id"], **receipt)
        assert not b.client.reconcile_pending_usage(pending["attempt_id"], **receipt)
        rows = b.sink.attempt_projection()["attempts"]
        assert len({row["attempt_id"] for row in rows}) == 2
        assert len({row["call_id"] for row in rows}) == 1
        assert {row["model"] for row in rows} == {"gpt-4o", "gpt-4o-mini"}
        assert all(set(row["beneficiaries"]) == {"first", "second"} for row in rows)
        assert b.client.reported_spend_usd == pytest.approx(first_cost + second_cost)
        assert b.client._governed_tokens == 12 and b.client.pending_usage_reservations == []
        ledger = PhaseCostLedger()
        ledger.project_attempts(b.sink.attempt_projection(), authoritative_spend=b.client.reported_spend_usd)
        assert ledger.total_spend_usd == pytest.approx(first_cost + second_cost)
        assert ledger.total_failed_attempts_cost_usd == pytest.approx(first_cost)
    finally:
        alternate.client.close()

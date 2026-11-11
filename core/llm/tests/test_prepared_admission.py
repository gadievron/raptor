"""Prepared admission tokens own one request and never reach transport."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event

import httpx
import pytest

from core.llm import prepared_admission as admission
from core.llm.budget_errors import LLMBudgetExceededError, LLMCallAdmissionRefused


def _request(token):
    return httpx.Request("POST", "https://captured.invalid/v1/messages",
                         headers={admission.WIRE_HEADER: token}, content=b"{}")


def _registry_tokens():
    with admission._registry_lock:
        return set(admission._registry)


def test_owned_token_is_consumed_before_callback_and_transport():
    baseline = _registry_tokens()
    admitted, transported = [], []

    def permit(request):
        assert admission.WIRE_HEADER not in request.headers
        admitted.append(request.content)

    def transport(request):
        assert admission.WIRE_HEADER not in request.headers
        transported.append(request.content)
        return httpx.Response(200, request=request)

    with admission.prepared_attempt(permit) as state, httpx.Client(
        transport=httpx.MockTransport(transport),
        event_hooks={"request": [admission.admit_prepared_request]},
    ) as client:
        client.send(_request(state.token))
        assert state.admitted
        with pytest.raises(LLMCallAdmissionRefused, match="another generation"):
            client.send(_request(state.token))
        assert state.admitted
    assert admitted == transported == [b"{}"]
    assert _registry_tokens() == baseline


def test_unmarked_request_keeps_legacy_transport_behavior():
    seen = []
    with httpx.Client(transport=httpx.MockTransport(
        lambda request: seen.append(request) or httpx.Response(200, request=request)),
        event_hooks={"request": [admission.admit_prepared_request]},
    ) as client:
        client.post("https://captured.invalid/v1/messages", content=b"{}")
    assert len(seen) == 1


@pytest.mark.parametrize("error_type", [LLMBudgetExceededError, LLMCallAdmissionRefused])
def test_original_refusal_is_preserved_without_dispatch(error_type):
    baseline = _registry_tokens()
    refusal = error_type("captured admission refusal")
    attempts, sent = [], []

    def refuse(request):
        assert admission.WIRE_HEADER not in request.headers
        attempts.append(request)
        raise refusal

    with admission.prepared_attempt(refuse) as state, httpx.Client(
        transport=httpx.MockTransport(lambda request: sent.append(request) or httpx.Response(200)),
        event_hooks={"request": [admission.admit_prepared_request]},
    ) as client:
        for _ in range(2):
            with pytest.raises(error_type) as caught:
                client.send(_request(state.token))
            assert caught.value is refusal
        assert not state.admitted
    assert len(attempts) == 1 and sent == []
    assert _registry_tokens() == baseline


def test_closed_and_forged_tokens_refuse_in_helper_thread():
    baseline = _registry_tokens()
    with admission.prepared_attempt(lambda request: None) as state:
        closed_token = state.token
    for token in (closed_token, "not-a-registered-attempt"):
        request = _request(token)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(admission.admit_prepared_request, request)
            with pytest.raises(LLMCallAdmissionRefused, match="unavailable or closed"):
                future.result(timeout=5)
        assert admission.WIRE_HEADER not in request.headers
    assert _registry_tokens() == baseline


def test_concurrent_requests_share_one_admission():
    entered, release, second_started = Event(), Event(), Event()
    calls, sent = [], []

    def permit(request):
        calls.append(request)
        entered.set()
        assert release.wait(5), "owned callback was not released"

    with admission.prepared_attempt(permit) as state, httpx.Client(
        transport=httpx.MockTransport(lambda request: sent.append(request) or httpx.Response(200)),
        event_hooks={"request": [admission.admit_prepared_request]},
    ) as client, ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(client.send, _request(state.token))
        second = None
        try:
            assert entered.wait(5), "first callback did not start"

            def send_second():
                second_started.set()
                return client.send(_request(state.token))

            second = pool.submit(send_second)
            assert second_started.wait(5), "second request did not start"
        finally:
            release.set()
        assert first.result(timeout=5).status_code == 200
        assert second is not None
        with pytest.raises(LLMCallAdmissionRefused, match="another generation"):
            second.result(timeout=5)
    assert len(calls) == len(sent) == 1


def test_closure_during_callback_retains_commitment_but_refuses_wire():
    entered, release = Event(), Event()
    committed, sent = [], []

    def permit(request):
        entered.set()
        assert release.wait(5), "owned callback was not released"
        committed.append(request)

    with httpx.Client(
        transport=httpx.MockTransport(lambda request: sent.append(request) or httpx.Response(200)),
        event_hooks={"request": [admission.admit_prepared_request]},
    ) as client, ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with admission.prepared_attempt(permit) as state:
                future = pool.submit(client.send, _request(state.token))
                assert entered.wait(5), "callback did not start"
        finally:
            release.set()
        with pytest.raises(LLMCallAdmissionRefused, match="closed during admission"):
            future.result(timeout=5)
        assert state.admitted
    assert len(committed) == 1 and sent == []


def test_nested_scopes_keep_separate_owners():
    baseline = _registry_tokens()
    outer_calls, inner_calls = [], []
    with admission.prepared_attempt(outer_calls.append) as outer:
        with admission.prepared_attempt(inner_calls.append) as inner:
            assert outer.token != inner.token
            admission.admit_prepared_request(_request(inner.token))
        with pytest.raises(LLMCallAdmissionRefused):
            admission.admit_prepared_request(_request(inner.token))
        admission.admit_prepared_request(_request(outer.token))
    assert len(outer_calls) == len(inner_calls) == 1
    assert _registry_tokens() == baseline


def test_reentrant_request_cannot_enter_callback_again():
    calls = []

    def permit(request):
        calls.append(request)
        assert not state.admitted
        with pytest.raises(LLMCallAdmissionRefused, match="another generation"):
            admission.admit_prepared_request(_request(state.token))

    with admission.prepared_attempt(permit) as state:
        admission.admit_prepared_request(_request(state.token))
        assert state.admitted
    assert len(calls) == 1


@pytest.mark.parametrize("error_type", [KeyboardInterrupt, SystemExit])
def test_fresh_callback_cancellation_cleans_registry(error_type):
    baseline = _registry_tokens()
    cancellation = error_type("captured cancellation")

    def cancel(request):
        raise cancellation

    with pytest.raises(error_type) as caught:
        with admission.prepared_attempt(cancel) as state:
            admission.admit_prepared_request(_request(state.token))
    assert caught.value is cancellation
    assert not state.admitted
    assert _registry_tokens() == baseline


def test_sdk_factory_adds_request_guard_without_changing_forwarding_hooks(monkeypatch):
    from core.llm import http_pool

    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    monkeypatch.setattr(http_pool, "_keepalive_transport_and_mounts",
                        lambda **kwargs: (transport, {}))
    response_hooks = http_pool.response_event_hooks()
    assert "request" not in response_hooks
    with http_pool.sdk_http_client(5, trust_env=False) as client:
        assert client.event_hooks["request"] == [admission.admit_prepared_request]
        assert client.event_hooks["response"] == response_hooks["response"]
    assert http_pool.response_event_hooks() == response_hooks


def test_dispatcher_factory_resets_spend_state_before_admission(monkeypatch):
    from core.llm.dispatcher import client as dispatcher
    from core.testing.module_bindings import patch_module_attribute

    transport = httpx.MockTransport(lambda request: httpx.Response(200, request=request))
    patch_module_attribute(monkeypatch, dispatcher, "httpx", "HTTPTransport",
                           lambda **kwargs: transport)
    monkeypatch.setattr(dispatcher._attempt_state, "response_started", True, raising=False)
    calls = []

    def permit(request):
        assert not dispatcher._attempt_state.response_started
        calls.append(request)

    with admission.prepared_attempt(permit) as state, dispatcher._make_httpx_client(
        "/unused-owned-socket", "inert",
    ) as client:
        assert client.event_hooks["request"] == [dispatcher._reset_attempt_state,
                                                 admission.admit_prepared_request]
        assert client.event_hooks["response"] == [dispatcher._note_attempt_state]
        request = _request(state.token)
        for hook in client.event_hooks["request"]:
            hook(request)
        assert state.admitted and admission.WIRE_HEADER not in request.headers
    assert len(calls) == 1

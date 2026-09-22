"""Spend-aware retry gate for consumed upstream attempts.

A transport death AFTER the dispatcher relayed the upstream response
head means the upstream fully processed — and billed — the generation;
re-sending buys it a second time. The gate reads the dispatcher's
``X-Raptor-Upstream-State`` stamp (recorded per worker thread by the
httpx hooks in ``core.llm.dispatcher.client``) and turns such failures
terminal for the model instead of retryable, unless the operator opted
back in via ``RAPTOR_LLM_RETRY_CONSUMED``.

Hermetic — stub providers and synthetic hook state; the real-dispatcher
round-trip lives in ``test_consumed_attempt_e2e.py``.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

import core.llm.dispatcher.client as dispatcher_client
from core.llm.client import (
    LLMClient,
    MidResponseDeathError,
    _is_transport_failure,
)
from core.llm.config import LLMConfig, ModelConfig
from core.llm.dispatcher.client import (
    _note_attempt_state,
    _reset_attempt_state,
    take_upstream_response_started,
)


class FakeAPIConnectionError(Exception):
    """Name-shaped like the SDK wrappers the gate must recognise."""


def _client(max_retries: int = 3) -> LLMClient:
    primary = ModelConfig(
        provider="anthropic", model_name="primary", api_key="test-key",
    )
    return LLMClient(LLMConfig(
        primary_model=primary, fallback_models=[],
        enable_caching=False, max_retries=max_retries,
        enable_fallback=False,
    ))


def _mark_response_started() -> None:
    """Simulate the response hook having seen a relayed upstream head
    for the current thread's in-flight request."""
    dispatcher_client._attempt_state.response_started = True


@pytest.fixture(autouse=True)
def _clean_attempt_state():
    """Each test starts and ends with no recorded attempt state, so a
    failure in one test can never steer another's retry gate."""
    dispatcher_client._attempt_state.response_started = False
    yield
    dispatcher_client._attempt_state.response_started = False


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    import core.llm.client as client_mod
    monkeypatch.setattr(client_mod.time, "sleep", lambda _s: None)


class TestAttemptStateHooks:
    def test_started_stamp_recorded_and_taken_once(self):
        resp = httpx.Response(
            200, headers={"X-Raptor-Upstream-State": "response-started"},
        )
        _note_attempt_state(resp)
        assert take_upstream_response_started() is True
        # Destructive read: the signal is scoped to one consultation.
        assert take_upstream_response_started() is False

    def test_pre_response_stamp_is_not_started(self):
        resp = httpx.Response(
            502, headers={"X-Raptor-Upstream-State": "pre-response"},
        )
        _note_attempt_state(resp)
        assert take_upstream_response_started() is False

    def test_unstamped_response_is_no_signal(self):
        _note_attempt_state(httpx.Response(200))
        assert take_upstream_response_started() is False

    def test_new_request_resets_previous_attempt_state(self):
        _mark_response_started()
        _reset_attempt_state(object())
        assert take_upstream_response_started() is False


class TestIsTransportFailure:
    def test_sdk_connection_wrapper(self):
        assert _is_transport_failure(
            FakeAPIConnectionError("Connection error."),
        )

    def test_httpx_protocol_and_read_errors(self):
        assert _is_transport_failure(httpx.RemoteProtocolError("eof"))
        assert _is_transport_failure(httpx.ReadError("rst"))
        assert _is_transport_failure(httpx.ReadTimeout("slow"))

    def test_builtin_connection_and_timeout(self):
        assert _is_transport_failure(ConnectionError("refused"))
        assert _is_transport_failure(TimeoutError("late"))

    def test_status_error_is_not_a_wire_death(self):
        class InternalServerError(Exception):
            pass

        assert not _is_transport_failure(
            InternalServerError("Error code: 502 - connection reset"),
        )

    def test_response_shape_failure_is_not_a_wire_death(self):
        assert not _is_transport_failure(
            json.JSONDecodeError("Expecting value", "doc", 0),
        )


class TestGenerateConsumedGate:
    def test_mid_response_death_is_not_resent(self, caplog):
        """THE defect direction: response started, wire died — the
        provider must be called exactly once, the failure surfaces
        the distinct error class, and one loud line names the spend."""
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()

            def _die_mid_response(*_a, **_kw):
                _mark_response_started()
                raise FakeAPIConnectionError("Connection error.")

            prov.generate.side_effect = _die_mid_response
            mock_get.return_value = prov
            with caplog.at_level("WARNING", logger="core.llm.client"):
                with pytest.raises(RuntimeError) as excinfo:
                    client.generate("prompt")
        assert prov.generate.call_count == 1
        # Distinct class in the causal chain, transport error beneath.
        cause = excinfo.value.__cause__
        assert isinstance(cause, MidResponseDeathError)
        assert isinstance(cause.__cause__, FakeAPIConnectionError)
        spend_lines = [
            r.message for r in caplog.records
            if "already processed (and billed)" in r.message
        ]
        assert len(spend_lines) == 1
        assert "NOT re-sending" in spend_lines[0]

    def test_pre_response_death_keeps_retrying(self):
        """The other direction: no response-started signal (connect
        failures, dispatcher pre-response 502s) keeps today's full
        retry budget."""
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate.side_effect = FakeAPIConnectionError(
                "Connection error.",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("prompt")
        assert prov.generate.call_count == 3

    def test_escape_hatch_retries_and_names_the_rebuy(
        self, caplog, monkeypatch,
    ):
        """RAPTOR_LLM_RETRY_CONSUMED=1: operator chose availability
        over cost — retries proceed, and every one is loudly named a
        re-purchase."""
        monkeypatch.setenv("RAPTOR_LLM_RETRY_CONSUMED", "1")
        client = _client(max_retries=2)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()

            def _die_mid_response(*_a, **_kw):
                _mark_response_started()
                raise FakeAPIConnectionError("Connection error.")

            prov.generate.side_effect = _die_mid_response
            mock_get.return_value = prov
            with caplog.at_level("WARNING", logger="core.llm.client"):
                with pytest.raises(RuntimeError):
                    client.generate("prompt")
        assert prov.generate.call_count == 2
        rebuy_lines = [
            r.message for r in caplog.records
            if "re-buys the generation" in r.message
        ]
        assert len(rebuy_lines) == 2

    def test_shape_failure_after_completed_response_keeps_retrying(self):
        """A COMPLETED response whose body fails to parse keeps its
        deliberate retry-as-new-sample semantics — the head stamp
        alone must not veto (only wire deaths qualify)."""
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()

            def _bad_sample(*_a, **_kw):
                _mark_response_started()
                raise json.JSONDecodeError("Expecting value", "doc", 0)

            prov.generate.side_effect = _bad_sample
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("prompt")
        assert prov.generate.call_count == 3

    def test_signal_does_not_leak_across_failures(self):
        """The veto consumes the signal: after a vetoed call, a later
        unrelated transport failure on the same thread retries
        normally."""
        client = _client(max_retries=2)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()

            def _die_mid_response(*_a, **_kw):
                _mark_response_started()
                raise FakeAPIConnectionError("Connection error.")

            prov.generate.side_effect = _die_mid_response
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate("prompt")
        assert prov.generate.call_count == 1
        assert take_upstream_response_started() is False

        client2 = _client(max_retries=2)
        with patch.object(client2, "_get_provider") as mock_get:
            prov2 = MagicMock()
            prov2.generate.side_effect = FakeAPIConnectionError(
                "Connection error.",
            )
            mock_get.return_value = prov2
            with pytest.raises(RuntimeError):
                client2.generate("prompt")
        assert prov2.generate.call_count == 2


class TestGenerateStructuredConsumedGate:
    def test_mid_response_death_is_not_resent(self, caplog):
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()

            def _die_mid_response(*_a, **_kw):
                _mark_response_started()
                raise FakeAPIConnectionError("Connection error.")

            prov.generate_structured.side_effect = _die_mid_response
            mock_get.return_value = prov
            with caplog.at_level("WARNING", logger="core.llm.client"):
                with pytest.raises(RuntimeError) as excinfo:
                    client.generate_structured(
                        "prompt", {"type": "object"},
                    )
        assert prov.generate_structured.call_count == 1
        assert isinstance(excinfo.value.__cause__, MidResponseDeathError)
        assert any(
            "NOT re-sending" in r.message for r in caplog.records
        )

    def test_pre_response_death_keeps_retrying(self):
        client = _client(max_retries=3)
        with patch.object(client, "_get_provider") as mock_get:
            prov = MagicMock()
            prov.generate_structured.side_effect = FakeAPIConnectionError(
                "Connection error.",
            )
            mock_get.return_value = prov
            with pytest.raises(RuntimeError):
                client.generate_structured("prompt", {"type": "object"})
        assert prov.generate_structured.call_count == 3

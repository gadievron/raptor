"""Schema-validity scorecard cell must record ONLY response-shape
failures.

Refusals, auth errors, budget aborts, quota and empty-content outcomes
are model/account/transport boundaries: they say nothing about whether
the model can emit schema-conformant output. Counting them as schema
failures corrupted the ``_structured`` decision class (Wilson bounds /
calibrated merge weights drifted toward models that were merely being
refused or rate-limited).
"""

from __future__ import annotations

import json

import pytest

from core.llm.client import (
    LLMClient,
    _failure_disposition,
    _is_response_shape_failure,
)
from core.llm.config import LLMConfig, ModelConfig
from core.llm.response_validation import SchemaUnknownFieldError

# ---------------------------------------------------------------------------
# Unit: _failure_disposition taxonomy
# ---------------------------------------------------------------------------


def test_refusal_disposition_is_blocked() -> None:
    e = RuntimeError(
        "Anthropic model refused request (stop_reason=refusal, empty content)"
    )
    assert _failure_disposition(e) == "blocked"


def test_auth_error_gets_own_disposition() -> None:
    assert _failure_disposition(RuntimeError("401 unauthorized")) == "auth"
    assert _failure_disposition(
        RuntimeError("invalid api key provided")) == "auth"


def test_budget_abort_gets_own_disposition() -> None:
    assert _failure_disposition(
        RuntimeError("claude -p exited 1: error_max_budget_usd")) == "budget"
    assert _failure_disposition(
        RuntimeError("your credit balance is too low")) == "budget"


def test_shape_failure_disposition_stays_fatal() -> None:
    e = ValueError("schema validation failed: missing required field 'x'")
    assert _failure_disposition(e) == "fatal"


# ---------------------------------------------------------------------------
# Unit: _is_response_shape_failure predicate
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("error", [
    RuntimeError(
        "Anthropic model refused request (stop_reason=refusal, empty content)"
    ),
    RuntimeError("401 unauthorized"),
    RuntimeError("403 permission denied"),
    RuntimeError("claude -p exited 1: error_max_budget_usd"),
    RuntimeError("your credit balance is too low"),
    RuntimeError("Anthropic returned empty content (stop_reason=end_turn)"),
    RuntimeError("Gemini returned empty response (finish_reason=OTHER)"),
    RuntimeError("429 rate limit exceeded"),
    TimeoutError("read timed out"),
    ConnectionError("connection reset by peer"),
])
def test_boundary_failures_are_not_shape_failures(error: Exception) -> None:
    assert not _is_response_shape_failure(error)


@pytest.mark.parametrize("error", [
    SchemaUnknownFieldError("unknown field 'foo' not in schema"),
    ValueError("schema validation failed: missing required field 'x'"),
    RuntimeError("claude -p structured parse failed: no JSON found"),
])
def test_shape_failures_are_recorded(error: Exception) -> None:
    assert _is_response_shape_failure(error)


# ---------------------------------------------------------------------------
# Integration: the _structured cell only counts shape failures
# ---------------------------------------------------------------------------


class _RaisingProvider:
    def __init__(self, exc: Exception):
        self.exc = exc
        self.total_cost = 0.0
        self.total_tokens = 0

    def generate_structured(self, prompt, schema, system_prompt=None,
                            **kwargs):
        raise self.exc


def _client_with(exc: Exception) -> LLMClient:
    config = LLMConfig(
        primary_model=ModelConfig(
            provider="anthropic", model_name="test-model", api_key="k",
        ),
        enable_caching=False,
        enable_fallback=False,
        enable_cost_tracking=False,
        max_retries=1,
    )
    client = LLMClient(config)
    provider = _RaisingProvider(exc)
    client._get_provider = lambda model_config: provider
    client.providers["anthropic:test-model"] = provider
    return client


_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def _fired_schema_cell(client: LLMClient) -> dict:
    return getattr(client, "_fired_schema", None) or {}


def test_refusal_does_not_corrupt_structured_cell() -> None:
    client = _client_with(RuntimeError(
        "Anthropic model refused request (stop_reason=refusal, empty content)"
    ))
    with pytest.raises(Exception):
        client.generate_structured("p", _SCHEMA)
    cell = _fired_schema_cell(client).get("test-model", {})
    assert cell.get("fail", 0) == 0


def test_auth_error_does_not_corrupt_structured_cell() -> None:
    client = _client_with(RuntimeError("401 unauthorized: invalid api key"))
    with pytest.raises(Exception):
        client.generate_structured("p", _SCHEMA)
    cell = _fired_schema_cell(client).get("test-model", {})
    assert cell.get("fail", 0) == 0


def test_budget_abort_does_not_corrupt_structured_cell() -> None:
    client = _client_with(RuntimeError(
        "claude -p exited 1: error_max_budget_usd"))
    with pytest.raises(Exception):
        client.generate_structured("p", _SCHEMA)
    cell = _fired_schema_cell(client).get("test-model", {})
    assert cell.get("fail", 0) == 0


def test_shape_failure_still_records_scorecard_fail() -> None:
    client = _client_with(ValueError(
        "schema validation failed: missing required field 'x'"))
    with pytest.raises(Exception):
        client.generate_structured("p", _SCHEMA)
    cell = _fired_schema_cell(client).get("test-model", {})
    assert cell.get("fail", 0) >= 1


def test_json_decode_failure_retries_without_boundary_record() -> None:
    """Malformed JSON is retryable — the per-attempt record policy for
    it is unchanged by the disposition split (parity pin)."""
    client = _client_with(json.JSONDecodeError("Expecting value", "", 0))
    with pytest.raises(Exception):
        client.generate_structured("p", _SCHEMA)
    cell = _fired_schema_cell(client).get("test-model", {})
    assert cell.get("fail", 0) == 0

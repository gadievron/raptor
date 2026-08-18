"""Refusals surfaced through the instructor tool-use leg.

A hard refusal on the tool-use leg has no tool call to parse:
instructor sees ``{}``, raises a validation-shaped
``InstructorRetryException``, and (pre-fix) the provider counted it
toward the instructor-disable cap and re-sent the same content via the
JSON fallback — one more guaranteed-refused call, and three such
refusals would permanently disable instructor for the session. The
provider now probes the exception's raw completions for
``stop_reason="refusal"`` and raises the canonical "model refused"
error immediately (bucketed 'blocked', non-retryable upstream).
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import (
    AnthropicProvider,
    _instructor_refusal_stop,
)


def _completion(stop_reason: str | None) -> SimpleNamespace:
    return SimpleNamespace(stop_reason=stop_reason, content=[])


class _FakeInstructorRetryException(Exception):
    """Shape-compatible stand-in for instructor's exception."""

    def __init__(self, last_completion=None, failed_attempts=()):
        super().__init__("3 validation errors for DynamicSchema")
        self.last_completion = last_completion
        self.failed_attempts = list(failed_attempts)


class TestInstructorRefusalStop:
    def test_refusal_on_last_completion(self):
        exc = _FakeInstructorRetryException(
            last_completion=_completion("refusal"),
        )
        assert _instructor_refusal_stop(exc) == "refusal"

    def test_refusal_on_earlier_attempt(self):
        exc = _FakeInstructorRetryException(
            last_completion=None,
            failed_attempts=[
                SimpleNamespace(completion=_completion("refusal")),
            ],
        )
        assert _instructor_refusal_stop(exc) == "refusal"

    def test_validation_flake_is_not_refusal(self):
        exc = _FakeInstructorRetryException(
            last_completion=_completion("end_turn"),
        )
        assert _instructor_refusal_stop(exc) is None

    def test_non_instructor_exception(self):
        assert _instructor_refusal_stop(RuntimeError("boom")) is None


@pytest.fixture
def provider(monkeypatch):
    pytest.importorskip("anthropic")
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    config = ModelConfig(
        provider="anthropic",
        model_name="claude-test",
        api_key="dummy-key-for-tests",
    )
    p = AnthropicProvider(config)
    p.client = MagicMock()
    return p


_SCHEMA = {
    "type": "object",
    "properties": {"verdict": {"type": "string"}},
    "required": ["verdict"],
}


class TestGenerateStructuredRefusal:
    def test_refusal_raises_blocked_and_skips_fallback(self, provider):
        instructor_client = MagicMock()
        instructor_client.messages.create_with_completion.side_effect = (
            _FakeInstructorRetryException(
                last_completion=_completion("refusal"),
            )
        )
        provider.instructor_client = instructor_client
        provider._structured_fallback = MagicMock()

        with pytest.raises(RuntimeError, match="model refused request"):
            provider.generate_structured("prompt", _SCHEMA)

        # Not re-sent via the JSON fallback: an identical retry cannot
        # change a refusal.
        provider._structured_fallback.assert_not_called()
        # Not counted toward the instructor-disable cap: a model
        # boundary is not instructor unreliability.
        assert provider._instructor_consec_failures == 0
        assert provider.instructor_client is not None

    def test_refusal_error_buckets_blocked(self, provider):
        from core.llm.structured_call import classify_error_text

        provider.instructor_client = MagicMock()
        provider.instructor_client.messages.create_with_completion.side_effect = (
            _FakeInstructorRetryException(
                last_completion=_completion("refusal"),
            )
        )
        provider._structured_fallback = MagicMock()
        with pytest.raises(RuntimeError) as excinfo:
            provider.generate_structured("prompt", _SCHEMA)
        assert classify_error_text(str(excinfo.value)) == "blocked"

    def test_validation_failure_still_falls_back(self, provider):
        instructor_client = MagicMock()
        instructor_client.messages.create_with_completion.side_effect = (
            _FakeInstructorRetryException(
                last_completion=_completion("end_turn"),
            )
        )
        provider.instructor_client = instructor_client
        sentinel = object()
        provider._structured_fallback = MagicMock(return_value=sentinel)

        assert provider.generate_structured("prompt", _SCHEMA) is sentinel
        provider._structured_fallback.assert_called_once()
        assert provider._instructor_consec_failures == 1

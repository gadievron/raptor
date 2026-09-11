"""Instructor-funnel failure routing.

The blanket ``except Exception`` around the instructor call used to
fall straight through to ``_structured_fallback`` — an immediate paid
re-send of the SAME payload — for every failure class. Refusals fail
identically on re-send, auth errors fail identically, and a 429 gets
hammered with zero backoff. Those boundary failures must re-raise to
the client's retry policy (which applies backoff / non-retryable
classification) instead, must not count toward the instructor-disable
strike counter, and a completed-but-invalid generation's spend must be
booked on the provider ledger.
"""

from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from core.llm.config import ModelConfig
from core.llm.providers import LLMProvider, StructuredResponse

# ---------------------------------------------------------------------------
# Unit: route classification
# ---------------------------------------------------------------------------


def _transport_exc(msg: str) -> Exception:
    """Exception whose class is stamped with an SDK module root, the
    way real transport errors present. Quota/auth message sniffing
    only applies to transport-typed exceptions — a validation/shape
    exception's message embeds the model's raw output, where the same
    vocabulary is content, not an API status."""
    exc_type = type("FakeAPIStatusError", (Exception,), {})
    exc_type.__module__ = "openai"
    return exc_type(msg)


@pytest.mark.parametrize("exc,expected", [
    (RuntimeError("model refused to respond"), "blocked"),
    (RuntimeError("content filter triggered"), "blocked"),
    (_transport_exc("401 unauthorized"), "auth"),
    (_transport_exc("invalid api key"), "auth"),
    (_transport_exc("429 too many requests"), "quota"),
    (_transport_exc("rate limit exceeded, retry in 20s"), "quota"),
    (_transport_exc("quota exceeded for model"), "quota"),
    (ValueError("1 validation error for Model"), "fallback"),
    (RuntimeError("connection reset"), "fallback"),
    # Non-transport exception types never route on quota/auth
    # vocabulary in their message — the recoverable fallback wins.
    (RuntimeError("429 too many requests"), "fallback"),
    (ValueError("model said: rate limit exceeded"), "fallback"),
])
def test_instructor_exception_route(exc: Exception, expected: str) -> None:
    assert LLMProvider._instructor_exception_route(exc) == expected


def test_validation_error_embedding_429_routes_fallback() -> None:
    """A pydantic ValidationError's message embeds the offending input
    — the model's raw output. A '429'/'rate limit' inside that is
    content from a completed, recoverable generation: it must reach
    the JSON fallback, not be re-raised as a quota boundary."""
    pydantic = pytest.importorskip("pydantic")

    class _Shape(pydantic.BaseModel):
        count: int

    with pytest.raises(pydantic.ValidationError) as excinfo:
        _Shape.model_validate({"count": "HTTP 429 rate limit exceeded"})
    exc = excinfo.value
    assert "429" in str(exc)
    assert LLMProvider._instructor_exception_route(exc) == "fallback"


def test_real_transport_429_still_routes_quota() -> None:
    """The other direction: genuine API rate-limit signals keep the
    quota route — SDK-module exception classes by message, and any
    exception carrying ``status_code == 429``."""
    assert LLMProvider._instructor_exception_route(
        _transport_exc("Error code: 429 - rate limit")) == "quota"
    exc = RuntimeError("too many requests")
    exc.status_code = 429  # type: ignore[attr-defined] — SDK errors carry this
    assert LLMProvider._instructor_exception_route(exc) == "quota"


def test_rate_limit_error_type_routes_quota() -> None:
    class RateLimitError(Exception):
        pass
    assert LLMProvider._instructor_exception_route(
        RateLimitError("slow down")) == "quota"


def test_authentication_error_type_routes_auth() -> None:
    class AuthenticationError(Exception):
        pass
    assert LLMProvider._instructor_exception_route(
        AuthenticationError("nope")) == "auth"


# ---------------------------------------------------------------------------
# Provider-level routing (OpenAI-compat shape)
# ---------------------------------------------------------------------------


def _openai_provider(monkeypatch, exc: Exception):
    pytest.importorskip("openai")
    from core.llm.providers import OpenAICompatibleProvider
    provider = OpenAICompatibleProvider(ModelConfig(
        provider="openai", model_name="gpt-5.2",
        api_key="sk-test", timeout=1,
    ))
    fake_instructor = MagicMock()
    fake_instructor.chat.completions.create_with_completion.side_effect = exc
    provider.instructor_client = fake_instructor
    fallback_calls: list = []

    def _fake_fallback(*a, **k):
        fallback_calls.append(a)
        return StructuredResponse(result={}, raw="{}")

    monkeypatch.setattr(provider, "_structured_fallback", _fake_fallback)
    return provider, fallback_calls


_SCHEMA = {"type": "object", "properties": {"x": {"type": "string"}}}


def test_refusal_does_not_resend_via_fallback(monkeypatch) -> None:
    provider, fallback_calls = _openai_provider(
        monkeypatch, RuntimeError("model refused to respond"))
    with pytest.raises(RuntimeError, match="refused"):
        provider.generate_structured("p", _SCHEMA)
    assert fallback_calls == []
    # Not an instructor strike — boundary failures say nothing about
    # instructor's reliability.
    assert provider._instructor_consec_failures == 0
    assert provider.instructor_client is not None


def test_auth_error_does_not_resend_via_fallback(monkeypatch) -> None:
    # Transport-typed: auth message sniffing applies to SDK/transport
    # exception classes only.
    provider, fallback_calls = _openai_provider(
        monkeypatch, _transport_exc("401 unauthorized: invalid api key"))
    with pytest.raises(Exception, match="401"):
        provider.generate_structured("p", _SCHEMA)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0


def test_429_reraises_for_client_backoff(monkeypatch) -> None:
    """A 429 must reach the client's retry loop (which sleeps between
    attempts), not trigger an instant same-payload fallback re-send."""
    provider, fallback_calls = _openai_provider(
        monkeypatch, _transport_exc("429 rate limit exceeded"))
    with pytest.raises(Exception, match="429"):
        provider.generate_structured("p", _SCHEMA)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0


def test_shape_failure_still_falls_back_and_strikes(monkeypatch) -> None:
    provider, fallback_calls = _openai_provider(
        monkeypatch, ValueError("1 validation error for Model"))
    out = provider.generate_structured("p", _SCHEMA)
    assert out.result == {}
    assert len(fallback_calls) == 1
    assert provider._instructor_consec_failures == 1


def test_anthropic_refusal_does_not_resend(monkeypatch) -> None:
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider
    provider = AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-sonnet-4-6",
        api_key="sk-ant-test", timeout=1,
    ))
    fake_instructor = MagicMock()
    fake_instructor.messages.create_with_completion.side_effect = (
        RuntimeError("model refused to respond"))
    provider.instructor_client = fake_instructor
    fallback_calls: list = []
    monkeypatch.setattr(
        provider, "_structured_fallback",
        lambda *a, **k: fallback_calls.append(a))
    with pytest.raises(RuntimeError, match="refused"):
        provider.generate_structured("p", _SCHEMA)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0


# ---------------------------------------------------------------------------
# Exception-path usage booking
# ---------------------------------------------------------------------------


def test_failed_instructor_call_books_usage(monkeypatch) -> None:
    """Pydantic validation failure happens AFTER a completed (paid)
    generation — the spend attached to the exception's last_completion
    must reach track_usage."""
    exc = ValueError("1 validation error for Model")
    exc.last_completion = SimpleNamespace(
        usage=SimpleNamespace(prompt_tokens=100, completion_tokens=50),
    )
    provider, _ = _openai_provider(monkeypatch, exc)
    booked: list = []
    original = provider.track_usage

    def _spy(*a, **k):
        booked.append((a, k))
        return original(*a, **k)

    monkeypatch.setattr(provider, "track_usage", _spy)
    provider.generate_structured("p", _SCHEMA)
    assert booked, "failed call's usage never reached track_usage"
    args, kwargs = booked[0]
    # (tokens, cost, input_tokens, output_tokens, duration)
    assert args[0] == 150
    assert args[2] == 100
    assert args[3] == 50
    assert provider.total_tokens == 150


def test_failed_call_books_anthropic_shaped_usage() -> None:
    """The booking helper reads both OpenAI (prompt/completion) and
    Anthropic (input/output) usage field names."""
    with patch.multiple(LLMProvider, __abstractmethods__=set()):
        provider = LLMProvider.__new__(LLMProvider)
    provider.config = ModelConfig(
        provider="anthropic", model_name="claude-sonnet-4-6",
        api_key="k",
    )
    provider.total_cost = 0.0
    provider.total_tokens = 0
    provider.call_count = 0
    provider._instructor_lock = threading.Lock()
    booked: list = []
    provider.track_usage = lambda *a, **k: booked.append(a)
    exc = ValueError("validation error")
    exc.last_completion = SimpleNamespace(
        usage=SimpleNamespace(input_tokens=7, output_tokens=3),
    )
    provider._book_instructor_failure_usage(exc, 0.5)
    assert booked and booked[0][0] == 10


def test_no_completion_books_nothing() -> None:
    with patch.multiple(LLMProvider, __abstractmethods__=set()):
        provider = LLMProvider.__new__(LLMProvider)
    provider.config = ModelConfig(
        provider="openai", model_name="gpt-5.2", api_key="k",
    )
    booked: list = []
    provider.track_usage = lambda *a, **k: booked.append(a)
    provider._book_instructor_failure_usage(RuntimeError("net down"), 0.1)
    assert booked == []


# ---------------------------------------------------------------------------
# Truncation in the JSON fallback is non-retryable
# ---------------------------------------------------------------------------


def test_fallback_truncation_raises_non_retryable(monkeypatch) -> None:
    """An identical retry at the same max_tokens re-truncates
    deterministically — the failure must classify non-retryable (like
    the Gemini native guard), not as a retryable JSON parse error."""
    import json as _json

    from core.llm.client import _is_retryable_error

    pytest.importorskip("openai")
    from core.llm.providers import LLMResponse, OpenAICompatibleProvider
    provider = OpenAICompatibleProvider(ModelConfig(
        provider="openai", model_name="gpt-5.2",
        api_key="sk-test", timeout=1,
    ))
    monkeypatch.setattr(
        provider, "generate",
        lambda *a, **k: LLMResponse(
            content='{"x": "trunca', model="gpt-5.2", provider="openai",
            tokens_used=10, cost=0.0, finish_reason="length",
        ),
    )
    from core.llm.providers import _dict_schema_to_pydantic
    with pytest.raises(RuntimeError) as excinfo:
        provider._structured_fallback(
            "p", _SCHEMA, _dict_schema_to_pydantic(_SCHEMA))
    assert not isinstance(excinfo.value, _json.JSONDecodeError)
    assert not _is_retryable_error(excinfo.value)
    # The audit orchestrator's _classify_error keys on this phrasing.
    assert "truncated (output token limit" in str(excinfo.value)


def test_fallback_truncation_classifies_as_truncation() -> None:
    from core.audit.orchestrator import _classify_error
    exc = RuntimeError(
        "Response truncated (output token limit reached, "
        "finish_reason=length)")
    assert _classify_error(exc) == "truncation"


# ---------------------------------------------------------------------------
# Truncation on the instructor tool-use leg (anthropic/bedrock shape)
# ---------------------------------------------------------------------------


class _FakeIncompleteOutput(Exception):
    """Shape-compatible stand-in for instructor's
    ``IncompleteOutputException``: same message, with the partial
    completion (``stop_reason="max_tokens"``) riding on
    ``last_completion``."""

    def __init__(self, last_completion=None):
        super().__init__(
            "The output is incomplete due to a max_tokens length limit.")
        self.last_completion = last_completion


class _FakeValidationError(ValueError):
    """Validation-shaped instructor failure carrying raw completions."""

    def __init__(self, last_completion=None, failed_attempts=()):
        super().__init__("1 validation error for Model")
        self.last_completion = last_completion
        self.failed_attempts = list(failed_attempts)


def _truncated_completion(stop_reason: str = "max_tokens") -> SimpleNamespace:
    return SimpleNamespace(
        stop_reason=stop_reason,
        content=[],
        usage=SimpleNamespace(input_tokens=100, output_tokens=8192),
    )


def _anthropic_provider(monkeypatch, exc: Exception,
                        provider_name: str = "anthropic",
                        model_name: str = "claude-sonnet-4-6"):
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    provider = AnthropicProvider(ModelConfig(
        provider=provider_name, model_name=model_name,
        api_key="sk-ant-test", timeout=1,
    ))
    fake_instructor = MagicMock()
    fake_instructor.messages.create_with_completion.side_effect = exc
    provider.instructor_client = fake_instructor
    fallback_calls: list = []
    monkeypatch.setattr(
        provider, "_structured_fallback",
        lambda *a, **k: fallback_calls.append(a))
    return provider, fallback_calls


class TestInstructorTruncationStop:
    """Unit: probing an instructor-funnel exception for a length-limit
    stop reason (same contract as ``_instructor_refusal_stop``)."""

    def test_max_tokens_on_last_completion(self) -> None:
        from core.llm.providers import _instructor_truncation_stop
        exc = _FakeIncompleteOutput(
            last_completion=_truncated_completion())
        assert _instructor_truncation_stop(exc) == "max_tokens"

    def test_length_stop_on_earlier_attempt(self) -> None:
        from core.llm.providers import _instructor_truncation_stop
        exc = _FakeValidationError(failed_attempts=[
            SimpleNamespace(completion=_truncated_completion("length")),
        ])
        assert _instructor_truncation_stop(exc) == "length"

    def test_incomplete_output_type_matches_without_completion(self) -> None:
        """The exception type is a definitional truncation signal even
        when no completion rides on it."""
        pytest.importorskip("instructor")
        try:
            # instructor >= 1.9: public exceptions live in
            # instructor.core; the old path is deprecated-for-removal.
            from instructor.core import IncompleteOutputException
        except ImportError:  # older installs predating instructor.core
            from instructor.exceptions import IncompleteOutputException

        from core.llm.providers import _instructor_truncation_stop
        exc = IncompleteOutputException(last_completion=None)
        assert _instructor_truncation_stop(exc) == "max_tokens"

    def test_complete_stop_is_not_truncation(self) -> None:
        from core.llm.providers import _instructor_truncation_stop
        exc = _FakeValidationError(
            last_completion=SimpleNamespace(stop_reason="end_turn"))
        assert _instructor_truncation_stop(exc) is None

    def test_non_instructor_exception(self) -> None:
        from core.llm.providers import _instructor_truncation_stop
        assert _instructor_truncation_stop(RuntimeError("boom")) is None


def test_anthropic_truncation_skips_fallback_and_names_condition(
        monkeypatch, caplog) -> None:
    """A structured response cut by the output token budget must be
    detected on the instructor leg itself: no strike toward the
    instructor-disable cap (a model output-budget boundary is not
    instructor unreliability), no JSON fallback re-send (an identical
    re-send at the same max_tokens re-truncates deterministically —
    one more paid call for a guaranteed failure), and a log line that
    names the condition."""
    provider, fallback_calls = _anthropic_provider(
        monkeypatch,
        _FakeIncompleteOutput(last_completion=_truncated_completion()),
    )
    with caplog.at_level("WARNING", logger="core.llm.providers"):  # noqa: SIM117
        with pytest.raises(RuntimeError) as excinfo:
            provider.generate_structured("p", _SCHEMA)
    # The audit orchestrator's _classify_error keys on this phrasing.
    assert "truncated (output token limit" in str(excinfo.value)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0
    assert provider.instructor_client is not None
    assert any(
        "truncated" in r.getMessage()
        and "stop_reason=max_tokens" in r.getMessage()
        for r in caplog.records
    ), "no log line naming the truncation condition"


def test_bedrock_truncation_classifies_truncation_for_retry(
        monkeypatch) -> None:
    """Bedrock rides the Anthropic provider. Its truncation error must
    reach the audit orchestrator's classifier as "truncation" (retried
    there at reduced context), not masquerade as a schema/parse error
    out of a fallback re-send — and must not be retried in place by
    the client (same max_tokens re-truncates deterministically, like
    the Gemini native guard)."""
    from core.audit.orchestrator import _classify_error
    from core.llm.client import _is_retryable_error
    provider, fallback_calls = _anthropic_provider(
        monkeypatch,
        _FakeIncompleteOutput(last_completion=_truncated_completion()),
        provider_name="bedrock",
        model_name="anthropic.claude-sonnet-5",
    )
    with pytest.raises(RuntimeError) as excinfo:
        provider.generate_structured("p", _SCHEMA)
    assert _classify_error(excinfo.value) == "truncation"
    assert not _is_retryable_error(excinfo.value)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0


def test_real_instructor_incomplete_output_detected(monkeypatch) -> None:
    """The real instructor exception (as raised by its Anthropic
    handler on stop_reason="max_tokens") takes the truncation path."""
    pytest.importorskip("instructor")
    try:
        # instructor >= 1.9 moved the public exceptions to
        # instructor.core; the old instructor.exceptions path emits a
        # DeprecationWarning and is slated for removal.
        from instructor.core import IncompleteOutputException
    except ImportError:  # older installs predating instructor.core
        from instructor.exceptions import IncompleteOutputException
    provider, fallback_calls = _anthropic_provider(
        monkeypatch,
        IncompleteOutputException(
            last_completion=_truncated_completion()),
    )
    with pytest.raises(RuntimeError, match="truncated"):
        provider.generate_structured("p", _SCHEMA)
    assert fallback_calls == []
    assert provider._instructor_consec_failures == 0


def test_validation_flake_without_truncation_still_falls_back(
        monkeypatch) -> None:
    """An ordinary validation failure (completion ran to end_turn) must
    keep the existing route: JSON fallback plus an instructor strike."""
    exc = _FakeValidationError(
        last_completion=SimpleNamespace(stop_reason="end_turn"))
    provider, fallback_calls = _anthropic_provider(monkeypatch, exc)
    provider.generate_structured("p", _SCHEMA)
    assert len(fallback_calls) == 1
    assert provider._instructor_consec_failures == 1


# ---------------------------------------------------------------------------
# Gemini structured: safety block raises, no silent fallback
# ---------------------------------------------------------------------------


class TestGeminiStructuredSafetyBlock:

    @staticmethod
    def _make_gemini(mock_response):
        pytest.importorskip("google.genai")
        from core.llm.providers import GeminiProvider
        provider = GeminiProvider(ModelConfig(
            provider="gemini", model_name="gemini-2.5-flash",
            api_key="test-key", timeout=1,
        ))
        mock_client = MagicMock()
        mock_client.models.generate_content.return_value = mock_response
        provider._clients[threading.get_ident()] = mock_client
        return provider

    @staticmethod
    def _mock_response(text, finish_reason_name, out_tokens=0):
        fr = MagicMock()
        fr.name = finish_reason_name
        candidate = MagicMock()
        candidate.finish_reason = fr
        usage = MagicMock()
        usage.prompt_token_count = 50
        usage.candidates_token_count = out_tokens
        usage.thoughts_token_count = 0
        resp = MagicMock()
        resp.text = text
        resp.candidates = [candidate]
        resp.usage_metadata = usage
        return resp

    def test_safety_block_raises_blocked_not_fallback(self, monkeypatch):
        provider = self._make_gemini(self._mock_response("", "SAFETY"))
        fallback_calls: list = []
        monkeypatch.setattr(
            provider, "_structured_fallback",
            lambda *a, **k: fallback_calls.append(a))
        with pytest.raises(RuntimeError, match="blocked response"):
            provider.generate_structured("t", {"result": "string"})
        assert fallback_calls == []

    def test_blocked_error_classifies_blocked(self, monkeypatch):
        from core.llm.client import _failure_disposition
        provider = self._make_gemini(
            self._mock_response("", "PROHIBITED_CONTENT"))
        monkeypatch.setattr(
            provider, "_structured_fallback", lambda *a, **k: None)
        with pytest.raises(RuntimeError) as excinfo:
            provider.generate_structured("t", {"result": "string"})
        assert _failure_disposition(excinfo.value) == "blocked"

    def test_nonempty_text_still_parses(self, monkeypatch):
        provider = self._make_gemini(
            self._mock_response('{"result": "ok"}', "STOP", 20))
        out = provider.generate_structured("t", {"result": "string"})
        assert out.result["result"] == "ok"


def test_instructor_path_honours_per_call_max_tokens(monkeypatch) -> None:
    """A caller-supplied max_tokens must reach the instructor create
    call — pre-fix the path hardcoded config.max_tokens, so callers
    capping structured generations (study batches staying inside
    non-streaming request limits) silently ran at the full ceiling."""
    pytest.importorskip("anthropic")
    from core.llm.providers import AnthropicProvider

    provider = AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-opus-4-7",
        api_key="sk-test", max_tokens=128000, timeout=1,
    ))
    captured = {}

    class _FakeInstructor:
        class messages:
            @staticmethod
            def create_with_completion(**kw):
                captured.update(kw)
                raise RuntimeError("stop after capture")

    provider.instructor_client = _FakeInstructor()
    with pytest.raises(Exception):
        provider.generate_structured(
            "p", {"type": "object", "properties": {}},
            max_tokens=1234,
        )
    assert captured.get("max_tokens") == 1234

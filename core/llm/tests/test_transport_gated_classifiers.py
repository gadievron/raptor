"""Transport-provenance gate on the quota/credit classifiers.

Quota, daily-quota, and credit-exhaustion classification is a statement
about the PROVIDER TRANSPORT (HTTP status code, SDK error envelope) —
never about model-generated content. Validation/shape exceptions embed
raw model output in their messages, so hostile scanned content that
survives into a response could otherwise steer retry policy, telemetry
dispositions, and — worst — the session-wide ``_daily_quota_exhausted``
latch that suppresses a model for the remainder of the run.

The contract pinned here: a content-level vocabulary match without
transport corroboration is inert (logged, non-latching); typed SDK
``isinstance`` arms and ``status_code`` arms stay unconditional.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from core.llm.client import (  # noqa: E402
    LLMClient,
    _failure_disposition,
    _is_daily_quota_error,
    _is_quota_error,
    _is_retryable_error,
)
from core.llm.config import LLMConfig, ModelConfig  # noqa: E402
from core.llm.providers import is_credit_exhausted  # noqa: E402
from core.llm.response_validation import SchemaUnknownFieldError  # noqa: E402


class _FakeHTTPError(Exception):
    """Mimics an SDK HTTP error carrying a ``status_code``."""

    def __init__(self, status_code: int, message: str = "") -> None:
        self.status_code = status_code
        super().__init__(message)


def _transport_shaped(message: str) -> Exception:
    """An exception whose type reports a transport module root."""
    cls = type("FakeHttpxError", (Exception,), {"__module__": "httpx"})
    return cls(message)


class TestQuotaClassifierTransportGate:
    """Message arms of ``_is_quota_error`` need transport corroboration."""

    def test_model_echoed_field_name_is_inert(self) -> None:
        # The client's own strict schema floor quotes MODEL-CHOSEN
        # unknown field names — one injected key must not classify.
        e = SchemaUnknownFieldError(
            "structured response carried fields outside the requested "
            "schema: ['quota_exceeded_per_day']"
        )
        assert _is_quota_error(e) is False
        assert _is_daily_quota_error(e) is False
        assert _failure_disposition(e) != "quota"

    def test_bare_exception_quota_text_is_inert(self) -> None:
        e = Exception("API quota exceeded (per_day)")
        assert _is_quota_error(e) is False
        assert _is_daily_quota_error(e) is False

    def test_status_code_arm_still_classifies(self) -> None:
        e = _FakeHTTPError(429, "quota exceeded: per_day limit reached")
        assert _is_quota_error(e) is True
        assert _is_daily_quota_error(e) is True

    def test_transport_module_arm_still_classifies(self) -> None:
        e = _transport_shaped("quota exceeded, retry in 6h")
        assert _is_quota_error(e) is True
        assert _is_daily_quota_error(e) is True

    def test_gemini_free_tier_still_classifies_on_transport(self) -> None:
        e = _transport_shaped(
            "429 You exceeded your current quota. "
            "generate_content_free_tier_input_token_count"
        )
        assert _is_quota_error(e) is True

    def test_non_429_status_with_echoed_quota_text_is_inert(self) -> None:
        # 400 error bodies can echo request content — hostile prompt
        # text carrying quota vocabulary must not classify a plain
        # bad-request as quota, let alone arm the daily latch. Quota
        # boundaries ride 429; the status corroborates.
        e = _FakeHTTPError(
            400, "invalid request: unexpected input "
            "'quota exceeded, per_day limit reached'")
        assert _is_quota_error(e) is False
        assert _is_daily_quota_error(e) is False

    def test_statusless_transport_relay_stays_eligible(self) -> None:
        # CC/stream relays carry no numeric status — their envelopes
        # remain classifiable by vocabulary.
        from core.llm.cc_adapter import CCTransportError
        e = CCTransportError("claude -p exited 1: quota exceeded, per_day")
        assert _is_quota_error(e) is True
        assert _is_daily_quota_error(e) is True


class TestCreditClassifierTransportGate:
    """Message/body arms of ``is_credit_exhausted`` need transport
    corroboration — a content match must not kill retries or label the
    telemetry disposition ``budget``."""

    def test_model_output_billing_text_is_inert(self) -> None:
        e = ValueError(
            "1 validation error for Finding\nevidence\n  Input should be "
            "a valid string [input_value='handle insufficient_quota "
            "errors from the API']"
        )
        assert is_credit_exhausted(e) is False
        assert _failure_disposition(e) != "budget"

    def test_inert_match_does_not_kill_retry_policy(self) -> None:
        # Non-transport text mentioning billing vocabulary must fall
        # through to the ordinary retry classification, not the
        # credit-exhaustion hard stop.
        e = ValueError(
            "validation error [input_value='insufficient_quota'] — "
            "connection reset while parsing"
        )
        assert is_credit_exhausted(e) is False
        assert _is_retryable_error(e) is True  # "connection" pattern

    def test_status_code_arm_still_classifies(self) -> None:
        e = _FakeHTTPError(429, "You exceeded your current quota")
        assert is_credit_exhausted(e) is True

    def test_transport_module_arm_still_classifies(self) -> None:
        e = _transport_shaped("Your credit balance is too low")
        assert is_credit_exhausted(e) is True

    def test_cc_transport_envelope_still_classifies(self) -> None:
        # The claudecode transport relays the CLI's error envelope via
        # CCTransportError — billing text there is provider truth.
        from core.llm.cc_adapter import CCTransportError
        e = CCTransportError(
            "claude -p exited 1: your credit balance is too low")
        assert is_credit_exhausted(e) is True
        assert _failure_disposition(e) == "budget"

    def test_stream_relay_preserves_transport_corroboration(self) -> None:
        # _convert_stream_failure re-shapes raw SDK stream exceptions
        # into the RuntimeError convention; a transport-corroborated
        # source must stay corroborated through the re-shaping.
        from core.llm.providers import LLMProvider

        class _P(LLMProvider):
            def generate(self, *a: Any, **k: Any) -> Any:
                raise NotImplementedError

            def generate_structured(self, *a: Any, **k: Any) -> Any:
                raise NotImplementedError

        prov = _P(ModelConfig(provider="openai", model_name="m", api_key="k"))
        wrapped = prov._convert_stream_failure(
            _transport_shaped("your credit balance is too low"))
        assert isinstance(wrapped, RuntimeError)
        assert is_credit_exhausted(wrapped) is True
        # A non-transport source stays uncorroborated after wrapping.
        inert = prov._convert_stream_failure(
            ValueError("input_value='insufficient_quota'"))
        assert is_credit_exhausted(inert) is False


class TestIsApiTransportExceptionPublicSurface:
    """The gate predicate is public API for classifier consumers."""

    def test_status_code_counts_as_transport(self) -> None:
        from core.llm.providers import is_api_transport_exception
        assert is_api_transport_exception(_FakeHTTPError(429)) is True

    def test_plain_value_error_is_not_transport(self) -> None:
        from core.llm.providers import is_api_transport_exception
        assert is_api_transport_exception(ValueError("429 quota")) is False


class _StubProvider:
    """Numeric counters + a scripted ``generate_structured``."""

    def __init__(self, payloads: list[dict[str, Any]]) -> None:
        self.payloads = list(payloads)
        self.total_cost = 0.0
        self.total_tokens = 0
        self.calls = 0

    def generate_structured(
        self,
        prompt: str,
        schema: dict[str, Any],
        system_prompt: str | None = None,
        **kw: Any,
    ) -> tuple[dict[str, Any], str]:
        self.calls += 1
        payload = (
            self.payloads.pop(0) if len(self.payloads) > 1
            else self.payloads[0]
        )
        return payload, "raw"


class TestBudgetClassifierContentGate:
    """``is_budget_exceeded_error`` is RUN-TERMINAL — the audit
    executor's budget-stop predicate re-raises budget-classified
    exceptions out of the review loop. Its message arm must not be
    reachable with model-echoed content: the strict schema floor
    quotes model-chosen field names, and the all-models-failed wrapper
    relays that text into a bare RuntimeError, so one injected key
    literally named "budget exceeded" would otherwise stop the entire
    remaining run with zero transport failure and zero real spend."""

    SCHEMA = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }

    def test_typed_budget_error_classifies(self) -> None:
        from core.llm.client import (
            LLMBudgetExceededError,
            is_budget_exceeded_error,
        )
        e = LLMBudgetExceededError("LLM budget exceeded: $5.00 > $1.00")
        assert is_budget_exceeded_error(e) is True

    def test_chained_typed_budget_error_classifies(self) -> None:
        from core.llm.client import (
            LLMBudgetExceededError,
            is_budget_exceeded_error,
        )
        wrapper = RuntimeError("phase driver failed")
        wrapper.__cause__ = LLMBudgetExceededError(
            "LLM budget exceeded: $5.00 > $1.00")
        assert is_budget_exceeded_error(wrapper) is True

    def test_legacy_message_fallback_still_classifies(self) -> None:
        # Intermediaries that lose both the type and the chain
        # (subprocess relays, older code paths) keep working.
        from core.llm.client import is_budget_exceeded_error
        e = RuntimeError("worker relay: LLM budget exceeded, stopping")
        assert is_budget_exceeded_error(e) is True

    def test_shape_failure_chain_vetoes_message_match(self) -> None:
        from core.llm.client import is_budget_exceeded_error
        wrapper = RuntimeError(
            "Structured generation failed for all cloud models "
            "(tried 2 model(s)). Last error: structured response "
            "carried fields outside the requested schema: "
            "['budget exceeded']"
        )
        wrapper.__cause__ = SchemaUnknownFieldError(
            "structured response carried fields outside the requested "
            "schema: ['budget exceeded']"
        )
        assert is_budget_exceeded_error(wrapper) is False

    def test_model_echoed_key_cannot_stop_the_run(self) -> None:
        """E2E: hostile extra key named "budget exceeded" on every
        ladder model → the raised all-models-failed RuntimeError must
        NOT satisfy the executor's budget-terminal predicate."""
        from core.audit.executor import _is_budget_stop
        from core.llm.client import is_budget_exceeded_error

        cfg = LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-primary", api_key="k"),
            enable_caching=False, enable_fallback=False, max_retries=1)
        client = LLMClient(cfg)
        hostile = {"verdict": "ok", "budget exceeded": "x"}
        prov = _StubProvider([hostile])
        client._get_provider = (  # type: ignore[method-assign]
            lambda model: prov
        )
        with pytest.raises(RuntimeError) as excinfo:
            client.generate_structured("analyse", self.SCHEMA)
        exc = excinfo.value
        assert "budget exceeded" in str(exc).lower()  # echo IS relayed
        assert is_budget_exceeded_error(exc) is False
        assert _is_budget_stop(exc) is False

    def test_real_budget_stop_stays_terminal(self) -> None:
        """Both directions: a genuine cap breach still trips the
        executor's budget-terminal predicate."""
        from core.audit.executor import _is_budget_stop
        from core.llm.client import LLMBudgetExceededError

        cfg = LLMConfig(
            primary_model=ModelConfig(
                provider="openai", model_name="gpt-primary", api_key="k"),
            enable_caching=False, enable_fallback=False,
            max_cost_per_scan=1.0)
        client = LLMClient(cfg)
        client.total_cost = 5.0
        with pytest.raises(LLMBudgetExceededError) as excinfo:
            client.generate_structured("analyse", self.SCHEMA)
        assert _is_budget_stop(excinfo.value) is True


class TestDailyQuotaLatchNeedsTransport:
    """E2E: one model-echoed key must not suppress the primary model
    for the remainder of the session."""

    SCHEMA = {
        "type": "object",
        "properties": {"verdict": {"type": "string"}},
        "required": ["verdict"],
    }

    def test_hostile_extra_key_does_not_latch_primary(self) -> None:
        primary = ModelConfig(
            provider="openai", model_name="gpt-primary", api_key="k")
        fallback = ModelConfig(
            provider="anthropic", model_name="claude-fallback", api_key="k")
        cfg = LLMConfig(
            primary_model=primary, fallback_models=[fallback],
            enable_caching=False, max_retries=2)
        client = LLMClient(cfg)

        # Call 1: the primary's response carries ONE extra top-level
        # key (prompt-injection shape); the strict schema floor raises
        # SchemaUnknownFieldError quoting it.
        hostile = {"verdict": "ok", "quota_exceeded_per_day": "x"}
        clean = {"verdict": "ok"}
        prov_primary = _StubProvider([hostile])
        prov_fallback = _StubProvider([clean])
        client._get_provider = (  # type: ignore[method-assign]
            lambda model: prov_primary
            if model.model_name == "gpt-primary" else prov_fallback
        )

        client.generate_structured("analyse", self.SCHEMA)
        assert ("openai", "gpt-primary") not in client._daily_quota_exhausted

        # Call 2: the primary now answers cleanly — and IS asked again.
        prov_primary.payloads = [clean]
        before = prov_primary.calls
        r2 = client.generate_structured("analyse-2", self.SCHEMA)
        assert prov_primary.calls > before
        assert r2.model == "gpt-primary"

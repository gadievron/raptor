"""Tests for core.llm.structured_call — the shared call envelope.

Covers the one classifier (union vocabulary, word-boundary) and the
response unwrap, plus the cross-pipeline consistency contract: the
audit and /agentic seams must agree on what counts as a content-filter
block.
"""

from dataclasses import dataclass

from core.llm.structured_call import (
    StructuredCallResult,
    classify_error_text,
    is_auth_error_text,
    is_content_filter_text,
    unwrap_structured_response,
)


class TestClassifier:

    def test_blocked_union_vocabulary(self):
        # /agentic's original phrasings...
        assert classify_error_text("content filter engaged") == "blocked"
        assert classify_error_text("refused to respond") == "blocked"
        assert classify_error_text("moderation block") == "blocked"
        # ...plus audit's marker list (previously NOT classified as
        # blocked by the /agentic regex — the divergence this fixes):
        assert classify_error_text("model refused") == "blocked"
        assert classify_error_text("finish_reason=content_filter") == "blocked"
        assert classify_error_text("Response blocked by provider") == "blocked"

    def test_word_boundaries_prevent_substring_false_positives(self):
        # audit's substring markers would have matched these:
        assert classify_error_text("thread-safety violation in mutex") == "error"
        assert not is_content_filter_text("unsafety filtered dataset")
        # /agentic's documented 401-in-stack-trace case:
        assert classify_error_text('File "x.py", line 401, in foo') == "error"

    def test_auth(self):
        assert classify_error_text("HTTP 401 unauthorized") == "auth"
        assert classify_error_text("invalid api key") == "auth"
        assert classify_error_text("insufficient_quota") == "auth"
        assert is_auth_error_text("rate limit exceeded")
        assert not is_auth_error_text("credentials.py had a typo")

    def test_timeout(self):
        assert classify_error_text("read timed out") == "timeout"
        assert classify_error_text("deadline exceeded") == "timeout"

    def test_rate_limit_shapes_are_not_schema_errors(self):
        # The underscored provider error type and 429 statuses are the
        # same non-schema class as the spaced "rate limit".
        assert classify_error_text(
            "Error code: 429 - {'type': 'rate_limit_error'}") == "auth"
        assert classify_error_text("rate_limit_error") == "auth"
        assert classify_error_text("429 RESOURCE_EXHAUSTED") == "auth"
        assert classify_error_text("HTTP 429 Too Many Requests") == "auth"

    def test_unrelated_429_numerics_stay_error(self):
        # Boundary/context anchoring: a stack-trace line number or an
        # embedded numeric must not classify as a rate limit.
        assert classify_error_text(
            'File "x.py", line 429, in foo') == "error"
        assert classify_error_text("request id 14290 failed") == "error"

    def test_precedence_blocked_over_auth_over_timeout(self):
        assert classify_error_text(
            "content filter triggered after timeout") == "blocked"
        assert classify_error_text("quota exhausted; timed out") == "auth"

    def test_empty_and_none(self):
        assert classify_error_text("") == "error"
        assert classify_error_text(None) == "error"

    def test_pipeline_seams_agree(self):
        # The two pipelines' seams must be the SAME classifier.
        from core.audit.llm_review import _is_content_filter_error
        from packages.llm_analysis.dispatch import _classify_error
        for msg in ("model refused", "safety filter hit",
                    "blocked by content filter", "content_filter"):
            assert _classify_error(msg) == "blocked"
            assert _is_content_filter_error(RuntimeError(msg))
        for msg in ("thread-safety violation", "connection reset"):
            assert _classify_error(msg) == "error"
            assert not _is_content_filter_error(RuntimeError(msg))


@dataclass
class _FakeResponse:
    result: dict
    cost: float = 0.25
    model: str = "test-model"
    input_tokens: int = 10
    output_tokens: int = 5
    cache_read_tokens: int = 2
    cache_write_tokens: int = 1


class TestUnwrap:

    def test_structured_response_shape(self):
        call = unwrap_structured_response(_FakeResponse(result={"a": 1}))
        assert call.result == {"a": 1}
        assert call.cost == 0.25
        assert call.model == "test-model"
        assert call.usage == {
            "tokens_in": 10, "tokens_out": 5,
            "cache_read_tokens": 2, "cache_write_tokens": 1,
        }

    def test_legacy_tuple_shape(self):
        call = unwrap_structured_response(({"b": 2}, "raw text"))
        assert call.result == {"b": 2}
        assert call.cost == 0.0
        assert call.model == ""

    def test_empty_response_uses_sentinel(self):
        sentinel = {"status": "error"}
        assert unwrap_structured_response(
            None, empty_result=sentinel).result is sentinel
        assert unwrap_structured_response(
            (), empty_result=sentinel).result is sentinel

    def test_unsubscriptable_truthy_falls_back_to_sentinel(self):
        assert unwrap_structured_response(
            object(), empty_result="x").result == "x"

    def test_non_numeric_cost_coerced(self):
        @dataclass
        class Bad:
            result: dict
            cost: str = "not-a-number"
        assert unwrap_structured_response(Bad(result={})).cost == 0.0

    def test_default_result_type(self):
        assert isinstance(unwrap_structured_response(None),
                          StructuredCallResult)


class TestChainWalkingClassifiers:
    """Shared home for the blocked/refused predicates: every consumer
    must see a block hidden behind the all-models-failed wrapper's
    __cause__, and refusal vocabulary must stay narrower than the
    content-filter set (transport blocks must not classify refusal)."""

    def _wrapped(self, cause_msg: str) -> RuntimeError:
        cause = RuntimeError(cause_msg)
        wrapper = RuntimeError("All cloud models failed (tried 1 model(s)).")
        wrapper.__cause__ = cause
        return wrapper

    def test_content_filter_seen_through_cause_chain(self):
        from core.llm.structured_call import is_content_filter_error
        exc = self._wrapped("request blocked by content filter")
        assert is_content_filter_error(exc)

    def test_refusal_seen_through_cause_chain(self):
        from core.llm.structured_call import is_refusal_error
        exc = self._wrapped(
            "Anthropic model refused request (stop_reason=refusal)")
        assert is_refusal_error(exc)

    def test_transport_block_is_not_a_refusal(self):
        from core.llm.structured_call import (
            is_content_filter_error,
            is_refusal_error,
        )
        exc = self._wrapped("403: request blocked by security policy")
        assert not is_refusal_error(exc)
        assert is_content_filter_error(exc)

    def test_plain_transport_error_is_neither(self):
        from core.llm.structured_call import (
            is_content_filter_error,
            is_refusal_error,
        )
        exc = self._wrapped("connection reset by peer")
        assert not is_refusal_error(exc)
        assert not is_content_filter_error(exc)

    def test_connection_refused_is_not_a_refusal(self):
        from core.llm.structured_call import is_refusal_error
        assert not is_refusal_error(
            self._wrapped("[Errno 111] Connection refused"))
        exc = RuntimeError("All cloud models failed (tried 1 model(s)).")
        exc.__cause__ = ConnectionRefusedError(111, "Connection refused")
        assert not is_refusal_error(exc)

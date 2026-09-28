"""Retry / disposition classification for transport errors.

Four related invariants in ``core.llm.client``:

* google-genai wraps every 5xx in a bare ``ServerError`` whose message
  starts with the status ("500 INTERNAL ..."); it must classify as
  retryable, while its 4xx counterpart ``ClientError`` stays fatal.
* HTTP 529 / "overloaded_error" (capacity saturation) arrives as a
  generic status-error type that matches none of the retryable type
  names; it must classify retryable via the anchored 529 status / the
  "overloaded" message pattern.
* A fast HTTP 502/503/504 whose reason phrase contains "Timeout"
  ("Gateway Timeout") is a server-side transient, not a client-side
  timeout — it must ride the ordinary retryable path instead of
  burning the (possibly zero) timeout retry cap.
* Status codes carried in TEXT are boundary-anchored: unrelated
  numerics ("request 1500") never read as a status.
"""

from __future__ import annotations

import json

from core.llm.client import (
    _failure_disposition,
    _is_response_shape_failure,
    _is_retryable_error,
    is_timeout_error,
)


class FakeGenaiServerError(Exception):
    """Stands in for google.genai.errors.ServerError (name-matched)."""


class ServerError(FakeGenaiServerError):
    pass


class ClientError(Exception):
    pass


# ---------------------------------------------------------------------------
# 5xx retryability
# ---------------------------------------------------------------------------


class TestGenaiServerErrors:

    def test_server_error_type_is_retryable(self):
        err = ServerError(
            "500 INTERNAL. {'error': {'code': 500, "
            "'message': 'An internal error has occurred.'}}"
        )
        assert _is_retryable_error(err) is True

    def test_500_status_message_is_retryable_regardless_of_type(self):
        assert _is_retryable_error(
            RuntimeError("Error code: 500 - internal failure")) is True
        assert _is_retryable_error(RuntimeError("500 INTERNAL")) is True

    def test_client_error_400_stays_non_retryable(self):
        err = ClientError(
            "400 INVALID_ARGUMENT. {'error': {'code': 400, "
            "'message': 'Request contains an invalid argument.'}}"
        )
        assert _is_retryable_error(err) is False

    def test_bare_numerics_do_not_read_as_500(self):
        # "1500" must not match the 500-status arm.
        assert _is_retryable_error(
            RuntimeError("request id 1500 was rejected")) is False

    def test_bare_numerics_do_not_read_as_gateway(self):
        """Both directions of the anchored 502/503/504 arm: a fatal
        error embedding a 50x-shaped numeric must not classify
        retryable (pre-fix the bare substring burned max_retries paid
        attempts on it) ..."""
        assert _is_retryable_error(
            ValueError("prompt used 1502 tokens over budget")) is False
        assert _is_retryable_error(
            ValueError("schema id 5031 rejected")) is False

    def test_gateway_status_messages_stay_retryable(self):
        """... while genuine gateway statuses keep the retryable
        classification."""
        assert _is_retryable_error(
            RuntimeError("HTTP 502 Bad Gateway")) is True
        assert _is_retryable_error(
            RuntimeError("upstream returned 504")) is True


# ---------------------------------------------------------------------------
# 529 / overloaded (capacity saturation)
# ---------------------------------------------------------------------------


class TestOverloadedErrors:

    def test_529_overloaded_body_is_retryable(self) -> None:
        # Real provider error-string shape (synthetic request_id): the
        # SDK raises a status-error type whose name matches none of
        # the retryable type names, so the message must carry the
        # classification.
        err = RuntimeError(
            "Error code: 529 - {'type': 'error', 'request_id': "
            "'req_011CTsynthetic0000000000', 'error': {'type': "
            "'overloaded_error', 'message': 'Overloaded'}}"
        )
        assert _is_retryable_error(err) is True
        assert _failure_disposition(err) == "retryable"
        assert is_timeout_error(err) is False

    def test_529_status_without_overloaded_text_is_retryable(self) -> None:
        # The status arm must carry the classification on its own —
        # a relayed 529 can arrive without the word "overloaded"
        # anywhere in the message.
        assert _is_retryable_error(
            RuntimeError("Error code: 529 - upstream saturated")) is True

    def test_529_context_variants_are_retryable(self) -> None:
        # Every context the anchored RE accepts: explicit context word,
        # message-start status, and status + reason phrase.
        for msg in ("HTTP 529 from provider",
                    "status 529 returned by gateway",
                    "529 upstream capacity exceeded",
                    "529 Overloaded"):
            assert _is_retryable_error(RuntimeError(msg)) is True, msg

    def test_overloaded_error_without_status_is_retryable(self) -> None:
        # A relayed message can carry the body type without the
        # numeric status.
        assert _is_retryable_error(
            RuntimeError("overloaded_error: Overloaded")) is True

    def test_bare_overloaded_message_is_retryable(self) -> None:
        # ... or the human-readable message without the body type.
        assert _is_retryable_error(RuntimeError("Overloaded")) is True

    def test_bare_numerics_do_not_read_as_529(self) -> None:
        """Both directions of the anchored 529 arm: a fatal error
        embedding a 529-shaped numeric must stay non-retryable."""
        assert _is_retryable_error(
            RuntimeError(
                "Error code: 400 - {'error': {'message': 'prompt is "
                "1529 tokens over the limit'}}"
            )) is False

    def test_request_id_digits_do_not_read_as_529(self) -> None:
        # A request-id-like token embedding "529" between word
        # characters never reads as the status.
        assert _is_retryable_error(
            RuntimeError(
                "Error code: 400 - {'request_id': 'req_a529b', "
                "'error': {'message': 'invalid request'}}"
            )) is False

    def test_punctuation_adjacent_529_does_not_read_as_status(self) -> None:
        """Word boundaries alone are not enough: a 529 sitting next to
        punctuation (a parenthesised value, a stack-trace line number)
        is not a status and must leave a fatal error fatal."""
        assert _is_retryable_error(
            RuntimeError(
                "Error code: 400 - {'error': {'message': "
                "'invalid parameter (529)'}}"
            )) is False
        assert _is_retryable_error(
            RuntimeError(
                'ValueError at File "handler.py", line 529, in parse'
            )) is False

    def test_neighboring_status_digits_never_retryable(self) -> None:
        # Exact-digit pinning: adjacent 52x codes carry no retry
        # policy here, in any of the accepted status contexts.
        assert _is_retryable_error(
            RuntimeError("status 528 returned by gateway")) is False
        assert _is_retryable_error(
            RuntimeError("upstream trace recorded (520) mid-request")) is False


# ---------------------------------------------------------------------------
# Gateway statuses vs client-side timeouts
# ---------------------------------------------------------------------------


class TestGatewayVsTimeout:

    def test_gateway_timeout_message_is_transient_not_timeout(self):
        err = RuntimeError("504 Gateway Timeout")
        assert is_timeout_error(err) is False
        assert _is_retryable_error(err) is True
        assert _failure_disposition(err) == "retryable"

    def test_502_and_503_messages_are_transient_not_timeout(self):
        for msg in ("502 Bad Gateway timeout while proxying",
                    "503 Service Unavailable: upstream timeout"):
            err = RuntimeError(msg)
            assert is_timeout_error(err) is False
            assert _is_retryable_error(err) is True

    def test_genuine_client_side_timeout_still_classifies_timeout(self):
        assert is_timeout_error(TimeoutError("read operation timed out"))
        assert is_timeout_error(
            RuntimeError("claude -p timed out after 30s"))

    def test_timeout_exception_type_still_classifies_timeout(self):
        class ReadTimeout(Exception):
            pass

        assert is_timeout_error(ReadTimeout("read deadline hit")) is True


# ---------------------------------------------------------------------------
# Response-shape failure predicate
# ---------------------------------------------------------------------------


class TestResponseShapeFailure:

    def test_malformed_json_is_a_shape_failure(self):
        # Retryable AND a shape failure — the model emitted output
        # that failed to parse, which is exactly what the schema-
        # validity cell measures.
        err = json.JSONDecodeError("Expecting value", "", 0)
        assert _is_response_shape_failure(err) is True

    def test_generic_fatal_400_is_not_a_shape_failure(self):
        err = RuntimeError(
            "Error code: 400 - {'error': {'message': 'max_tokens too "
            "large for this request'}}"
        )
        assert _failure_disposition(err) == "fatal"
        assert _is_response_shape_failure(err) is False

    def test_schema_validation_failure_still_recorded(self):
        err = ValueError(
            "schema validation failed: missing required field 'x'")
        assert _is_response_shape_failure(err) is True

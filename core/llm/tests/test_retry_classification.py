"""Retry / disposition classification for transport errors.

Three related invariants in ``core.llm.client``:

* google-genai wraps every 5xx in a bare ``ServerError`` whose message
  starts with the status ("500 INTERNAL ..."); it must classify as
  retryable, while its 4xx counterpart ``ClientError`` stays fatal.
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

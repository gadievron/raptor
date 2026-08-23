"""Tests for the persistent-auth fail-closed substrate.

``AuthFailureTracker`` / ``LLMAuthPersistentError`` let phase drivers
distinguish "the LLM said nothing" from "the auth layer refused every
call" (a dead dispatcher token turned a >12 h audit's post-loop phases
into apparent empty successes across 690 straight 401s).
"""

from __future__ import annotations

import pytest

from core.llm.client import (
    AuthFailureTracker,
    LLMAuthPersistentError,
    is_auth_refusal,
)

# The wrapped shape LLMClient.generate actually raises after fallback
# exhaustion: a generic RuntimeError whose message retains the
# provider's status text.
TOKEN_EXPIRED_MSG = (
    "All cloud models failed (tried 1 model(s)).\n"
    "Last error: Error code: 401 - "
    "{'error': 'token expired (age 45011.6s, ttl 28800s)'}\n"
    "→ Check API keys and network connectivity"
)
UNKNOWN_TOKEN_MSG = (
    "All cloud models failed (tried 1 model(s)).\n"
    "Last error: Error code: 401 - {'error': 'unknown token'}"
)
GENERIC_401_MSG = (
    "All cloud models failed (tried 2 model(s)).\n"
    "Last error: Error code: 401 - authentication_error: "
    "invalid x-api-key"
)
NON_AUTH_MSG = "upstream error: ReadTimeout"


class TestIsAuthRefusal:
    def test_wrapped_401_is_auth(self):
        assert is_auth_refusal(RuntimeError(GENERIC_401_MSG))

    def test_token_expired_is_auth(self):
        assert is_auth_refusal(RuntimeError(TOKEN_EXPIRED_MSG))

    def test_timeout_is_not_auth(self):
        assert not is_auth_refusal(RuntimeError(NON_AUTH_MSG))

    def test_typed_abort_is_auth(self):
        assert is_auth_refusal(LLMAuthPersistentError("p", "m"))


class TestAuthFailureTracker:
    def test_trips_after_threshold_consecutive_auth_failures(self):
        t = AuthFailureTracker("phase-x")
        assert not t.note_failure(RuntimeError(GENERIC_401_MSG))
        assert not t.note_failure(RuntimeError(GENERIC_401_MSG))
        assert t.note_failure(RuntimeError(GENERIC_401_MSG))
        assert t.tripped

    def test_explicit_token_expired_trips_immediately(self):
        t = AuthFailureTracker("phase-x")
        assert t.note_failure(RuntimeError(TOKEN_EXPIRED_MSG))
        assert t.tripped

    def test_explicit_unknown_token_trips_immediately(self):
        t = AuthFailureTracker("phase-x")
        assert t.note_failure(RuntimeError(UNKNOWN_TOKEN_MSG))
        assert t.tripped

    def test_success_resets_streak(self):
        t = AuthFailureTracker("phase-x")
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_success()
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        assert not t.tripped

    def test_non_auth_failure_resets_streak(self):
        t = AuthFailureTracker("phase-x")
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_failure(RuntimeError(NON_AUTH_MSG))
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        assert not t.tripped

    def test_once_tripped_stays_tripped(self):
        t = AuthFailureTracker("phase-x")
        t.note_failure(RuntimeError(TOKEN_EXPIRED_MSG))
        t.note_success()
        assert t.tripped

    def test_raise_if_tripped_carries_phase(self):
        t = AuthFailureTracker("iris-assumptions")
        t.note_failure(RuntimeError(TOKEN_EXPIRED_MSG))
        with pytest.raises(LLMAuthPersistentError) as exc_info:
            t.raise_if_tripped()
        assert exc_info.value.phase == "iris-assumptions"
        assert "iris-assumptions" in str(exc_info.value)
        assert "auth" in str(exc_info.value)

    def test_raise_if_tripped_noop_when_healthy(self):
        t = AuthFailureTracker("phase-x")
        t.note_failure(RuntimeError(GENERIC_401_MSG))
        t.raise_if_tripped()  # must not raise


class TestClassifierPoisoningResistance:
    """Adversarial-review PoC-B inverted: classification must come
    from STRUCTURAL signals (typed causes, transport status codes) or
    a status-context-anchored word-boundary matcher — never from bare
    substrings over exception text, which quotes model/target-chosen
    content and JSON decode coordinates."""

    def test_json_decode_coordinates_do_not_trip(self):
        # PoC-B1 inverted: "column 401"/"column 4033" are coordinates,
        # not statuses. Three consecutive malformed-JSON failures must
        # not read as credential death.
        t = AuthFailureTracker("iris-assumptions")
        for msg in (
            "All cloud models failed (tried 1 model(s)).\n"
            "Last error: Expecting ',' delimiter: line 2 column 401 "
            "(char 4013)",
            "All cloud models failed (tried 1 model(s)).\n"
            "Last error: Expecting value: line 1 column 4033 (char 4032)",
            "All cloud models failed (tried 1 model(s)).\n"
            "Last error: Unterminated string starting at: line 3 "
            "column 14012 (char 14011)",
        ):
            t.note_failure(RuntimeError(msg))
        assert not t.tripped
        t.raise_if_tripped()  # must not raise

    def test_content_quoted_token_expired_does_not_classify(self):
        # PoC-B2 inverted: a schema-validation message QUOTING code
        # that mentions 401/token-expired ("resp.status == 401",
        # "die('token expired')") has no status context and no
        # error-field anchor — not auth, no instant trip.
        t = AuthFailureTracker("adversarial-refute")
        msg = (
            "All cloud models failed (tried 1 model(s)).\n"
            "Last error: schema validation failed for response "
            "\"if (resp.status == 401) die('token expired');\" — "
            "not of type 'object'"
        )
        assert not t.note_failure(RuntimeError(msg))
        assert not t.tripped

    def test_schema_field_name_with_cause_is_structurally_non_auth(self):
        # PoC-B3 inverted (structural arm): the client wraps the
        # original failure with ``raise ... from last_error``; a
        # response-shape cause (SchemaUnknownFieldError) is NEVER
        # auth, whatever field names the model chose to embed.
        from core.llm.response_validation import SchemaUnknownFieldError

        t = AuthFailureTracker("checker-synthesis")
        cause = SchemaUnknownFieldError(
            "structured response carried fields outside the requested "
            "schema: {'Error code: 401 - token expired'}"
        )
        wrapper = RuntimeError(
            "All cloud models failed (tried 1 model(s)).\n"
            f"Last error: {cause}"
            "\n→ Check API keys and network connectivity"
        )
        wrapper.__cause__ = cause
        assert not is_auth_refusal(wrapper)
        assert not t.note_failure(wrapper)
        assert not t.tripped

    def test_schema_field_name_without_cause_never_instant_trips(self):
        # PoC-B3 inverted (text arm): even when the causal chain was
        # lost, the anchored token-death regex does not match a field
        # name shaped "Error code: 401 - token expired" — one poisoned
        # response cannot instant-trip a phase abort.
        t = AuthFailureTracker("checker-synthesis")
        msg = (
            "All cloud models failed (tried 1 model(s)).\n"
            "Last error: structured response carried fields outside "
            "the requested schema: {'Error code: 401 - token expired'}"
        )
        assert not t.note_failure(RuntimeError(msg))
        assert not t.tripped

    def test_transport_status_code_is_structural_auth(self):
        class _Err(Exception):
            status_code = 401

        assert is_auth_refusal(_Err("refused"))

    def test_rate_limit_is_not_persistent_auth(self):
        # Quota/rate-limit vocabulary belongs to the auth/billing
        # UNION classifier, not the strict refusal class — a burst of
        # 429s must never abort a phase as credential death.
        t = AuthFailureTracker("iris-synth")
        for _ in range(3):
            t.note_failure(RuntimeError(
                "Error code: 429 - rate limit exceeded, retry in 20s",
            ))
        assert not t.tripped

    def test_dispatcher_shape_still_detected(self):
        # The genuine SDK shape "Error code: 401 - ..." (colon) must
        # keep matching the strict text classifier — the pre-existing
        # word-boundary matcher's `code\s+401` missed it.
        from core.llm.structured_call import is_auth_status_text

        assert is_auth_status_text(
            "Error code: 401 - {'error': 'unknown token'}",
        )
        assert not is_auth_status_text(
            "Expecting ',' delimiter: line 2 column 401 (char 4013)",
        )

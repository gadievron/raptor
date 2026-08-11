"""Test ``is_credit_exhausted()`` — provider-agnostic billing error detector."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT))

from core.llm.providers import is_credit_exhausted  # noqa: E402


class _FakeHTTPError(Exception):
    """Mimics an SDK HTTP error with ``status_code`` and optional ``body``."""

    def __init__(self, status_code: int, message: str = "", body: dict | None = None):
        self.status_code = status_code
        self.body = body
        super().__init__(message)


class TestIsCreditExhausted:
    """Unit tests for ``is_credit_exhausted``."""

    # ── Anthropic patterns ───────────────────────────────────────

    def test_anthropic_credit_balance_too_low(self):
        exc = _FakeHTTPError(400, "Your credit balance is too low")
        assert is_credit_exhausted(exc)

    # ── OpenAI patterns ──────────────────────────────────────────

    def test_openai_exceeded_quota(self):
        exc = _FakeHTTPError(429, "You exceeded your current quota")
        assert is_credit_exhausted(exc)

    def test_openai_insufficient_quota(self):
        exc = _FakeHTTPError(429, "insufficient_quota")
        assert is_credit_exhausted(exc)

    def test_openai_billing_hard_limit(self):
        exc = _FakeHTTPError(429, "billing hard limit reached")
        assert is_credit_exhausted(exc)

    # ── Generic billing patterns ─────────────────────────────────

    def test_account_deactivated(self):
        exc = _FakeHTTPError(403, "account has been deactivated")
        assert is_credit_exhausted(exc)

    def test_billing_not_active(self):
        exc = _FakeHTTPError(403, "billing not active")
        assert is_credit_exhausted(exc)

    def test_anthropic_spend_cap(self):
        """Anthropic spend-cap error (400, usage limits message)."""
        exc = _FakeHTTPError(
            400,
            "You have reached your specified API usage limits. "
            "You will regain access on 2026-09-01 at 00:00 UTC.",
        )
        assert is_credit_exhausted(exc)

    # ── Body-dict extraction ─────────────────────────────────────

    def test_body_dict_message_field(self):
        exc = _FakeHTTPError(
            400, "error",
            body={"error": {"message": "Your credit balance is too low"}},
        )
        assert is_credit_exhausted(exc)

    def test_body_dict_string_error(self):
        exc = _FakeHTTPError(
            400, "error",
            body={"error": "Your credit balance is too low"},
        )
        assert is_credit_exhausted(exc)

    # ── Negative cases ───────────────────────────────────────────

    def test_5xx_never_billing(self):
        """5xx is server-side — never a billing error."""
        exc = _FakeHTTPError(500, "credit balance is too low")
        assert not is_credit_exhausted(exc)

    def test_429_rate_limit_not_credit(self):
        """Plain rate-limit without billing keywords is not credit."""
        exc = _FakeHTTPError(429, "Rate limit exceeded, try again later")
        assert not is_credit_exhausted(exc)

    def test_403_unrelated(self):
        exc = _FakeHTTPError(403, "Forbidden — invalid API key")
        assert not is_credit_exhausted(exc)

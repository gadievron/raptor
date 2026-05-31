"""Tests for ``LLMClient(pinned_model=…)`` — caller-pinned model mode.

When a caller signals it will override the model on every ``generate()``
call (via ``model_config=``), the previous code path resolved + advertised
the operator's default ``primary_model`` anyway.  The log read
``Primary model: gemini-2.5-pro`` even when every call would actually hit
Anthropic, plus the upstream thinking-model auto-resolution path fired
its own misleading ``Auto-selected thinking model: gemini…`` line.

Pinned mode short-circuits both: ``_pinned_llm_config`` calls the inferred
provider's builder directly (so the resolver's lenient fall-through to
"whatever provider IS configured" can't substitute a different provider
for the pinned one), the fallback chain is empty, and the banner reflects
what's actually going to fire.
"""

from __future__ import annotations

import logging

from core.llm.client import LLMClient, _pinned_llm_config


class _RaptorLogCapture:
    """Capture records sent to the ``raptor`` logger.

    RAPTOR's :class:`RaptorLogger` sets ``propagate=False`` on the
    ``raptor`` logger, so pytest's ``caplog`` (which hooks the root
    logger) never sees these records — attaching a handler directly
    is the workaround used throughout ``core/llm/tests/``.
    """

    def __enter__(self):
        self.records: list = []
        self._h = logging.Handler()
        self._h.handle = lambda r: (self.records.append(r), True)[1]
        self._lg = logging.getLogger("raptor")
        self._lg.addHandler(self._h)
        return self

    def __exit__(self, *exc):
        self._lg.removeHandler(self._h)
        return False

    def messages(self) -> list:
        return [r.getMessage() for r in self.records]


def test_pinned_llm_config_anthropic_inference_from_claude_prefix(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    cfg = _pinned_llm_config("claude-opus-4-8")
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-opus-4-8"
    assert cfg.primary_model.role == "code"
    assert cfg.fallback_models == []


def test_pinned_llm_config_explicit_provider_slash_model(monkeypatch):
    """``provider/model`` syntax strips the prefix and is authoritative."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    cfg = _pinned_llm_config("anthropic/claude-sonnet-4-6")
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-sonnet-4-6"


def test_pinned_llm_config_inference_table(monkeypatch):
    """Bare-name inference: claude*→anthropic, gpt*→openai, *gemini*→gemini,
    everything else→anthropic (conservative default)."""
    # Make every provider's env-key probe succeed so the builder doesn't
    # influence the resolved provider.
    for v in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.setenv(v, "test-fake-key")
    cases = [
        ("claude-opus-4-8",        "anthropic"),
        ("claude-haiku-4-5",       "anthropic"),
        ("gpt-4o-mini",            "openai"),
        ("gemini-2.5-pro",         "gemini"),
        ("anthropic/claude-opus",  "anthropic"),
        ("openai/gpt-5",           "openai"),
    ]
    for name, expected in cases:
        cfg = _pinned_llm_config(name)
        assert cfg.primary_model.provider == expected, name


def test_pinned_llm_config_no_credentials_returns_bare_config():
    """When the inferred provider has no env credentials, returns a bare
    uncredentialed ModelConfig with the pinned name (does NOT fall through
    to a different provider — that lenient behaviour is what caused the
    misleading gemini banner the fix is removing)."""
    cfg = _pinned_llm_config("anthropic/claude-opus-4-8")  # explicit pin, no key
    assert cfg.primary_model.provider == "anthropic"
    assert cfg.primary_model.model_name == "claude-opus-4-8"
    assert cfg.fallback_models == []


def test_llmclient_pinned_banner_suppresses_default_primary(monkeypatch):
    """With ``pinned_model``, banner reports the pin instead of the
    operator's auto-resolved primary, and skips the misleading "Primary
    model:" / "Fallback models:" lines."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    with _RaptorLogCapture() as cap:
        LLMClient(pinned_model="claude-opus-4-8")
    msgs = cap.messages()
    assert any("Pinned model: claude-opus-4-8" in m for m in msgs), msgs
    # The two lines that the fix is removing for pinned mode:
    assert not any(m.startswith("Primary model:") for m in msgs), msgs
    assert not any(m.startswith("Fallback models:") for m in msgs), msgs


def test_llmclient_default_banner_unchanged(monkeypatch):
    """Without ``pinned_model``, banner behaviour is unchanged — the fix is
    additive (no regression for callers that don't opt in)."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-fake-key")
    with _RaptorLogCapture() as cap:
        LLMClient()
    msgs = cap.messages()
    # At least one of these fires in default mode (the existing banner).
    assert (any(m.startswith("Primary model:") for m in msgs)
            or any("no primary model" in m for m in msgs)), msgs

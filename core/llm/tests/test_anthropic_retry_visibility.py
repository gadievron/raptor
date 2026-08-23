"""The Anthropic transient-retry notice must be operator-visible.

At INFO the retry notices were invisible at the default log level, so
an upstream brownout — where every attempt burns a full read timeout —
presented as a silent multi-attempt stall (observed: a 50-minute
review-loop hang diagnosable only by SIGTERM). The notice now logs at
WARNING (parity with the OpenAI loop) and carries the cumulative
elapsed time so a live operator can see both that retries are
happening and how long the call has been stuck.
"""

from __future__ import annotations

import logging
import time

import pytest

from core.llm.providers import ModelConfig

pytest.importorskip("anthropic")


def test_transient_retry_logs_warning_with_elapsed(caplog, monkeypatch):
    import anthropic
    import httpx

    from core.llm.providers import AnthropicProvider
    from core.llm.tool_use import Message, TextBlock
    from core.llm.tool_use.tests.test_anthropic import (
        _StubBlock, _StubResponse, _StubUsage,
    )

    provider = AnthropicProvider(ModelConfig(
        provider="anthropic", model_name="claude-opus-4-6",
        api_key="test-key", timeout=1,
    ))

    ok = _StubResponse(
        [_StubBlock("text", text="ok")],
        stop_reason="end_turn",
        usage=_StubUsage(input_tokens=1, output_tokens=1),
    )
    calls = {"n": 0}

    class _Messages:
        def create(self, **kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise anthropic.APIConnectionError(
                    request=httpx.Request("POST", "http://unit.test"),
                )
            return ok

    class _Client:
        messages = _Messages()

    provider.client = _Client()  # type: ignore[assignment]
    monkeypatch.setattr(time, "sleep", lambda _s: None)  # skip backoff

    with caplog.at_level(logging.WARNING):
        resp = provider.turn(
            messages=[Message(role="user", content=[TextBlock(text="x")])],
            tools=[],
        )

    assert calls["n"] == 2, "transient error must be retried"
    assert resp.error_message is None

    notices = [r for r in caplog.records
               if "transient error attempt" in r.getMessage()]
    assert notices, "retry notice missing from WARNING-level records"
    assert notices[0].levelno == logging.WARNING
    message = notices[0].getMessage()
    assert "elapsed" in message
    assert "attempt 1/4" in message

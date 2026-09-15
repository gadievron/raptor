"""CC provider error paths must not relay raw subprocess/model bytes
into console logs or TurnResponse.error_message: the text is
CLI/model-authored (can carry ANSI/OSC terminal controls and
secret-shaped fragments), and the core/logging console handler applies
no escaping of its own."""

from __future__ import annotations

import logging

from core.llm.config import ModelConfig
from core.llm.providers import ClaudeCodeLLMProvider, StopReason
from core.llm.tool_use.types import Message, TextBlock, ToolDef

HOSTILE = "\x1b]0;pwned\x07\x9b2J boom sk-ant-api03-" + "a" * 32


def _provider() -> ClaudeCodeLLMProvider:
    return ClaudeCodeLLMProvider(
        ModelConfig(
            provider="claudecode", model_name="claude-opus-4-6",
            api_key="", timeout=1,
        ),
        claude_bin="/bin/true",
        resumable=False,
    )


def test_turn_runtime_error_message_scrubbed(monkeypatch, caplog):
    provider = _provider()

    def boom(**kwargs):
        raise RuntimeError(HOSTILE)

    monkeypatch.setattr(provider, "generate_structured", boom)
    tool = ToolDef(name="t", description="d", input_schema={"type": "object"},
                   handler=lambda _inp: "ok")
    msg = Message(role="user", content=[TextBlock(text="hi")])

    with caplog.at_level(logging.WARNING, logger="core.llm.providers"):
        resp = provider.turn([msg], [tool])

    assert resp.stop_reason == StopReason.ERROR
    assert resp.error_message is not None
    for raw in ("\x1b", "\x07", "\x9b"):
        assert raw not in resp.error_message
    assert "sk-ant-api03-" not in resp.error_message
    assert "boom" in resp.error_message
    joined = "\n".join(r.getMessage() for r in caplog.records)
    for raw in ("\x1b", "\x07", "\x9b"):
        assert raw not in joined
    assert "sk-ant-api03-" not in joined


def test_parse_stream_content_error_scrubbed():
    got = ClaudeCodeLLMProvider._parse_stream_content(HOSTILE)
    assert "error" in got
    for raw in ("\x1b", "\x07", "\x9b"):
        assert raw not in got["error"]
    assert "sk-ant-api03-" not in got["error"]

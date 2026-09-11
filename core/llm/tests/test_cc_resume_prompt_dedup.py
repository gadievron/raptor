"""Resumable CC turns must not re-send the model's own prior turn.

The tool-use loop echoes each turn back onto the history as an
assistant message, so it always leads the unseen slice on the next
resumed call — but the CC session already holds that turn server-side.
Re-rendering it into the prompt duplicated the model's own output every
resumed turn (token bloat linear in turn count). Assistant messages
injected by CALLERS carry different content and must still be sent.
"""

from __future__ import annotations

import contextlib

import pytest

from core.llm.cc_adapter import StreamJsonResult
from core.llm.config import ModelConfig
from core.llm.providers import ClaudeCodeLLMProvider
from core.llm.tool_use.types import Message, TextBlock, ToolDef, ToolResult


def _echo_tool() -> ToolDef:
    return ToolDef(
        name="echo",
        description="echoes input back",
        input_schema={"type": "object", "properties": {"x": {"type": "string"}}},
        handler=lambda inp: f"echoed:{inp}",
    )


def _tool_call_result(session_id: str, x_value: str) -> StreamJsonResult:
    return StreamJsonResult(
        content="",
        structured_output={
            "type": "tool_call",
            "tool_name": "echo",
            "tool_input": {"x": x_value},
        },
        session_id=session_id,
        cost_usd=0.01,
        input_tokens=10,
        output_tokens=5,
    )


@pytest.fixture()
def resumable_provider(monkeypatch) -> tuple[ClaudeCodeLLMProvider, list[str]]:
    """A resumable CC provider whose subprocess layer is stubbed —
    returns the provider plus the list of prompts sent per turn."""
    import core.llm.cc_adapter as cc_adapter

    prompts: list[str] = []
    scripted: list[StreamJsonResult] = [
        _tool_call_result("sess-1", "alpha-call"),
        _tool_call_result("sess-1", "beta-call"),
        _tool_call_result("sess-1", "gamma-call"),
    ]

    def fake_run(
        cmd: list[str], prompt: str, *,
        env: dict[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> StreamJsonResult:
        prompts.append(prompt)
        return scripted[len(prompts) - 1]

    monkeypatch.setattr(cc_adapter, "run_cc_streaming", fake_run)
    monkeypatch.setattr(
        cc_adapter, "build_cc_command",
        lambda config, system_prompt_file=None: ["claude-stub"],
    )
    monkeypatch.setattr(
        cc_adapter, "system_prompt_file_for",
        lambda config: contextlib.nullcontext(None),
    )
    monkeypatch.setattr(cc_adapter, "cc_subprocess_env", lambda: {})

    provider = ClaudeCodeLLMProvider(
        ModelConfig(
            provider="claudecode", model_name="claude-opus-4-6",
            api_key="", timeout=1,
        ),
        claude_bin="/bin/true",
        resumable=True,
    )
    return provider, prompts


def test_resumed_turn_skips_echo_of_own_prior_turn(resumable_provider) -> None:
    provider, prompts = resumable_provider
    tools = [_echo_tool()]

    messages: list[Message] = [
        Message(role="user", content=[TextBlock(text="find it")]),
    ]
    resp1 = provider.turn(messages, tools)
    call1 = resp1.content[0]

    # The loop echoes the provider's own turn back, then appends the
    # tool result.
    messages.append(Message(role="assistant", content=list(resp1.content)))
    messages.append(Message(role="user", content=[
        ToolResult(tool_use_id=call1.id, content="result-alpha"),
    ]))

    provider.turn(messages, tools)

    # Turn 2's prompt carries the NEW information (the tool result)
    # but not the model's own prior turn, which the CC session already
    # holds server-side.
    assert "result-alpha" in prompts[1]
    assert "alpha-call" not in prompts[1]
    assert "assistant called tool" not in prompts[1]


def test_caller_injected_assistant_message_still_sent(
    resumable_provider,
) -> None:
    provider, prompts = resumable_provider
    tools = [_echo_tool()]

    messages: list[Message] = [
        Message(role="user", content=[TextBlock(text="find it")]),
    ]
    resp1 = provider.turn(messages, tools)
    messages.append(Message(role="assistant", content=list(resp1.content)))
    messages.append(Message(role="user", content=[
        ToolResult(tool_use_id=resp1.content[0].id, content="result-alpha"),
    ]))

    resp2 = provider.turn(messages, tools)
    # Loop echo of turn 2 PLUS an assistant message a caller injected
    # (different content than what this provider emitted) — only the
    # echo may be skipped.
    messages.append(Message(role="assistant", content=list(resp2.content)))
    messages.append(Message(role="assistant", content=[
        TextBlock(text="operator note: focus on the parser"),
    ]))
    messages.append(Message(role="user", content=[
        ToolResult(tool_use_id=resp2.content[0].id, content="result-beta"),
    ]))

    provider.turn(messages, tools)

    assert "beta-call" not in prompts[2]          # own echo skipped
    assert "operator note: focus on the parser" in prompts[2]
    assert "result-beta" in prompts[2]


def test_first_turn_sends_full_history(resumable_provider) -> None:
    """The session-establishing turn still renders the whole history,
    assistant messages included."""
    provider, prompts = resumable_provider
    messages: list[Message] = [
        Message(role="user", content=[TextBlock(text="find it")]),
        Message(role="assistant", content=[TextBlock(text="thinking aloud")]),
        Message(role="user", content=[TextBlock(text="go on")]),
    ]
    provider.turn(messages, [_echo_tool()])
    assert "find it" in prompts[0]
    assert "thinking aloud" in prompts[0]

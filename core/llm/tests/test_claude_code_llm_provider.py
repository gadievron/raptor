"""Tests for :class:`ClaudeCodeLLMProvider` — the real provider that
wraps ``claude -p`` so consumers holding a :class:`ModelConfig` can
use the Claude Code CLI without an SDK API key.

Distinct from the legacy ``ClaudeCodeProvider`` stub (which returns
``None`` to signal "the surrounding orchestrator handles reasoning")
— this one actually does generation via subprocess and supports
tool-use through CC's ``--json-schema`` structured-output mode.

The ABC's :meth:`_tool_use_fallback` (JSON-in-prompt synthesis)
does NOT work for CC: anti-injection training refuses to roleplay
as a different agent system. The structured-output mode reframes
the task as form-filling rather than roleplay and bypasses the
guard.

All subprocess interaction is monkeypatched; no real ``claude``
binary is invoked.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

from core.llm.cc_adapter import StreamJsonResult
from core.llm.config import ModelConfig
from core.llm.providers import (
    ClaudeCodeLLMProvider, LLMProvider, create_provider,
)
from core.llm.tool_use import (
    Message, StopReason, TextBlock, ToolCall, ToolDef,
)


# ---------------------------------------------------------------------------
# Fake subprocess helpers
# ---------------------------------------------------------------------------


class _FakeCompleted:
    """Stand-in for :class:`subprocess.CompletedProcess`."""

    def __init__(self, stdout: str = "", stderr: str = "", returncode: int = 0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def _envelope(
    result: str = "ok",
    cost_usd: float = 0.01,
    duration_ms: int = 1234,
    input_tokens: int = 5,
    output_tokens: int = 7,
    model: str = "claude-opus-4-6",
) -> str:
    return json.dumps({
        "result": result,
        "total_cost_usd": cost_usd,
        "duration_ms": duration_ms,
        "modelUsage": {model: {}},
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
        },
    })


def _structured_envelope(
    payload: dict[str, Any],
    cost_usd: float = 0.02,
) -> str:
    return json.dumps({
        "structured_output": payload,
        "total_cost_usd": cost_usd,
        "duration_ms": 100,
        "modelUsage": {"claude-opus-4-6": {}},
        "usage": {"input_tokens": 3, "output_tokens": 4},
    })


def _config(model: str = "claude-opus-4-6") -> ModelConfig:
    return ModelConfig(
        provider="claudecode",
        model_name=model,
        api_key=None,
        timeout=30,
    )


# ---------------------------------------------------------------------------
# Stream-json mock helpers (used by generate/generate_structured/turn tests)
# ---------------------------------------------------------------------------


def _stream_result(
    payload: dict[str, Any],
    session_id: str = "sess-001",
    cost_usd: float = 0.02,
    error: str | None = None,
) -> StreamJsonResult:
    return StreamJsonResult(
        content=json.dumps(payload),
        session_id=session_id,
        cost_usd=cost_usd,
        input_tokens=3,
        output_tokens=4,
        model="claude-haiku-4-5-20251001",
        error=error,
    )


def _stream_freeform(
    text: str = "ok",
    cost_usd: float = 0.01,
    input_tokens: int = 5,
    output_tokens: int = 7,
    model: str = "claude-opus-4-6",
    error: str | None = None,
) -> StreamJsonResult:
    return StreamJsonResult(
        content=text,
        cost_usd=cost_usd,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        model=model,
        error=error,
    )


# ---------------------------------------------------------------------------
# Capability flags + factory wiring
# ---------------------------------------------------------------------------


def test_capabilities() -> None:
    p = ClaudeCodeLLMProvider(_config())
    assert isinstance(p, LLMProvider)
    assert p.supports_tool_use() is True
    assert p.supports_prompt_caching() is False
    assert p.supports_parallel_tools() is False


def test_factory_routes_claudecode_provider() -> None:
    for name in ("claudecode", "claude_code", "claude-code"):
        cfg = ModelConfig(
            provider=name, model_name="claude-opus-4-6",
            api_key=None, timeout=30,
        )
        p = create_provider(cfg)
        assert isinstance(p, ClaudeCodeLLMProvider)


def test_is_stub_false() -> None:
    """Distinguishes from the legacy ``ClaudeCodeProvider`` stub."""
    p = ClaudeCodeLLMProvider(_config())
    assert p.is_stub is False


def test_exported_from_core_llm_package() -> None:
    """Public API surface — consumers import via the package."""
    import core.llm
    assert hasattr(core.llm, "ClaudeCodeLLMProvider")
    assert core.llm.ClaudeCodeLLMProvider is ClaudeCodeLLMProvider
    assert "ClaudeCodeLLMProvider" in core.llm.__all__


# ---------------------------------------------------------------------------
# generate() — subprocess invocation, envelope parsing, usage tracking
# ---------------------------------------------------------------------------


def test_generate_invokes_claude_p_with_prompt(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        captured["prompt"] = prompt
        captured["timeout_s"] = timeout_s
        return _stream_freeform(text="hello world")

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("say hi")

    assert captured["cmd"][0] == "claude"
    assert captured["cmd"][1] == "-p"
    assert "--output-format" in captured["cmd"]
    assert captured["prompt"] == "say hi"
    assert captured["timeout_s"] == 30
    assert out.content == "hello world"
    assert out.provider == "claudecode"


def test_generate_disables_internal_cc_tools(monkeypatch) -> None:
    """When CC is used as a pure-LLM substrate (just emit text or a
    JSON tool call), CC's own Read/Grep/Glob tools must be disabled —
    otherwise the subprocess could read files in cwd before answering.
    Tool-use happens at the loop layer above, not inside CC."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    p.generate("hi")

    cmd = captured["cmd"]
    assert "--allowed-tools" in cmd
    tools_idx = cmd.index("--allowed-tools") + 1
    assert cmd[tools_idx] == ""


def test_generate_with_system_prompt_uses_system_flag(monkeypatch) -> None:
    """`system_prompt` flows through CC's --system-prompt flag, not via prompt prepend.

    Pre-cluster-107 the provider concatenated `f"{system_prompt}\\n\\n{prompt}"`
    and sent the combined text as the user message. That folded the
    system instruction into user content, where a hostile user prompt
    could re-instruct over it. Routing through `--system-prompt` keeps the
    system layer in its own role-channel.
    """
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    p.generate("user question", system_prompt="you are helpful")

    assert captured["prompt"] == "user question"
    cmd = captured["cmd"]
    assert "--system-prompt" in cmd
    sys_idx = cmd.index("--system-prompt") + 1
    assert cmd[sys_idx] == "you are helpful"


def test_generate_extracts_cost_and_tokens(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(
            cost_usd=0.05, input_tokens=10, output_tokens=20,
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("hi")

    assert out.cost == 0.05
    assert out.tokens_used == 30
    assert out.input_tokens == 10
    assert out.output_tokens == 20
    assert p.total_cost == 0.05
    assert p.call_count == 1


def test_generate_uses_envelope_model(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(model="claude-sonnet-4-6"),
    )
    p = ClaudeCodeLLMProvider(_config(model="auto"))
    out = p.generate("hi")
    assert out.model == "claude-sonnet-4-6"


def test_generate_nonzero_returncode_raises(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(
            error="claude -p exited 2: auth failed",
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="auth failed"):
        p.generate("hi")


def test_generate_error_message_redacts_secrets_in_stderr(monkeypatch) -> None:
    """CC subprocess stderr can contain credentials echoed by misconfig
    (e.g., env var values, URLs with embedded creds). ``run_cc_streaming``
    applies ``redact_secrets`` before setting ``StreamJsonResult.error``,
    so by the time ``generate()`` raises, the secret is gone."""
    import core.llm.cc_adapter as _cc_adapter
    from core.security.redaction import redact_secrets
    leaky = "fetch failed: https://user:s3cretpassword@api.example.com/v1/x"
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(error=redact_secrets(leaky)),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError) as ei:
        p.generate("hi")
    assert "s3cretpassword" not in str(ei.value)


def test_generate_error_message_escapes_control_bytes_in_stderr(monkeypatch) -> None:
    """Threat B: CC stderr containing ANSI / control bytes would
    corrupt the operator's terminal if propagated verbatim. The
    converter escapes them to a printable ``\\xHH`` form."""
    import core.llm.cc_adapter as _cc_adapter
    nasty = "boom\\x1b[31mfake red text\\x1b[0m\\x07"
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(error=nasty),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError) as ei:
        p.generate("hi")
    msg = str(ei.value)
    assert "\x1b" not in msg
    assert "\x07" not in msg
    assert "fake red text" in msg


def test_generate_structured_error_sanitises_stderr_too(monkeypatch) -> None:
    """generate_structured uses the same sanitisation path."""
    import core.llm.cc_adapter as _cc_adapter
    nasty = "fail \\x1b[31mBearer abcdefghijklmnopqrstuvwxyz1234"
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(error=nasty),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError) as ei:
        p.generate_structured("compute", {"type": "object"})
    msg = str(ei.value)
    assert "\x1b" not in msg


def test_generate_timeout_wrapped_as_runtimeerror(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter

    def fake_stream(*a, **k):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=30)

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="timed out"):
        p.generate("hi")


def test_generate_carries_duration(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("hi")
    assert out.duration >= 0.0


# ---------------------------------------------------------------------------
# generate_structured() — schema-shaped output
# ---------------------------------------------------------------------------


def test_generate_structured_passes_schema_to_subprocess(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_result({"answer": 42})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    schema = {"type": "object", "properties": {"answer": {"type": "integer"}}}
    result, raw = p.generate_structured("compute", schema)

    assert "--json-schema" in captured["cmd"]
    schema_idx = captured["cmd"].index("--json-schema") + 1
    assert json.loads(captured["cmd"][schema_idx]) == schema
    assert result["answer"] == 42
    assert json.loads(raw)["answer"] == 42


def test_generate_structured_parse_error_raises(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: StreamJsonResult(content="not json"),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="structured parse failed"):
        p.generate_structured("compute", {"type": "object"})


def test_generate_structured_tracks_usage(monkeypatch) -> None:
    """Structured calls must update provider stats too — symmetric
    with generate(). Otherwise total_cost / call_count drift away
    from the truth whenever a consumer mixes generate() and
    generate_structured()."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result({"answer": 1}, cost_usd=0.07),
    )
    p = ClaudeCodeLLMProvider(_config())
    p.generate_structured("compute", {"type": "object"})

    assert p.total_cost == 0.07
    assert p.call_count == 1
    assert p.total_tokens > 0


def test_generate_structured_returns_clean_payload(monkeypatch) -> None:
    """The returned dict must NOT carry envelope-level metadata keys
    that track_usage already consumed. Consumers expect their schema."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result({"answer": 1}, cost_usd=0.05),
    )
    p = ClaudeCodeLLMProvider(_config())
    result, raw = p.generate_structured("compute", {"type": "object"})
    assert "answer" in result


def test_generate_structured_disables_internal_cc_tools(monkeypatch) -> None:
    """Same rule as ``generate``: CC's internal Read/Grep/Glob tools
    must be disabled when used as a pure-LLM substrate."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_result({"a": 1})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    p.generate_structured("compute", {"type": "object"})

    cmd = captured["cmd"]
    tools_idx = cmd.index("--allowed-tools") + 1
    assert cmd[tools_idx] == ""


# ---------------------------------------------------------------------------
# turn() — delegates to ABC's _tool_use_fallback
# ---------------------------------------------------------------------------


def test_turn_text_response_returns_complete(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(text="final answer"),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )

    assert out.stop_reason is StopReason.COMPLETE
    assert isinstance(out.content[0], TextBlock)
    assert out.content[0].text == "final answer"


def test_turn_tool_call_response_returns_needs_tool_call(monkeypatch) -> None:
    """CC emits a ``tool_call``-shaped JSON via --json-schema; the
    provider parses it into a ``ToolCall`` block."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result({
            "type": "tool_call",
            "tool_name": "search",
            "tool_input": {"q": "x"},
        }),
    )
    tool = ToolDef(
        name="search", description="search tool",
        input_schema={"type": "object"},
        handler=lambda i: "result",
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="find x")])],
        tools=[tool],
    )

    assert out.stop_reason is StopReason.NEEDS_TOOL_CALL
    assert isinstance(out.content[0], ToolCall)
    assert out.content[0].name == "search"
    assert out.content[0].input == {"q": "x"}


def test_turn_complete_response_returns_complete(monkeypatch) -> None:
    """When CC emits ``type=complete`` (no more tools to call), the
    provider returns a ``TextBlock`` with the final answer."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result({
            "type": "complete",
            "final_text": "I'm done — the answer is 42.",
        }),
    )
    tool = ToolDef(
        name="search", description="search tool",
        input_schema={"type": "object"},
        handler=lambda i: "result",
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[tool],
    )

    assert out.stop_reason is StopReason.COMPLETE
    assert isinstance(out.content[0], TextBlock)
    assert "the answer is 42" in out.content[0].text


def test_turn_invokes_subprocess_with_json_schema(monkeypatch) -> None:
    """Sanity: the subprocess command includes ``--json-schema`` so
    CC honours the structured-output contract."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_result({"type": "complete", "final_text": "ok"})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    tool = ToolDef(
        name="search", description="search tool",
        input_schema={"type": "object"},
        handler=lambda i: "result",
    )
    p = ClaudeCodeLLMProvider(_config())
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[tool],
    )
    assert "--json-schema" in captured["cmd"]
    schema_idx = captured["cmd"].index("--json-schema") + 1
    schema = json.loads(captured["cmd"][schema_idx])
    assert schema["properties"]["type"]["enum"] == ["tool_call", "complete"]
    assert schema["properties"]["tool_name"]["enum"] == ["search"]


def test_turn_malformed_tool_call_falls_back_to_text(monkeypatch) -> None:
    """If CC emits ``type=tool_call`` but the tool_name doesn't match
    a registered tool (hallucination guard), we surface the raw result
    as a text block rather than dispatching a bogus call."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result({
            "type": "tool_call",
            "tool_name": "fictional_tool_99",
            "tool_input": {},
        }),
    )
    tool = ToolDef(
        name="search", description="search tool",
        input_schema={"type": "object"},
        handler=lambda i: "result",
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[tool],
    )
    assert out.stop_reason is StopReason.COMPLETE
    assert isinstance(out.content[0], TextBlock)


def test_turn_no_tools_uses_plain_generate(monkeypatch) -> None:
    """When ``tools=[]``, ``turn()`` skips the schema and falls back
    to plain text generation. No ``--json-schema`` flag in the
    command line."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_freeform(text="hello")

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )
    assert "--json-schema" not in captured["cmd"]
    assert out.stop_reason is StopReason.COMPLETE
    assert out.content[0].text == "hello"


def test_turn_subprocess_error_returns_error_response(monkeypatch) -> None:
    """When the underlying subprocess fails, return a TurnResponse
    with stop_reason=ERROR instead of letting RuntimeError bubble up."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_result(
            {}, error="claude -p exited 1: auth failed",
        ),
    )
    tool = ToolDef(
        name="search", description="search tool",
        input_schema={"type": "object"},
        handler=lambda i: "result",
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[tool],
    )
    assert out.stop_reason is StopReason.ERROR
    assert out.content == []


def test_turn_propagates_envelope_cost_to_compute_cost(monkeypatch) -> None:
    """The whole reason cost_usd exists on TurnResponse: Claude Code
    publishes total_cost_usd in its envelope, and we want the loop's
    budget tracking to use that exact figure rather than a token-
    derived approximation."""
    import core.llm.cc_adapter as _cc_adapter
    monkeypatch.setattr(
        _cc_adapter, "run_cc_streaming",
        lambda *a, **k: _stream_freeform(
            text="answer", cost_usd=0.0337,
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
    )
    assert out.cost_usd == 0.0337
    assert p.compute_cost(out) == 0.0337


def test_turn_passes_system_through_to_subprocess(monkeypatch) -> None:
    """``system`` arg goes via the CC `--system-prompt` flag."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config())
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
        system="be careful",
    )
    cmd = captured["cmd"]
    assert "--system-prompt" in cmd
    sys_idx = cmd.index("--system-prompt") + 1
    assert "be careful" in cmd[sys_idx]


# ---------------------------------------------------------------------------
# Custom claude_bin / timeout kwargs
# ---------------------------------------------------------------------------


def test_custom_claude_bin(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = cmd
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), claude_bin="/opt/claude")
    p.generate("hi")
    assert captured["cmd"][0] == "/opt/claude"


def test_custom_timeout(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["timeout_s"] = timeout_s
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), timeout_s=99)
    p.generate("hi")
    assert captured["timeout_s"] == 99


def test_per_call_timeout_overrides_provider_default(monkeypatch) -> None:
    """A ``timeout_s`` kwarg on one call wins over the provider-level
    timeout for that call only — heavy call classes (checker
    synthesis) outlive the provider default without the caller
    having to rebuild the (cached) provider instance."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["timeout_s"] = timeout_s
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), timeout_s=99)

    p.generate("hi", timeout_s=1800)
    assert captured["timeout_s"] == 1800

    # Next call without the kwarg reverts to the provider default.
    p.generate("hi")
    assert captured["timeout_s"] == 99


def test_per_call_timeout_zero_means_no_timeout(monkeypatch) -> None:
    """``timeout_s=0`` per call honours the documented no-timeout
    sentinel, same as the constructor kwarg."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["timeout_s"] = timeout_s
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), timeout_s=99)
    p.generate("hi", timeout_s=0)
    assert captured["timeout_s"] is None


def test_per_call_timeout_on_generate_structured(monkeypatch) -> None:
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["timeout_s"] = timeout_s
        return _stream_result({"ok": True})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), timeout_s=99)
    result, _raw = p.generate_structured(
        "hi", {"type": "object"}, timeout_s=1800,
    )
    assert result == {"ok": True}
    assert captured["timeout_s"] == 1800


# ---------------------------------------------------------------------------
# Resumable session support
# ---------------------------------------------------------------------------

_TOOL_DEFS = [
    ToolDef(
        name="check_value",
        description="Check a value",
        input_schema={"type": "object", "properties": {"x": {"type": "string"}}},
        handler=lambda inp: "ok",
    ),
]


def _structured_envelope_with_session(
    payload: dict[str, Any],
    session_id: str = "sess-001",
    cost_usd: float = 0.02,
) -> str:
    return json.dumps({
        "structured_output": payload,
        "session_id": session_id,
        "total_cost_usd": cost_usd,
        "duration_ms": 100,
        "modelUsage": {"claude-haiku-4-5-20251001": {}},
        "usage": {"input_tokens": 3, "output_tokens": 4},
    })


def test_factory_routes_claudecode_resumable() -> None:
    for name in ("claudecode-resumable", "claude_code_resumable",
                 "claude-code-resumable"):
        cfg = ModelConfig(
            provider=name, model_name="claude-haiku-4-5-20251001",
            api_key=None, timeout=30,
        )
        p = create_provider(cfg)
        assert isinstance(p, ClaudeCodeLLMProvider)
        assert p._resumable is True


def test_resumable_default_false() -> None:
    p = ClaudeCodeLLMProvider(_config())
    assert p._resumable is False
    assert p._session_id is None


def test_resumable_first_turn_no_resume_flag(monkeypatch) -> None:
    """First turn should NOT use --resume (no session yet)."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        return _stream_result({"type": "complete", "final_text": "done"})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), resumable=True)

    msgs = [Message(role="user", content=[TextBlock(text="hello")])]
    p.turn(msgs, _TOOL_DEFS, system="be helpful")

    cmd = captured["cmd"]
    assert "--resume" not in cmd
    assert "--no-session-persistence" not in cmd
    assert p._session_id == "sess-001"


def test_resumable_second_turn_uses_resume(monkeypatch) -> None:
    """After first turn establishes session, subsequent turns use --resume."""
    import core.llm.cc_adapter as _cc_adapter
    call_count = 0

    def fake_stream(cmd, prompt, *, env, timeout_s):
        nonlocal call_count
        call_count += 1
        return _stream_result(
            {"type": "tool_call", "tool_name": "check_value",
             "tool_input": {"x": "42"}}
            if call_count == 1 else
            {"type": "complete", "final_text": "done"},
            session_id="sess-xyz",
        )

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), resumable=True)

    msgs = [Message(role="user", content=[TextBlock(text="start")])]
    r1 = p.turn(msgs, _TOOL_DEFS)
    assert r1.stop_reason == StopReason.NEEDS_TOOL_CALL
    assert p._session_id == "sess-xyz"

    msgs.append(Message(
        role="assistant",
        content=[ToolCall(id="call_abc", name="check_value", input={"x": "42"})],
    ))
    msgs.append(Message(
        role="user",
        content=[TextBlock(text="tool result: value is 42")],
    ))

    captured: dict[str, Any] = {}
    orig_stream = fake_stream

    def spy_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        captured["prompt"] = prompt
        return orig_stream(cmd, prompt, env=env, timeout_s=timeout_s)

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", spy_stream)
    r2 = p.turn(msgs, _TOOL_DEFS)

    cmd = captured["cmd"]
    assert "--resume" in cmd
    idx = cmd.index("--resume")
    assert cmd[idx + 1] == "sess-xyz"
    assert r2.stop_reason == StopReason.COMPLETE

    assert "start" not in captured["prompt"]
    assert "tool result" in captured["prompt"]


def test_resumable_second_turn_omits_system_prompt(monkeypatch) -> None:
    """System prompt is in the session — don't re-send on --resume turns."""
    import core.llm.cc_adapter as _cc_adapter
    calls: list[list[str]] = []

    def fake_stream(cmd, prompt, *, env, timeout_s):
        calls.append(list(cmd))
        return _stream_result({"type": "complete", "final_text": "ok"})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), resumable=True)

    msgs = [Message(role="user", content=[TextBlock(text="hi")])]
    p.turn(msgs, _TOOL_DEFS, system="be helpful")
    assert "--system-prompt" in calls[0]

    msgs.append(Message(role="assistant", content=[TextBlock(text="ok")]))
    msgs.append(Message(role="user", content=[TextBlock(text="more")]))
    p.turn(msgs, _TOOL_DEFS, system="be helpful")
    assert "--system-prompt" not in calls[1]


def test_reset_session_clears_state() -> None:
    p = ClaudeCodeLLMProvider(_config(), resumable=True)
    p._session_id = "sess-old"
    p._messages_seen = 5
    p.reset_session()
    assert p._session_id is None
    assert p._messages_seen == 0


def test_resumable_stale_marker_retries_as_fresh(monkeypatch) -> None:
    """When CC returns 'deferred tool marker' error, session resets and
    the turn is retried immediately as a fresh first turn."""
    import core.llm.cc_adapter as _cc_adapter
    call_count = 0

    def fake_stream(cmd, prompt, *, env, timeout_s):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return _stream_result(
                {"type": "complete", "final_text": "ok"},
            )
        if call_count == 2:
            return StreamJsonResult(
                error=(
                    "claude -p exited 1: Error: No deferred tool marker "
                    "found in the resumed session."
                ),
            )
        return _stream_result(
            {"type": "complete", "final_text": "retried"},
        )

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), resumable=True)

    msgs = [Message(role="user", content=[TextBlock(text="hi")])]
    p.turn(msgs, _TOOL_DEFS)
    assert p._session_id == "sess-001"

    msgs.append(Message(role="assistant", content=[TextBlock(text="ok")]))
    msgs.append(Message(role="user", content=[TextBlock(text="more")]))
    r2 = p.turn(msgs, _TOOL_DEFS)
    assert r2.stop_reason == StopReason.COMPLETE
    assert r2.content[0].text == "retried"
    assert p._session_id == "sess-001"
    assert call_count == 3


def test_resumable_false_uses_stateless_path(monkeypatch) -> None:
    """Non-resumable provider uses the original stateless path."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        return _stream_result({"type": "complete", "final_text": "ok"})

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(), resumable=False)

    msgs = [Message(role="user", content=[TextBlock(text="hi")])]
    p.turn(msgs, _TOOL_DEFS)

    assert "--no-session-persistence" in captured["cmd"]
    assert "--resume" not in captured["cmd"]


# ---------------------------------------------------------------------------
# Session-default sentinel (claudecode fallback inherits CLI session model)
# ---------------------------------------------------------------------------


def test_generate_session_default_omits_model_flag(monkeypatch) -> None:
    """The fallback sentinel must not become ``--model session-default``
    — the flag is omitted entirely so the subprocess inherits the CLI
    session's own default model (Bedrock/Vertex-backed installs don't
    serve bare Anthropic model IDs)."""
    from core.llm.config import CLAUDECODE_SESSION_MODEL
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(model=CLAUDECODE_SESSION_MODEL))
    p.generate("hi")

    assert "--model" not in captured["cmd"]


def test_generate_explicit_model_still_passes_flag(monkeypatch) -> None:
    """An operator-chosen model name (models.json claudecode entry) is
    still forwarded as ``--model``."""
    import core.llm.cc_adapter as _cc_adapter
    captured: dict[str, Any] = {}

    def fake_stream(cmd, prompt, *, env, timeout_s):
        captured["cmd"] = list(cmd)
        return _stream_freeform()

    monkeypatch.setattr(_cc_adapter, "run_cc_streaming", fake_stream)
    p = ClaudeCodeLLMProvider(_config(model="claude-opus-4-6"))
    p.generate("hi")

    cmd = captured["cmd"]
    assert "--model" in cmd
    assert cmd[cmd.index("--model") + 1] == "claude-opus-4-6"


def test_build_claudecode_config_uses_session_sentinel(monkeypatch) -> None:
    """The auto-fallback builder stamps the sentinel, not a hardcoded
    Anthropic model name."""
    import shutil as _shutil
    from core.llm.config import (
        CLAUDECODE_SESSION_MODEL,
        _build_claudecode_config,
    )
    monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/claude")
    cfg = _build_claudecode_config()
    assert cfg is not None
    assert cfg.provider == "claudecode"
    assert cfg.model_name == CLAUDECODE_SESSION_MODEL

"""Tests for :class:`ClaudeCodeLLMProvider` — the real provider that
wraps ``claude -p`` so consumers holding a :class:`ModelConfig` can
use the Claude Code CLI without an SDK API key.

Distinct from the legacy ``ClaudeCodeProvider`` stub (which returns
``None`` to signal "the surrounding orchestrator handles reasoning")
— this one actually does generation via subprocess and supports
tool-use through the ABC's JSON-protocol fallback.

All subprocess interaction is monkeypatched; no real ``claude``
binary is invoked.
"""

from __future__ import annotations

import json
import subprocess
from typing import Any

import pytest

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
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        captured["input"] = kw.get("input")
        captured["timeout"] = kw.get("timeout")
        return _FakeCompleted(stdout=_envelope(result="hello world"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("say hi")

    assert captured["cmd"][0] == "claude"
    assert captured["cmd"][1] == "-p"
    assert "--output-format" in captured["cmd"]
    assert captured["input"] == "say hi"
    assert captured["timeout"] == 30
    assert out.content == "hello world"
    assert out.provider == "claudecode"


def test_generate_disables_internal_cc_tools(monkeypatch) -> None:
    """When CC is used as a pure-LLM substrate (just emit text or a
    JSON tool call), CC's own Read/Grep/Glob tools must be disabled —
    otherwise the subprocess could read files in cwd before answering.
    Tool-use happens at the loop layer above, not inside CC."""
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **k: (captured.update({"cmd": cmd}),
                          _FakeCompleted(stdout=_envelope()))[1],
    )
    p = ClaudeCodeLLMProvider(_config())
    p.generate("hi")

    cmd = captured["cmd"]
    assert "--allowed-tools" in cmd
    tools_idx = cmd.index("--allowed-tools") + 1
    # Must be empty (no tools) — not the cc_adapter default of
    # "Read,Grep,Glob".
    assert cmd[tools_idx] == ""


def test_generate_with_system_prompt_prepended(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kw):
        captured["input"] = kw.get("input")
        return _FakeCompleted(stdout=_envelope(result="ok"))

    monkeypatch.setattr(subprocess, "run", fake_run)
    p = ClaudeCodeLLMProvider(_config())
    p.generate("user question", system_prompt="you are helpful")

    assert captured["input"].startswith("you are helpful\n\n")
    assert "user question" in captured["input"]


def test_generate_extracts_cost_and_tokens(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout=_envelope(cost_usd=0.05, input_tokens=10, output_tokens=20)
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("hi")

    assert out.cost == 0.05
    assert out.tokens_used == 30                # input + output
    assert p.total_cost == 0.05
    assert p.call_count == 1


def test_generate_uses_envelope_model(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout=_envelope(model="claude-sonnet-4-6")
        ),
    )
    p = ClaudeCodeLLMProvider(_config(model="auto"))
    out = p.generate("hi")
    assert out.model == "claude-sonnet-4-6"


def test_generate_nonzero_returncode_raises(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout="", stderr="auth failed", returncode=2,
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="claude -p exited with status 2"):
        p.generate("hi")


def test_generate_timeout_wrapped_as_runtimeerror(monkeypatch) -> None:
    def fake_run(*a, **k):
        raise subprocess.TimeoutExpired(cmd="claude", timeout=30)

    monkeypatch.setattr(subprocess, "run", fake_run)
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="timed out"):
        p.generate("hi")


def test_generate_carries_duration(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout=_envelope()),
    )
    p = ClaudeCodeLLMProvider(_config())
    out = p.generate("hi")
    # duration measured locally, not from envelope; just non-negative
    assert out.duration >= 0.0


# ---------------------------------------------------------------------------
# generate_structured() — schema-shaped output
# ---------------------------------------------------------------------------


def test_generate_structured_passes_schema_to_subprocess(monkeypatch) -> None:
    captured: dict[str, Any] = {}

    def fake_run(cmd, **kw):
        captured["cmd"] = cmd
        return _FakeCompleted(
            stdout=_structured_envelope({"answer": 42})
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    p = ClaudeCodeLLMProvider(_config())
    schema = {"type": "object", "properties": {"answer": {"type": "integer"}}}
    result, raw = p.generate_structured("compute", schema)

    assert "--json-schema" in captured["cmd"]
    schema_idx = captured["cmd"].index("--json-schema") + 1
    assert json.loads(captured["cmd"][schema_idx]) == schema
    assert result["answer"] == 42
    assert json.loads(raw)["answer"] == 42


def test_generate_structured_parse_error_raises(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout="not json"),
    )
    p = ClaudeCodeLLMProvider(_config())
    with pytest.raises(RuntimeError, match="structured parse failed"):
        p.generate_structured("compute", {"type": "object"})


def test_generate_structured_tracks_usage(monkeypatch) -> None:
    """Structured calls must update provider stats too — symmetric
    with generate(). Otherwise total_cost / call_count drift away
    from the truth whenever a consumer mixes generate() and
    generate_structured()."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout=_structured_envelope({"answer": 1}, cost_usd=0.07)
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    p.generate_structured("compute", {"type": "object"})

    assert p.total_cost == 0.07
    assert p.call_count == 1
    assert p.total_tokens > 0


def test_generate_structured_returns_clean_payload(monkeypatch) -> None:
    """The returned dict must NOT carry envelope-level metadata keys
    (cost_usd / _tokens / duration_seconds / analysed_by) that
    track_usage already consumed. Consumers expect their schema."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout=_structured_envelope({"answer": 1}, cost_usd=0.05)
        ),
    )
    p = ClaudeCodeLLMProvider(_config())
    result, raw = p.generate_structured("compute", {"type": "object"})
    assert "cost_usd" not in result
    assert "_tokens" not in result
    assert "duration_seconds" not in result
    assert "analysed_by" not in result
    # parse_cc_structured silently injects ``finding_id`` via setdefault
    # (legacy CVE-aware behaviour from other cc_adapter consumers); we
    # strip it because it isn't in the consumer's schema.
    assert "finding_id" not in result
    assert "answer" in result
    assert "cost_usd" not in json.loads(raw)
    assert "finding_id" not in json.loads(raw)


def test_generate_structured_disables_internal_cc_tools(monkeypatch) -> None:
    """Same rule as ``generate``: CC's internal Read/Grep/Glob tools
    must be disabled when used as a pure-LLM substrate."""
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **k: (captured.update({"cmd": cmd}),
                          _FakeCompleted(
                              stdout=_structured_envelope({"a": 1})
                          ))[1],
    )
    p = ClaudeCodeLLMProvider(_config())
    p.generate_structured("compute", {"type": "object"})

    cmd = captured["cmd"]
    tools_idx = cmd.index("--allowed-tools") + 1
    assert cmd[tools_idx] == ""


# ---------------------------------------------------------------------------
# turn() — delegates to ABC's _tool_use_fallback
# ---------------------------------------------------------------------------


def test_turn_text_response_returns_complete(monkeypatch) -> None:
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout=_envelope(result="final answer")),
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
    payload = '```json\n{"tool": "search", "input": {"q": "x"}}\n```'
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(stdout=_envelope(result=payload)),
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


def test_turn_propagates_envelope_cost_to_compute_cost(monkeypatch) -> None:
    """The whole reason cost_usd exists on TurnResponse: Claude Code
    publishes total_cost_usd in its envelope, and we want the loop's
    budget tracking to use that exact figure rather than a token-
    derived approximation that's near-zero for non-billed models.
    End-to-end: envelope cost → generate() → fallback → TurnResponse
    → compute_cost."""
    monkeypatch.setattr(
        subprocess, "run",
        lambda *a, **k: _FakeCompleted(
            stdout=_envelope(result="answer", cost_usd=0.0337)
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
    """``system`` arg goes via the prompt (not a CLI flag) — our fallback
    appends the tool protocol to the system message before calling
    ``generate()``, which prepends it to the prompt."""
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **k: (captured.update({"input": k["input"]}),
                          _FakeCompleted(stdout=_envelope(result="ok")))[1],
    )
    p = ClaudeCodeLLMProvider(_config())
    p.turn(
        messages=[Message(role="user", content=[TextBlock(text="hi")])],
        tools=[],
        system="be careful",
    )
    assert "be careful" in captured["input"]


# ---------------------------------------------------------------------------
# Custom claude_bin / timeout kwargs
# ---------------------------------------------------------------------------


def test_custom_claude_bin(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **k: (captured.update({"cmd": cmd}),
                          _FakeCompleted(stdout=_envelope()))[1],
    )
    p = ClaudeCodeLLMProvider(_config(), claude_bin="/opt/claude")
    p.generate("hi")
    assert captured["cmd"][0] == "/opt/claude"


def test_custom_timeout(monkeypatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(
        subprocess, "run",
        lambda cmd, **k: (captured.update({"timeout": k["timeout"]}),
                          _FakeCompleted(stdout=_envelope()))[1],
    )
    p = ClaudeCodeLLMProvider(_config(), timeout_s=99)
    p.generate("hi")
    assert captured["timeout"] == 99

"""Intervention #2 knob-wiring (2026-05-31): operator dials to curb the
research-spiral, default-safe (no behavior change).

Forensic (bench50-20260531-183716): the spiral CVEs over-explore via WebSearch /
web_fetch / sub-`Agent` (3/191 spawned a sub-Agent, 0 built). This exposes a
`CVE_ENV_DISALLOWED_TOOLS` knob (wired into the SDK's `disallowed_tools`) so an
operator/bench can disable sub-Agent (or any builtin). DEFAULT is empty — no
behavior change. Per the config's 3-bench M-rule, setting a default-disable (or
a default research-tool cap) waits for bench A/B evidence; this is just the dial.

(2026-06-11) A security hardening briefly default-disabled WebFetch/WebSearch
here; it was REVERTED after a 14-day bench audit showed those tools fire in
119/1868 runs — default-disabling removes real research capability. The default
is empty again; operators opt in via the env var.
"""

from __future__ import annotations
import pytest
pytest.importorskip("claude_agent_sdk")

import asyncio
import os
from typing import Any
from unittest.mock import patch

import pytest

from cve_env.agent import llm
from cve_env.config import get_disallowed_tools

# ── config getter ───────────────────────────────────────────────────────────

def test_get_disallowed_tools_default_empty(monkeypatch: Any) -> None:
    monkeypatch.delenv("CVE_ENV_DISALLOWED_TOOLS", raising=False)
    assert get_disallowed_tools() == []

def test_web_tools_enabled_by_default(monkeypatch: Any) -> None:
    """Regression guard for the 2026-06-11 revert: built-in WebFetch/WebSearch
    must NOT be disabled by default (the agent uses them for research)."""
    monkeypatch.delenv("CVE_ENV_DISALLOWED_TOOLS", raising=False)
    disallowed = get_disallowed_tools()
    assert "WebFetch" not in disallowed
    assert "WebSearch" not in disallowed

def test_get_disallowed_tools_parses_csv_and_trims() -> None:
    with patch.dict(
        os.environ, {"CVE_ENV_DISALLOWED_TOOLS": "Agent, Task ,, WebSearch"}
    ):
        assert get_disallowed_tools() == ["Agent", "Task", "WebSearch"]

def test_get_disallowed_tools_empty_string_is_empty() -> None:
    with patch.dict(os.environ, {"CVE_ENV_DISALLOWED_TOOLS": "   "}):
        assert get_disallowed_tools() == []

# ── llm wiring (the load-bearing part: it reaches ClaudeAgentOptions) ─────────

def _fake_outcome() -> Any:
    return llm.AgentRunOutcome(
        stop_reason="end_turn",
        num_turns=1,
        total_cost_usd=0.0,
        is_error=False,
        session_id="s",
        final_text="",
        tool_uses=[],
    )

def _capture_options(monkeypatch: Any) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    async def _fake_rqo(
        *, options: Any, user_prompt: str, on_message: Any = None
    ) -> Any:
        captured["options"] = options
        return _fake_outcome()

    monkeypatch.setattr(llm, "_run_query_once", _fake_rqo)
    return captured

def test_run_agent_wires_disallowed_tools_from_env(monkeypatch: Any) -> None:
    captured = _capture_options(monkeypatch)
    monkeypatch.setenv("CVE_ENV_DISALLOWED_TOOLS", "Agent")
    asyncio.run(llm.run_agent(system_prompt="x", user_prompt="y", tools=[]))
    assert captured["options"].disallowed_tools == ["Agent"]

def test_run_agent_no_disallowed_tools_by_default(monkeypatch: Any) -> None:
    """Default-safe: env unset → no disallowed_tools restriction (current behavior)."""
    captured = _capture_options(monkeypatch)
    monkeypatch.delenv("CVE_ENV_DISALLOWED_TOOLS", raising=False)
    asyncio.run(llm.run_agent(system_prompt="x", user_prompt="y", tools=[]))
    assert not captured["options"].disallowed_tools  # [] or None — no restriction

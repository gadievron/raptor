"""Tests for agent/loop.py.

The core.llm ToolUseLoop provider is stubbed — these tests never hit
the network. They cover budget enforcement, tool dispatch, submit
handling, and the validator boundary. The agent's actual reasoning
quality is a bench-time question, not a unit-test question.

Migrated from Anthropic SDK fakes to core.llm substrate fakes on
2026-05-04: tests now script ``TurnResponse`` objects for a
``_FakeProvider`` instead of canned ``_FakeResp`` objects for a fake
``client.messages.create``.
"""
from __future__ import annotations

import json
from typing import Any, Callable

import pytest
from cve_diff.agent.loop import AgentConfig, AgentLoop
from cve_diff.agent.tools import Tool
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender

from core.llm.tool_use.types import (
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallDispatched,
    ToolCallReturned,
    ToolLoopResult,
    ToolResult,
    TurnResponse,
)

# ---------- fake provider -----------


class _FakeProvider:
    """Replays scripted TurnResponse objects; records calls for assertions."""

    def __init__(self, responses: list[TurnResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def supports_tool_use(self) -> bool: return True
    def supports_prompt_caching(self) -> bool: return True
    def supports_parallel_tools(self) -> bool: return False
    def context_window(self) -> int: return 200_000
    def price_per_million(self) -> tuple[float, float]: return (15.0, 75.0)
    def estimate_tokens(self, text: str) -> int: return max(len(text) // 4, 1)

    def compute_cost(self, response: TurnResponse) -> float:
        return (response.input_tokens * 15.0
                + response.output_tokens * 75.0) / 1_000_000

    def turn(self, messages, tools, *, system, max_tokens, cache_control,
             **provider_specific) -> TurnResponse:
        self.calls.append({
            "messages": list(messages),
            "tools": list(tools),
            "system": system,
            "max_tokens": max_tokens,
            "cache_control": cache_control,
            "provider_specific": dict(provider_specific),
        })
        if not self._responses:
            raise RuntimeError("fake provider exhausted scripted responses")
        return self._responses.pop(0)


# ---------- helpers -----------


def _tc_response(*tool_calls: ToolCall, in_t: int = 100, out_t: int = 50) -> TurnResponse:
    return TurnResponse(
        content=list(tool_calls),
        stop_reason=StopReason.NEEDS_TOOL_CALL,
        input_tokens=in_t,
        output_tokens=out_t,
    )


def _text_response(text: str = "done", in_t: int = 100, out_t: int = 50) -> TurnResponse:
    return TurnResponse(
        content=[TextBlock(text=text)],
        stop_reason=StopReason.COMPLETE,
        input_tokens=in_t,
        output_tokens=out_t,
    )


def _patch_provider(
    monkeypatch: pytest.MonkeyPatch,
    responses: list[TurnResponse],
) -> _FakeProvider:
    fake = _FakeProvider(responses)
    monkeypatch.setattr(
        "cve_diff.agent.loop.create_provider",
        lambda config: fake,
    )
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    return fake


def _pass_validator(payload: dict, ctx: AgentContext) -> AgentResult:
    if payload.get("outcome") == "unsupported":
        return AgentSurrender(reason="unsupported_source", detail="stub")
    return AgentOutput(value=payload.get("fix_commit", ""), rationale="stub")


def _tool(name: str, impl=None) -> Tool:
    return Tool(
        name=name,
        description=f"stub {name}",
        parameters={"type": "object", "properties": {"x": {"type": "string"}}, "required": []},
        impl=impl or (lambda **_: "stub"),
    )


def _cfg(tools: tuple[Tool, ...] = ()) -> AgentConfig:
    return AgentConfig(
        system_prompt="sys",
        user_message="find it",
        tools=tools,
        validator=_pass_validator,
        budget_tokens=10_000,
        budget_cost_usd=0.15,
        budget_s=10.0,
        max_iterations=5,
    )


def _submit_call(
    outcome: str = "rescued",
    fix_commit: str = "abc1234",
    rationale: str = "ok",
    call_id: str = "ts",
    **extra: Any,
) -> ToolCall:
    inp = {"outcome": outcome, "fix_commit": fix_commit, "rationale": rationale}
    inp.update(extra)
    return ToolCall(id=call_id, name="submit_result", input=inp)


# ---------- tests -----------

def test_client_init_failure_surrenders(monkeypatch: pytest.MonkeyPatch) -> None:
    """When provider construction raises (e.g. SDK rejects the
    config, dispatcher unreachable, etc.) the agent surrenders
    with reason="client_init_failed" rather than crashing.

    Previously this test simply dropped ``ANTHROPIC_API_KEY``, but
    after cve-diff went model-agnostic the resolver falls through
    to Claude Code OAuth for Anthropic models — which doesn't
    surrender at init, it tries to spawn ``claude``. We now mock
    ``create_provider`` to raise, which exercises the surrender
    code path directly without depending on env shape."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.setattr(
        "cve_diff.agent.loop.create_provider",
        lambda *a, **k: (_ for _ in ()).throw(
            RuntimeError("simulated SDK init failure"),
        ),
    )
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "client_init_failed"
    assert "simulated SDK init failure" in result.detail


def test_immediate_submit_rescued(monkeypatch: pytest.MonkeyPatch) -> None:
    fake = _patch_provider(monkeypatch, [
        _tc_response(_submit_call()),
    ])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "abc1234"
    assert result.tool_calls == ("submit_result",)
    assert result.cost_usd > 0
    assert fake.calls


def test_trajectory_persisted_when_env_var_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """When RAPTOR_TRAJECTORY_DIR is set, the cve-diff agent writes a
    trajectory file keyed off the CVE ID. The libexec shim sets this
    automatically from --output-dir for operator runs."""
    import json

    from core.trajectories.auto import TRAJECTORY_DIR_ENV

    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))
    _patch_provider(monkeypatch, [_tc_response(_submit_call())])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-2024-12345"))
    assert isinstance(result, AgentOutput)

    traj = (
        tmp_path / "trajectories" / "cve-diff-CVE-2024-12345"
        / "trajectory.json"
    )
    assert traj.exists(), (
        f"trajectory not at {traj}; tree was: {list(tmp_path.rglob('*'))}"
    )
    payload = json.loads(traj.read_text())
    assert payload["run_id"] == "cve-diff-CVE-2024-12345"
    assert payload["finding_id"] == "CVE-2024-12345"
    # cve_id flows into finding_id; cwe stays empty for this consumer
    assert payload["cwe"] == ""
    assert payload["terminated_by"] == "terminal_tool"


def test_partial_trajectory_persisted_on_cost_cap(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """On the CostBudgetExceeded path the agent loop must persist
    whatever messages survived to the point of termination — this is
    the case where the trajectory is MOST useful for operator
    debugging. Earlier wiring used a finally-block that only fired on
    the success path; this test pins the symmetric exception-path
    contract."""
    import json

    from core.llm.tool_use.types import (
        CostBudgetExceeded,
        Message,
        TextBlock,
    )
    from core.trajectories.auto import TRAJECTORY_DIR_ENV

    monkeypatch.setenv(TRAJECTORY_DIR_ENV, str(tmp_path))

    partial_msgs = [
        Message(role="user", content=[TextBlock(text="diff this")]),
        Message(role="assistant", content=[TextBlock(text="thinking…")]),
    ]
    exc = CostBudgetExceeded(
        "budget", messages=partial_msgs, tool_calls_made=0,
    )
    from unittest.mock import patch
    _patch_provider(monkeypatch, [_tc_response(_submit_call())])
    with patch(
        "core.llm.tool_use.loop.ToolUseLoop.run",
        side_effect=exc,
    ):
        result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-2024-99999"))
    # Surrender output expected — that's the cost-cap exit code path.
    assert isinstance(result, AgentSurrender)
    assert result.reason == "budget_cost_usd"

    traj = (
        tmp_path / "trajectories" / "cve-diff-CVE-2024-99999"
        / "trajectory.json"
    )
    assert traj.exists(), (
        f"partial trajectory not at {traj}; "
        f"tree: {list(tmp_path.rglob('*'))}"
    )
    payload = json.loads(traj.read_text())
    assert payload["terminated_by"] == "max_cost_usd"
    assert payload["finding_id"] == "CVE-2024-99999"
    # Two partial messages survived to disk.
    assert len(payload["steps"]) == 2


def test_tool_dispatched_then_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    def impl(**kw):
        calls.append(kw)
        return '{"ok": true}'

    mytool = _tool("osv_raw", impl=impl)
    fake = _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="osv_raw", input={"cve_id": "CVE-X"})),
        _tc_response(_submit_call()),
    ])
    result = AgentLoop().run(_cfg(tools=(mytool,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert calls == [{"cve_id": "CVE-X"}]
    assert len(fake.calls) == 2
    assert result.tool_calls == ("osv_raw", "submit_result")


def test_unknown_tool_errors_without_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="no_such_tool", input={})),
        _tc_response(_submit_call()),
    ])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)


def test_tool_impl_raising_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_):
        raise RuntimeError("boom")
    mytool = _tool("osv_raw", impl=boom)
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="osv_raw", input={})),
        _tc_response(_submit_call()),
    ])
    result = AgentLoop().run(_cfg(tools=(mytool,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)


def test_max_iterations_budget_surrender(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_tool = _tool("osv_raw")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="osv_raw", input={}))
        for i in range(10)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(stub_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "budget_iterations"


def test_model_stopped_without_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_provider(monkeypatch, [_text_response("I give up")])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "model_stopped_without_submit"


def test_unsupported_outcome_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_provider(monkeypatch, [
        _tc_response(_submit_call(outcome="unsupported", fix_commit="", rationale="firmware")),
    ])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "unsupported_source"


def test_model_is_opus_4_7_default() -> None:
    cfg = _cfg()
    assert cfg.model_id == "claude-opus-4-7"


def test_verified_candidates_captured_on_surrender(monkeypatch: pytest.MonkeyPatch) -> None:
    gh_tool = Tool(
        name="gh_commit_detail",
        description="stub",
        parameters={"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]},
        impl=lambda **kw: json.dumps({"slug": kw["slug"], "sha": kw["sha"], "message": "fix", "files": [], "files_total": 0, "parents": []}),
    )
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="gh_commit_detail",
                              input={"slug": "acme/widget", "sha": "deadbeef1234567"}))
        for i in range(5)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gh_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "budget_iterations"
    assert result.verified_candidates == (("acme/widget", "deadbeef1234567"),)


def test_verified_candidates_captured_from_cgit_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    cgit_tool = Tool(
        name="cgit_fetch",
        description="stub",
        parameters={"type": "object",
                    "properties": {"host": {"type": "string"},
                                   "slug": {"type": "string"},
                                   "sha": {"type": "string"}},
                    "required": ["host", "slug", "sha"]},
        impl=lambda **_: json.dumps({"url": "https://x", "body": "fix"}),
    )
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="cgit_fetch",
                              input={"host": "https://git.savannah.gnu.org",
                                     "slug": "bash",
                                     "sha": "3ee6b0b3674df3a1bee3146d40b1d62cb0e2a9e3"}))
        for i in range(5)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(cgit_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.verified_candidates == (
        ("bash", "3ee6b0b3674df3a1bee3146d40b1d62cb0e2a9e3"),
    )


def test_verified_candidates_captured_from_gitlab_commit(monkeypatch: pytest.MonkeyPatch) -> None:
    gl_tool = Tool(
        name="gitlab_commit",
        description="stub",
        parameters={"type": "object",
                    "properties": {"host": {"type": "string"},
                                   "slug": {"type": "string"},
                                   "sha": {"type": "string"}},
                    "required": ["host", "slug", "sha"]},
        impl=lambda **_: json.dumps({"id": "x", "title": "fix", "message": "m"}),
    )
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="gitlab_commit",
                              input={"host": "https://gitlab.com",
                                     "slug": "libtiff/libtiff",
                                     "sha": "deadbeef1234567"}))
        for i in range(5)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gl_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.verified_candidates == (
        ("libtiff/libtiff", "deadbeef1234567"),
    )


def test_verified_candidates_skipped_when_forge_tool_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    cgit_err = Tool(
        name="cgit_fetch",
        description="stub",
        parameters={"type": "object",
                    "properties": {"host": {"type": "string"},
                                   "slug": {"type": "string"},
                                   "sha": {"type": "string"}},
                    "required": ["host", "slug", "sha"]},
        impl=lambda **_: json.dumps({"error": "http 404"}),
    )
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="cgit_fetch",
                              input={"host": "x", "slug": "y", "sha": "z"}))
        for i in range(5)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(cgit_err,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.verified_candidates == ()


def test_verified_candidates_skipped_when_gh_returns_error(monkeypatch: pytest.MonkeyPatch) -> None:
    err_tool = Tool(
        name="gh_commit_detail",
        description="stub",
        parameters={"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]},
        impl=lambda **_: json.dumps({"error": "not found"}),
    )
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id=f"t{i}", name="gh_commit_detail",
                              input={"slug": "noise/repo", "sha": "abc1234"}))
        for i in range(5)
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(err_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.verified_candidates == ()


# ---------- call_id-keyed (slug, sha) recovery ----------
#
# The cgit_fetch / gitlab_commit verification arm recovers the
# (slug, sha) pair a tool call was dispatched with. Keying recovery off
# the globally most-recently-dispatched input misattributes pairs into
# ``verified`` (the evidence store behind the verified-SHA gate) under
# parallel dispatch or out-of-order returns; the dispatched input must
# ride along in the call_id index so each return recovers exactly the
# input it was dispatched with. The real ToolUseLoop is replaced with a
# scripted fake that drives the events callback with interleaved
# orderings the serial loop cannot currently produce — the regression
# net for any future async/parallel loop substrate.

_SHA_A = "a" * 40
_SHA_B = "b" * 40


def _ok_result(call_id: str, content: str = '{"url": "u", "body": "ok"}') -> ToolResult:
    return ToolResult(tool_use_id=call_id, content=content)


def _scripted_loop_result() -> ToolLoopResult:
    return ToolLoopResult(
        final_text="",
        terminal_tool_input={
            "outcome": "rescued",
            "repository_url": "https://github.com/proj/alpha",
            "fix_commit": _SHA_A,
            "rationale": "stub",
        },
        messages=[],
        iterations=1,
        tool_calls_made=2,
        total_input_tokens=10,
        total_output_tokens=5,
        total_cost_usd=0.0,
        terminated_by="terminal_tool",
    )


def _fake_loop_cls(script: Callable[[Callable], ToolLoopResult]) -> type:
    """A ToolUseLoop stand-in whose run() replays ``script(events)``."""

    class _FakeLoop:
        def __init__(self, **kwargs: Any) -> None:
            self._events = kwargs["events"]

        def run(self, _user_message: str) -> ToolLoopResult:
            return script(self._events)

    return _FakeLoop


def _run_with_script(
    monkeypatch: pytest.MonkeyPatch,
    script: Callable[[Callable], ToolLoopResult],
    *tool_names: str,
) -> AgentResult:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    monkeypatch.delenv("RAPTOR_TRAJECTORY_DIR", raising=False)
    monkeypatch.setattr("cve_diff.agent.loop.create_provider", lambda config: object())
    monkeypatch.setattr("cve_diff.agent.loop.ToolUseLoop", _fake_loop_cls(script))
    cfg = _cfg(tools=tuple(_tool(n) for n in tool_names))
    return AgentLoop().run(cfg, AgentContext(cve_id="CVE-2024-1"))


def test_parallel_cgit_dispatch_attributes_each_return_to_its_own_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two cgit_fetch calls dispatched before either returns: each
    return must land the (slug, sha) it was dispatched with, not the
    most recently dispatched pair."""
    call_a = ToolCall(id="c1", name="cgit_fetch",
                      input={"host": "h", "slug": "proj/alpha", "sha": _SHA_A})
    call_b = ToolCall(id="c2", name="cgit_fetch",
                      input={"host": "h", "slug": "proj/beta", "sha": _SHA_B})

    def script(emit: Callable) -> ToolLoopResult:
        emit(ToolCallDispatched(iteration=0, call=call_a))
        emit(ToolCallDispatched(iteration=0, call=call_b))
        emit(ToolCallReturned(iteration=0, call_id="c1",
                              result=_ok_result("c1"), duration_s=0.0))
        emit(ToolCallReturned(iteration=0, call_id="c2",
                              result=_ok_result("c2"), duration_s=0.0))
        return _scripted_loop_result()

    result = _run_with_script(monkeypatch, script, "cgit_fetch")
    assert isinstance(result, AgentOutput)
    assert result.verified_candidates == (
        ("proj/alpha", _SHA_A),
        ("proj/beta", _SHA_B),
    )


def test_out_of_order_gitlab_returns_still_attributed_by_call_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Returns arriving in reverse dispatch order must still recover
    each call's own (slug, sha)."""
    call_a = ToolCall(id="g1", name="gitlab_commit",
                      input={"host": "h", "slug": "grp/alpha", "sha": _SHA_A})
    call_b = ToolCall(id="g2", name="gitlab_commit",
                      input={"host": "h", "slug": "grp/beta", "sha": _SHA_B})
    body = json.dumps({"id": _SHA_A, "title": "fix"})

    def script(emit: Callable) -> ToolLoopResult:
        emit(ToolCallDispatched(iteration=0, call=call_a))
        emit(ToolCallDispatched(iteration=0, call=call_b))
        emit(ToolCallReturned(iteration=0, call_id="g2",
                              result=_ok_result("g2", body), duration_s=0.0))
        emit(ToolCallReturned(iteration=0, call_id="g1",
                              result=_ok_result("g1", body), duration_s=0.0))
        return _scripted_loop_result()

    result = _run_with_script(monkeypatch, script, "gitlab_commit")
    assert isinstance(result, AgentOutput)
    assert result.verified_candidates == (
        ("grp/beta", _SHA_B),
        ("grp/alpha", _SHA_A),
    )


def test_cgit_return_after_unrelated_dispatch_uses_own_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cgit_fetch return arriving after a LATER unrelated dispatch
    (the exact 'most recent dispatch' trap) must not pick up the
    unrelated call's arguments."""
    cgit = ToolCall(id="c1", name="cgit_fetch",
                    input={"host": "h", "slug": "proj/alpha", "sha": _SHA_A})
    other = ToolCall(id="o1", name="osv_raw", input={"cve_id": "CVE-2024-1"})

    def script(emit: Callable) -> ToolLoopResult:
        emit(ToolCallDispatched(iteration=0, call=cgit))
        emit(ToolCallDispatched(iteration=0, call=other))
        emit(ToolCallReturned(iteration=0, call_id="c1",
                              result=_ok_result("c1"), duration_s=0.0))
        emit(ToolCallReturned(iteration=0, call_id="o1",
                              result=_ok_result("o1", '{"x": 1}'), duration_s=0.0))
        return _scripted_loop_result()

    result = _run_with_script(monkeypatch, script, "cgit_fetch", "osv_raw")
    assert isinstance(result, AgentOutput)
    assert result.verified_candidates == (("proj/alpha", _SHA_A),)


def test_provider_error_surrenders_as_llm_error(monkeypatch: pytest.MonkeyPatch) -> None:
    """A provider exception surfaces as reason=llm_error."""
    class _FailProvider(_FakeProvider):
        def turn(self, messages, tools, *, system, max_tokens, cache_control,
                 **provider_specific):
            raise RuntimeError("API down")

    monkeypatch.setattr("cve_diff.agent.loop.create_provider", lambda config: _FailProvider([]))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "llm_error"


# ---------- task_budget beta integration ----------

def test_task_budget_beta_passes_provider_kwargs(monkeypatch: pytest.MonkeyPatch) -> None:
    """When enable_task_budgets=True (default), the ToolUseLoop receives
    anthropic_task_budget_beta=True and anthropic_task_budget_tokens."""
    fake = _patch_provider(monkeypatch, [
        _tc_response(_submit_call()),
    ])
    AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))

    assert fake.calls
    kw = fake.calls[0]["provider_specific"]
    assert kw.get("anthropic_task_budget_beta") is True
    assert kw.get("anthropic_task_budget_tokens") == 10_000


def test_task_budget_disabled_skips_provider_kwargs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flipping enable_task_budgets=False omits the task budget kwargs."""
    fake = _patch_provider(monkeypatch, [
        _tc_response(_submit_call()),
    ])
    cfg = AgentConfig(
        system_prompt="sys",
        user_message="find it",
        tools=(),
        validator=_pass_validator,
        budget_tokens=10_000,
        budget_cost_usd=0.15,
        budget_s=10.0,
        max_iterations=5,
        enable_task_budgets=False,
    )
    AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))

    assert fake.calls
    kw = fake.calls[0]["provider_specific"]
    assert "anthropic_task_budget_beta" not in kw
    assert "anthropic_task_budget_tokens" not in kw


# ---------- CVE_DIFF_DISABLE_RULES env switch ----------

def test_rules_disabled_skips_cascade(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CVE_DIFF_DISABLE_RULES", "1")
    osv_tool = _tool("osv_raw", impl=lambda **_: '{"ok": true}')
    responses = [
        _tc_response(ToolCall(id=f"t{i}", name="osv_raw", input={"cve_id": f"CVE-X{i}"}))
        for i in range(3)
    ] + [
        _tc_response(_submit_call()),
    ]
    _patch_provider(monkeypatch, responses)
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(osv_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)


@pytest.mark.parametrize("value", ["1", "true", "yes", "on", "TRUE"])
def test_rules_disabled_shared_truthy_spellings(
    monkeypatch: pytest.MonkeyPatch, value: str,
) -> None:
    """Pre-fix only the exact string ``1`` disabled the rules —
    ``CVE_DIFF_DISABLE_RULES=true`` silently left them on."""
    from cve_diff.agent.loop import _rules_disabled

    monkeypatch.setenv("CVE_DIFF_DISABLE_RULES", value)
    assert _rules_disabled() is True


@pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
def test_rules_enabled_falsy_and_empty_spellings(
    monkeypatch: pytest.MonkeyPatch, value: str,
) -> None:
    from cve_diff.agent.loop import _rules_disabled

    monkeypatch.setenv("CVE_DIFF_DISABLE_RULES", value)
    assert _rules_disabled() is False


def test_rules_enabled_when_unset_or_unrecognised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from cve_diff.agent.loop import _rules_disabled

    monkeypatch.delenv("CVE_DIFF_DISABLE_RULES", raising=False)
    assert _rules_disabled() is False
    monkeypatch.setenv("CVE_DIFF_DISABLE_RULES", "disable")
    assert _rules_disabled() is False


# ---------- Verified-SHA submit gate ----------


def _gh_tool(slug: str, sha: str) -> Tool:
    def _impl(slug: str = slug, sha: str = sha) -> str:
        return json.dumps({"slug": slug, "sha": sha, "message": "fix",
                           "files": [], "files_total": 0, "parents": []})
    return Tool(
        name="gh_commit_detail",
        description="stub",
        parameters={"type": "object",
                    "properties": {"slug": {"type": "string"},
                                   "sha": {"type": "string"}},
                    "required": ["slug", "sha"]},
        impl=_impl,
    )


def test_verified_sha_gate_rejects_unverified_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cve_diff.infra.github_client.commit_exists",
                        lambda slug, sha: True)
    gh = _gh_tool("acme/widget", "deadbeef0000")
    fake = _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "acme/widget", "sha": "deadbeef0000"})),
        _tc_response(_submit_call(
            fix_commit="cafebabe9999", rationale="submitted typo",
            repository_url="https://github.com/acme/widget")),
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="fixed it",
            repository_url="https://github.com/acme/widget")),
    ])
    result = AgentLoop().run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"
    assert len(fake.calls) == 3
    third_call_msgs = fake.calls[2]["messages"]
    rejection_found = False
    for msg in third_call_msgs:
        for block in msg.content:
            if (isinstance(block, ToolResult) and block.is_error
                    and "submit_rejected" in block.content):
                rejection_found = True
    assert rejection_found, "submit_rejected feedback never sent to the agent"


def test_verified_sha_gate_accepts_prefix_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cve_diff.infra.github_client.commit_exists",
                        lambda slug, sha: True)
    gh = _gh_tool("acme/widget", "deadbeef00001234567")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "acme/widget",
                                     "sha": "deadbeef00001234567"})),
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="fixed it",
            repository_url="https://github.com/acme/widget")),
    ])
    result = AgentLoop().run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"


def test_verified_sha_gate_surrenders_after_three_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gh = _gh_tool("acme/widget", "real00000000")
    bad_submit = _submit_call(
        fix_commit="phantom00000", rationale="still wrong",
        repository_url="https://github.com/acme/widget")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "acme/widget", "sha": "real00000000"})),
        _tc_response(bad_submit),
        _tc_response(bad_submit),
        _tc_response(bad_submit),
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gh,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "submit_unverified_sha"


def test_verified_sha_gate_skipped_for_non_github_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_provider(monkeypatch, [
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="non-github forge",
            repository_url="https://gitlab.freedesktop.org/xkb/xkbcommon")),
    ])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"


# ---------- SHA-existence (404) submit gate ----------


def test_sha_not_found_gate_rejects_404_submit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "cve_diff.infra.github_client.commit_exists",
        lambda slug, sha: not (
            len(sha) == 40 and sha.startswith("fb4415d8aee6c14")),
    )
    gh = _gh_tool("curl/curl", "fb4415d8aee6")
    fake = _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "curl/curl", "sha": "fb4415d8aee6"})),
        _tc_response(_submit_call(
            fix_commit="fb4415d8aee6c14a9ec300ca28dfe318fe85e1cc",
            rationale="hallucinated tail",
            repository_url="https://github.com/curl/curl")),
        _tc_response(_submit_call(
            fix_commit="fb4415d8aee6",
            rationale="verified prefix",
            repository_url="https://github.com/curl/curl")),
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gh,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-2023-38545"))
    assert isinstance(result, AgentOutput), \
        f"expected AgentOutput, got {type(result).__name__}: {getattr(result,'reason','')}"
    assert result.value == "fb4415d8aee6"
    assert len(fake.calls) == 3
    third_call_msgs = fake.calls[2]["messages"]
    rejection_found = False
    for msg in third_call_msgs:
        for block in msg.content:
            if (isinstance(block, ToolResult) and block.is_error
                    and "sha_not_found" in block.content):
                rejection_found = True
    assert rejection_found, "404 feedback never sent to the agent"


def test_sha_not_found_gate_surrenders_after_three_404s(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "cve_diff.infra.github_client.commit_exists",
        lambda slug, sha: False,
    )
    gh = _gh_tool("curl/curl", "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb")
    bad_submit = _submit_call(
        fix_commit="fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb",
        rationale="still 404",
        repository_url="https://github.com/curl/curl")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "curl/curl",
                                     "sha": "fb4415d8aee6c10a4ce3328c42b9c2e4eb5bbafb"})),
        _tc_response(bad_submit),
        _tc_response(bad_submit),
        _tc_response(bad_submit),
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gh,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-2023-38545"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "sha_not_found_in_repo"


def test_sha_not_found_gate_skipped_when_commit_exists_returns_none(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    def _track(slug: str, sha: str):
        calls.append((slug, sha))
    monkeypatch.setattr("cve_diff.infra.github_client.commit_exists", _track)
    gh = _gh_tool("acme/widget", "deadbeef0000")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "acme/widget", "sha": "deadbeef0000"})),
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="rate-limited path",
            repository_url="https://github.com/acme/widget")),
    ])
    result = AgentLoop().run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"
    assert calls == [("acme/widget", "deadbeef0000")], "gate should still call commit_exists once"


def test_sha_not_found_gate_skipped_for_non_github_urls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "cve_diff.infra.github_client.commit_exists",
        lambda slug, sha: calls.append((slug, sha)) or False,
    )
    _patch_provider(monkeypatch, [
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="non-github forge",
            repository_url="https://gitlab.freedesktop.org/xkb/xkbcommon")),
    ])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"
    assert calls == [], "commit_exists must not be called for non-GitHub URLs"


# ---------- Gate-firing telemetry counters ----------


def test_telemetry_unverified_submits_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("cve_diff.infra.github_client.commit_exists",
                        lambda slug, sha: True)
    gh = _gh_tool("acme/widget", "deadbeef0000")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "acme/widget", "sha": "deadbeef0000"})),
        _tc_response(_submit_call(
            fix_commit="cafebabe9999", rationale="typo",
            repository_url="https://github.com/acme/widget")),
        _tc_response(_submit_call(
            fix_commit="deadbeef0000", rationale="fixed it",
            repository_url="https://github.com/acme/widget")),
    ])
    loop = AgentLoop()
    result = loop.run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert loop.last_telemetry["unverified_submits"] == 1
    assert loop.last_telemetry["not_found_submits"] == 0


def test_telemetry_not_found_submits_counter(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "cve_diff.infra.github_client.commit_exists",
        lambda slug, sha: len(sha) != 40,
    )
    gh = _gh_tool("curl/curl", "fb4415d8aee6")
    _patch_provider(monkeypatch, [
        _tc_response(ToolCall(id="t1", name="gh_commit_detail",
                              input={"slug": "curl/curl", "sha": "fb4415d8aee6"})),
        _tc_response(_submit_call(
            fix_commit="fb4415d8aee6c14a9ec300ca28dfe318fe85e1cc",
            rationale="hallucinated",
            repository_url="https://github.com/curl/curl")),
        _tc_response(_submit_call(
            fix_commit="fb4415d8aee6", rationale="real",
            repository_url="https://github.com/curl/curl")),
    ])
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(gh,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    loop = AgentLoop()
    result = loop.run(cfg, AgentContext(cve_id="CVE-2023-38545"))
    assert isinstance(result, AgentOutput)
    assert loop.last_telemetry["not_found_submits"] == 1
    assert loop.last_telemetry["unverified_submits"] == 0


# ── pricing delegation ────────────────────────────────────────────────

def test_price_uses_core_model_table_not_stale_fallback():
    """The loop's fast-path pricing must come from core.llm.model_data —
    the local class-token table had drifted to 3x the real Opus price
    (15/75 vs 5/25 per M-token), tripling budget burn accounting."""
    from cve_diff.agent.loop import _price

    from core.llm.model_data import price_for

    in_per_m, out_per_m = price_for("claude-opus-5")
    assert (in_per_m, out_per_m) != (0.0, 0.0)
    got = _price("claude-opus-5", in_t=1_000_000, out_t=0)
    assert got == pytest.approx(in_per_m)
    # regression pin: the stale fallback said $15/M for opus input
    assert got < 10.0


def test_price_falls_back_to_class_token_for_unknown_models():
    from cve_diff.agent.loop import _price
    got = _price("my-custom-opus-finetune", in_t=1_000_000, out_t=0)
    assert got == pytest.approx(5.0)


def test_price_unknown_model_is_zero():
    from cve_diff.agent.loop import _price
    assert _price("totally-unknown-model", in_t=1000, out_t=1000) == 0.0


def test_turn_completed_emits_run_local_telemetry(
    monkeypatch: pytest.MonkeyPatch, tmp_path,
) -> None:
    """Each completed provider turn writes one llm-telemetry.jsonl
    record (call_class cve-diff:discovery) when a sink is installed —
    the run-local cost ledger the libexec shim and the Typer CLI
    install at run start. Without a sink the emit is a no-op, so the
    bench and library consumers pay nothing."""
    from core.llm.telemetry import TelemetrySink, set_sink

    _patch_provider(monkeypatch, [_tc_response(_submit_call())])
    sink = TelemetrySink(tmp_path / "llm-telemetry.jsonl")
    set_sink(sink)
    try:
        result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    finally:
        set_sink(None)

    assert isinstance(result, AgentOutput)
    lines = (tmp_path / "llm-telemetry.jsonl").read_text().splitlines()
    recs = [json.loads(line) for line in lines]
    discovery = [r for r in recs if r.get("call_class") == "cve-diff:discovery"]
    assert discovery, f"no discovery telemetry records in {recs}"
    rec = discovery[0]
    assert rec["event"] == "call"
    assert rec["model"] == _cfg().model_id
    assert rec["provider"] == "anthropic"
    assert rec["tokens_in"] == 100
    assert rec["tokens_out"] == 50
    assert rec["cost_usd"] > 0

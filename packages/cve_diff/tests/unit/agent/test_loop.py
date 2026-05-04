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
from typing import Any

import pytest

from core.llm.tool_use.types import (
    StopReason,
    TextBlock,
    ToolCall,
    ToolResult,
    TurnResponse,
)

from cve_diff.agent.loop import AgentConfig, AgentLoop
from cve_diff.agent.tools import Tool
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender


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
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "client_init_failed"


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
            if isinstance(block, ToolResult) and block.is_error:
                if "submit_rejected" in block.content:
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
        lambda slug, sha: False if len(sha) == 40 and sha.startswith("fb4415d8aee6c14") else True,
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
            if isinstance(block, ToolResult) and block.is_error:
                if "sha_not_found" in block.content:
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
        return None
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
        lambda slug, sha: False if len(sha) == 40 else True,
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

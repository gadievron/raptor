"""Tests for agent/loop.py.

The Anthropic client is stubbed — these tests never hit the network.
They cover budget enforcement, tool dispatch, submit handling, and the
validator boundary. The agent's actual reasoning quality is a bench-
time question, not a unit-test question.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from cve_diff.agent.loop import AgentConfig, AgentLoop
from cve_diff.agent.tools import Tool
from cve_diff.agent.types import AgentContext, AgentOutput, AgentResult, AgentSurrender


# ---------- fakes -----------

@dataclass
class _FakeUsage:
    input_tokens: int = 100
    output_tokens: int = 50


@dataclass
class _FakeBlock:
    type: str
    text: str = ""
    id: str = ""
    name: str = ""
    input: dict = None


@dataclass
class _FakeResp:
    content: list
    usage: _FakeUsage


class _FakeMessages:
    def __init__(self, responses: list[_FakeResp]) -> None:
        self._responses = list(responses)
        self.calls = 0
        # Record kwargs for each call so tests can verify what the
        # loop sent to the API (betas, output_config, etc).
        self.kwargs_log: list[dict[str, Any]] = []

    def create(self, **kw: Any) -> _FakeResp:
        self.calls += 1
        self.kwargs_log.append(kw)
        if not self._responses:
            raise RuntimeError("ran out of canned responses")
        return self._responses.pop(0)


class _FakeBetaNamespace:
    """Mirrors `client.beta.messages` → same _FakeMessages instance."""
    def __init__(self, messages: _FakeMessages) -> None:
        self.messages = messages


class _FakeClient:
    def __init__(self, responses: list[_FakeResp]) -> None:
        self.messages = _FakeMessages(responses)
        # `client.beta.messages` shares the same fake so kwargs are
        # captured regardless of which call path the loop uses.
        self.beta = _FakeBetaNamespace(self.messages)


def _patch_client(monkeypatch: pytest.MonkeyPatch, responses: list[_FakeResp]) -> _FakeClient:
    fake = _FakeClient(responses)
    monkeypatch.setattr(AgentLoop, "_client", lambda self: fake)
    return fake


def _pass_validator(payload: dict, ctx: AgentContext) -> AgentResult:
    if payload.get("outcome") == "unsupported":
        return AgentSurrender(reason="UnsupportedSource", detail="stub")
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


# ---------- tests -----------

def test_client_init_failure_surrenders(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    # Bypass the _client stub — use the real one, which will raise.
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "client_init_failed"


def test_immediate_submit_rescued(monkeypatch: pytest.MonkeyPatch) -> None:
    resp = _FakeResp(
        content=[
            _FakeBlock(type="tool_use", id="t1", name="submit_result",
                       input={"outcome": "rescued", "fix_commit": "abc1234", "rationale": "ok"}),
        ],
        usage=_FakeUsage(),
    )
    _patch_client(monkeypatch, [resp])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "abc1234"
    assert result.tool_calls == ("submit_result",)
    assert result.cost_usd > 0


def test_tool_dispatched_then_submit(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict] = []

    def impl(**kw):
        calls.append(kw)
        return '{"ok": true}'

    mytool = _tool("osv_raw", impl=impl)
    resp1 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="osv_raw", input={"cve_id": "CVE-X"})],
        usage=_FakeUsage(),
    )
    resp2 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t2", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc1234", "rationale": "ok"})],
        usage=_FakeUsage(),
    )
    fake = _patch_client(monkeypatch, [resp1, resp2])
    result = AgentLoop().run(_cfg(tools=(mytool,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert calls == [{"cve_id": "CVE-X"}]
    assert fake.messages.calls == 2
    assert result.tool_calls == ("osv_raw", "submit_result")


def test_unknown_tool_errors_without_crash(monkeypatch: pytest.MonkeyPatch) -> None:
    resp1 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="no_such_tool", input={})],
        usage=_FakeUsage(),
    )
    resp2 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t2", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc1234", "rationale": "ok"})],
        usage=_FakeUsage(),
    )
    _patch_client(monkeypatch, [resp1, resp2])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)


def test_tool_impl_raising_is_caught(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(**_):
        raise RuntimeError("boom")
    mytool = _tool("osv_raw", impl=boom)
    resp1 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="osv_raw", input={})],
        usage=_FakeUsage(),
    )
    resp2 = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t2", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc1234", "rationale": "ok"})],
        usage=_FakeUsage(),
    )
    _patch_client(monkeypatch, [resp1, resp2])
    result = AgentLoop().run(_cfg(tools=(mytool,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)  # loop survived the tool error


def test_max_iterations_budget_surrender(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each response calls a tool but never submits.
    stub_tool = _tool("osv_raw")
    many = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="osv_raw", input={})],
            usage=_FakeUsage(),
        )
        for i in range(10)
    ]
    _patch_client(monkeypatch, many)
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
    resp = _FakeResp(
        content=[_FakeBlock(type="text", text="I give up")],
        usage=_FakeUsage(),
    )
    _patch_client(monkeypatch, [resp])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "model_stopped_without_submit"


def test_unsupported_outcome_passes_through(monkeypatch: pytest.MonkeyPatch) -> None:
    resp = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="submit_result",
                            input={"outcome": "unsupported", "rationale": "firmware"})],
        usage=_FakeUsage(),
    )
    _patch_client(monkeypatch, [resp])
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "UnsupportedSource"


def test_model_is_opus_4_7_default() -> None:
    cfg = _cfg()
    assert cfg.model_id == "claude-opus-4-7"


def test_verified_candidates_captured_on_surrender(monkeypatch: pytest.MonkeyPatch) -> None:
    """A successful gh_commit_detail call followed by budget exhaustion
    should surface the (slug, sha) on the surrender for the retry path."""
    import json

    def gh_impl(slug: str = "", sha: str = "") -> str:
        return json.dumps({"slug": slug, "sha": sha, "message": "fix", "files": [], "files_total": 0, "parents": []})

    gh_tool = Tool(
        name="gh_commit_detail",
        description="stub",
        parameters={"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]},
        impl=gh_impl,
    )
    # Iteration 1: agent calls gh_commit_detail with a real (slug, sha).
    # Iterations 2-4: agent stalls on the same tool until max_iterations=3 trips.
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="gh_commit_detail",
                                input={"slug": "acme/widget", "sha": "deadbeef1234567"})],
            usage=_FakeUsage(),
        )
        for i in range(5)
    ]
    _patch_client(monkeypatch, responses)
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
    """cgit_fetch is a verification tool (per source_classes.VERIFICATION_TOOLS)
    and successful calls should populate `verified_candidates` so that
    `_maybe_retry` fires when the agent hits a budget cap. Bug caught
    2026-04-30 on CVE-2014-6271 (Shellshock): the agent verified bash
    commits via cgit_fetch from Savannah but `verified` only captured
    gh_commit_detail successes — meta_retry didn't fire on the
    inevitable budget walk."""
    import json

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
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="cgit_fetch",
                                input={"host": "https://git.savannah.gnu.org",
                                       "slug": "bash",
                                       "sha": "3ee6b0b3674df3a1bee3146d40b1d62cb0e2a9e3"})],
            usage=_FakeUsage(),
        )
        for i in range(5)
    ]
    _patch_client(monkeypatch, responses)
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
    """gitlab_commit is a verification tool — successful calls populate
    `verified_candidates` so meta_retry can pin the agent to the GitLab
    pick on a budget walk (relevant for libtiff and other GitLab-hosted
    projects)."""
    import json

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
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="gitlab_commit",
                                input={"host": "https://gitlab.com",
                                       "slug": "libtiff/libtiff",
                                       "sha": "deadbeef1234567"})],
            usage=_FakeUsage(),
        )
        for i in range(5)
    ]
    _patch_client(monkeypatch, responses)
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
    """cgit_fetch / gitlab_commit returning an error JSON must NOT be
    captured (parallels the gh_commit_detail error-skip behaviour)."""
    import json

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
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="cgit_fetch",
                                input={"host": "x", "slug": "y", "sha": "z"})],
            usage=_FakeUsage(),
        )
        for i in range(5)
    ]
    _patch_client(monkeypatch, responses)
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
    """gh_commit_detail returning an error JSON must NOT be captured as verified."""
    import json

    err_tool = Tool(
        name="gh_commit_detail",
        description="stub",
        parameters={"type": "object", "properties": {"slug": {"type": "string"}, "sha": {"type": "string"}}, "required": ["slug", "sha"]},
        impl=lambda **_: json.dumps({"error": "not found"}),
    )
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="gh_commit_detail",
                                input={"slug": "noise/repo", "sha": "abc1234"})],
            usage=_FakeUsage(),
        )
        for i in range(5)
    ]
    _patch_client(monkeypatch, responses)
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(err_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=3,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.verified_candidates == ()


def test_llm_error_retries_then_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """A transient connection error on the first attempt should retry and succeed."""
    from anthropic import APIConnectionError
    import httpx

    success = _FakeResp(
        content=[
            _FakeBlock(type="tool_use", id="t1", name="submit_result",
                       input={"outcome": "rescued", "fix_commit": "abc1234", "rationale": "ok"}),
        ],
        usage=_FakeUsage(),
    )

    class _FlakyMessages:
        def __init__(self) -> None:
            self.calls = 0

        def create(self, **_kw: Any) -> _FakeResp:
            self.calls += 1
            if self.calls == 1:
                raise APIConnectionError(request=httpx.Request("POST", "http://stub"))
            return success

    class _FlakyClient:
        def __init__(self) -> None:
            self.messages = _FlakyMessages()
            self.beta = _FakeBetaNamespace(self.messages)

    flaky = _FlakyClient()
    monkeypatch.setattr(AgentLoop, "_client", lambda self: flaky)
    monkeypatch.setattr("cve_diff.agent.loop.time.sleep", lambda _s: None)
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert flaky.messages.calls == 2  # 1 fail + 1 retry success


def test_llm_error_retries_exhaust_then_surrender(monkeypatch: pytest.MonkeyPatch) -> None:
    """If all 3 attempts fail, surrender with reason=llm_error."""
    from anthropic import APIConnectionError
    import httpx

    class _AlwaysFlaky:
        def __init__(self) -> None:
            self.calls = 0

        def create(self, **_kw: Any) -> _FakeResp:
            self.calls += 1
            raise APIConnectionError(request=httpx.Request("POST", "http://stub"))

    class _FailClient:
        def __init__(self) -> None:
            self.messages = _AlwaysFlaky()
            self.beta = _FakeBetaNamespace(self.messages)

    failing = _FailClient()
    monkeypatch.setattr(AgentLoop, "_client", lambda self: failing)
    monkeypatch.setattr("cve_diff.agent.loop.time.sleep", lambda _s: None)
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentSurrender)
    assert result.reason == "llm_error"
    assert failing.messages.calls == 3  # 3 attempts (1 + 2 retries)


# ---------- task_budget beta integration (Action B) ----------

def test_task_budget_beta_call_passes_betas_header(monkeypatch: pytest.MonkeyPatch) -> None:
    """When `enable_task_budgets=True` (the default), the loop calls
    `client.beta.messages.create` with `betas=["task-budgets-2026-03-13"]`
    so Anthropic's beta gate accepts the request."""
    resp = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc",
                                   "rationale": "stub"})],
        usage=_FakeUsage(),
    )
    fake = _patch_client(monkeypatch, [resp])
    AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))

    assert fake.messages.calls == 1
    kw = fake.messages.kwargs_log[0]
    assert kw.get("betas") == ["task-budgets-2026-03-13"]


def test_task_budget_beta_call_passes_output_config(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each request includes `output_config.task_budget` keyed to
    `AgentConfig.budget_tokens`. Server tracks `remaining` itself; we
    omit it per Anthropic's guidance to keep the prompt cache prefix
    stable across follow-ups."""
    resp = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc",
                                   "rationale": "stub"})],
        usage=_FakeUsage(),
    )
    fake = _patch_client(monkeypatch, [resp])
    cfg = _cfg()
    AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))

    kw = fake.messages.kwargs_log[0]
    output_config = kw.get("output_config")
    assert output_config is not None, "output_config not passed to beta API"
    tb = output_config.get("task_budget")
    assert tb is not None, "task_budget not set in output_config"
    assert tb["type"] == "tokens"
    assert tb["total"] == cfg.budget_tokens
    assert "remaining" not in tb, "remaining should be omitted (server tracks)"


def test_task_budget_disabled_via_flag_uses_messages_namespace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Flipping `enable_task_budgets=False` reverts to the non-beta
    `client.messages.create` path so we can disable if the beta API
    misbehaves. No betas header, no output_config."""
    resp = _FakeResp(
        content=[_FakeBlock(type="tool_use", id="t1", name="submit_result",
                            input={"outcome": "rescued", "fix_commit": "abc",
                                   "rationale": "stub"})],
        usage=_FakeUsage(),
    )
    fake = _patch_client(monkeypatch, [resp])
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

    assert fake.messages.calls == 1
    kw = fake.messages.kwargs_log[0]
    assert "betas" not in kw
    assert "output_config" not in kw


# ---------- CVE_DIFF_DISABLE_RULES env switch (cascade only) ----------

def test_rules_disabled_skips_cascade(monkeypatch: pytest.MonkeyPatch) -> None:
    """With CVE_DIFF_DISABLE_RULES=1, the cascade-surrender rule is skipped.
    The iter-3 reflection hint that this flag also gated is now retired
    (2026-04-26); the flag survives only as the cascade kill-switch.
    """
    monkeypatch.setenv("CVE_DIFF_DISABLE_RULES", "1")
    osv_tool = _tool("osv_raw", impl=lambda **_: '{"ok": true}')
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id=f"t{i}", name="osv_raw",
                                input={"cve_id": f"CVE-X{i}"})],
            usage=_FakeUsage(),
        )
        for i in range(3)
    ] + [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="ts", name="submit_result",
                                input={"outcome": "rescued", "fix_commit": "abc1234",
                                       "rationale": "ok"})],
            usage=_FakeUsage(),
        ),
    ]
    _patch_client(monkeypatch, responses)
    cfg = AgentConfig(
        system_prompt="sys", user_message="go",
        tools=(osv_tool,), validator=_pass_validator,
        budget_tokens=1_000_000, budget_cost_usd=1.0, budget_s=60.0,
        max_iterations=10,
    )
    result = AgentLoop().run(cfg, AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)


# ---------- Verified-SHA submit gate ----------

import json as _json


def _gh_tool(slug: str, sha: str) -> Tool:
    """A `gh_commit_detail` stub that records (slug, sha) into the
    loop's `verified` list (the loop reads from the tool's JSON output)."""
    def _impl(slug: str = slug, sha: str = sha) -> str:
        return _json.dumps({"slug": slug, "sha": sha, "message": "fix",
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
    """Submit with a (slug, sha) NOT seen by gh_commit_detail returns a
    tool_result with submit_rejected=true; the loop continues, doesn't
    terminate."""
    gh = _gh_tool("acme/widget", "deadbeef0000")
    responses = [
        # Iter 1: agent verifies one (slug, sha)
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t1", name="gh_commit_detail",
                                input={"slug": "acme/widget", "sha": "deadbeef0000"})],
            usage=_FakeUsage(),
        ),
        # Iter 2: agent submits a *different* SHA (typo / fork pick)
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t2", name="submit_result",
                                input={"outcome": "rescued",
                                       "repository_url": "https://github.com/acme/widget",
                                       "fix_commit": "cafebabe9999",
                                       "rationale": "submitted typo"})],
            usage=_FakeUsage(),
        ),
        # Iter 3: agent re-submits the verified SHA
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t3", name="submit_result",
                                input={"outcome": "rescued",
                                       "repository_url": "https://github.com/acme/widget",
                                       "fix_commit": "deadbeef0000",
                                       "rationale": "fixed it"})],
            usage=_FakeUsage(),
        ),
    ]
    fake = _patch_client(monkeypatch, responses)
    result = AgentLoop().run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"
    # Confirm the rejection tool_result was actually fed back.
    rejection_seen = False
    for kw in fake.messages.kwargs_log:
        for m in kw.get("messages", []):
            content = m.get("content")
            if isinstance(content, list):
                for block in content:
                    text = block.get("content", "") if isinstance(block, dict) else ""
                    if isinstance(text, str) and "submit_rejected" in text:
                        rejection_seen = True
    assert rejection_seen, "submit_rejected feedback never sent to the agent"


def test_verified_sha_gate_accepts_prefix_match(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Agent verifies a 12-char SHA via gh_commit_detail then submits
    the same 12 chars (or a prefix of the SHA the tool returned). The
    gate accepts prefix-match in either direction."""
    gh = _gh_tool("acme/widget", "deadbeef00001234567")
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t1", name="gh_commit_detail",
                                input={"slug": "acme/widget",
                                       "sha": "deadbeef00001234567"})],
            usage=_FakeUsage(),
        ),
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t2", name="submit_result",
                                input={"outcome": "rescued",
                                       "repository_url": "https://github.com/acme/widget",
                                       "fix_commit": "deadbeef0000",  # 12-char prefix
                                       "rationale": "fixed it"})],
            usage=_FakeUsage(),
        ),
    ]
    _patch_client(monkeypatch, responses)
    result = AgentLoop().run(_cfg(tools=(gh,)), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"


def test_verified_sha_gate_surrenders_after_three_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """After _MAX_UNVERIFIED_SUBMITS (=2) rejections + 1 more, the loop
    surrenders with reason=submit_unverified_sha. Prevents infinite loops
    when the agent keeps submitting phantom SHAs."""
    gh = _gh_tool("acme/widget", "real00000000")
    bad_submit = _FakeBlock(
        type="tool_use", id="ts", name="submit_result",
        input={"outcome": "rescued",
               "repository_url": "https://github.com/acme/widget",
               "fix_commit": "phantom00000",
               "rationale": "still wrong"},
    )
    responses = [
        # First verify so the gate has at least one verified pair.
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t1", name="gh_commit_detail",
                                input={"slug": "acme/widget", "sha": "real00000000"})],
            usage=_FakeUsage(),
        ),
        # 3 bad submits in a row → 3rd one trips the surrender.
        _FakeResp(content=[bad_submit], usage=_FakeUsage()),
        _FakeResp(content=[bad_submit], usage=_FakeUsage()),
        _FakeResp(content=[bad_submit], usage=_FakeUsage()),
    ]
    _patch_client(monkeypatch, responses)
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
    """Non-GitHub repository URLs aren't gated — gh_commit_detail only
    verifies github-hosted SHAs, and we don't want to block legitimate
    cgit / gitlab forge picks."""
    responses = [
        _FakeResp(
            content=[_FakeBlock(type="tool_use", id="t1", name="submit_result",
                                input={"outcome": "rescued",
                                       "repository_url": "https://gitlab.freedesktop.org/xkb/xkbcommon",
                                       "fix_commit": "deadbeef0000",
                                       "rationale": "non-github forge"})],
            usage=_FakeUsage(),
        ),
    ]
    _patch_client(monkeypatch, responses)
    result = AgentLoop().run(_cfg(), AgentContext(cve_id="CVE-X"))
    assert isinstance(result, AgentOutput)
    assert result.value == "deadbeef0000"

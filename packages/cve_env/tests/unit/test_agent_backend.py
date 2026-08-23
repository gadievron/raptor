"""Tests for the agent engine: the core ToolUseLoop-driven build.

(The file name keeps its historical spelling from the backend-A/B era;
the SDK engine and the selection seam are gone — build_core IS the
engine, called synchronously by the CLI.)
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch

import pytest

from core.llm.tool_use.types import (
    StopReason,
    TextBlock,
    ToolCall,
    TurnResponse,
)

from cve_env.agent.tools import ALL_TOOLS, TOOL_NAMES
from cve_env.models import CveRecord, HostInfo, Outcome

# ── tool conversion ───────────────────────────────────────────────────


def test_tool_defs_cover_the_full_belt() -> None:
    assert tuple(d.name for d in ALL_TOOLS) == TOOL_NAMES
    for d in ALL_TOOLS:
        assert d.description
        schema = d.input_schema
        assert schema["type"] == "object"
        for prop in schema["properties"].values():
            assert "type" in prop


def test_schema_types_and_optionals() -> None:
    defs = {d.name: d for d in ALL_TOOLS}
    gf = defs["github_fetch"].input_schema
    assert gf["properties"]["owner"]["type"] == "string"
    assert "GitHub org/user" in gf["properties"]["owner"]["description"]
    # 'ref' documents itself optional → not required.
    assert "ref" not in gf["required"]
    assert "owner" in gf["required"]


def test_handlers_are_sync_and_speak_json() -> None:
    defs = {d.name: d for d in ALL_TOOLS}
    text = defs["give_up"].handler({"reason": "no_image", "detail": "d"})
    payload = json.loads(text)
    assert payload == {"terminal": True, "reason": "no_image", "detail": "d"}


# ── core build loop ───────────────────────────────────────────────────


class _FakeProvider:
    def __init__(self, responses: list[TurnResponse]) -> None:
        self._responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    def supports_tool_use(self) -> bool:
        return True

    def supports_prompt_caching(self) -> bool:
        return True

    def supports_parallel_tools(self) -> bool:
        return True

    def supports_streaming(self) -> bool:
        return False

    def context_window(self) -> int:
        return 200_000

    def price_per_million(self) -> tuple[float, float]:
        return (3.0, 15.0)

    def estimate_tokens(self, text: str) -> int:
        return max(len(text) // 4, 1)

    def compute_cost(self, response: TurnResponse) -> float:
        return 0.01

    def turn(self, messages, tools, *, system, max_tokens, cache_control,
             **provider_specific) -> TurnResponse:
        self.calls.append({"messages": list(messages), "system": system})
        if not self._responses:
            raise RuntimeError("fake provider exhausted")
        return self._responses.pop(0)


def _cve() -> CveRecord:
    return CveRecord(cve_id="CVE-2018-7600", product="drupal",
                     version="8.5.0")


def _host() -> HostInfo:
    return HostInfo(arch="amd64")


def _run_core(responses: list[TurnResponse], tmp_path, tools=None) -> Outcome:
    from cve_env.agent.core_loop import build_core

    fake = _FakeProvider(responses)
    patches = [patch("cve_env.agent.core_loop._resolve_provider",
                     return_value=fake)]
    if tools is not None:
        patches.append(patch("cve_env.agent.tools.ALL_TOOLS", tools))
    with patches[0], patches[1] if len(patches) > 1 else patch(
            "cve_env.agent.core_loop.logger"):
        return build_core(_cve(), _host(), run_id="test-run",
                          audit_root=tmp_path, max_turns=10,
                          max_cost_usd=5.0)


def test_core_build_give_up_terminal(tmp_path) -> None:
    responses = [
        TurnResponse(
            content=[
                TextBlock(text="cannot reproduce"),
                ToolCall(id="t1", name="give_up",
                         input={"reason": "arch_incompatible",
                                "detail": "kernel CVE"}),
            ],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=100, output_tokens=50,
        ),
    ]
    out = _run_core(responses, tmp_path)
    assert out.status == "unresolvable"
    assert out.give_up_reason == "arch_incompatible"
    assert out.give_up_detail == "kernel CVE"
    assert "give_up" in out.tool_names_called
    assert out.total_cost_usd > 0
    # Audit JSONL landed under the run dir.
    audit = tmp_path / "test-run" / "CVE-2018-7600.jsonl"
    assert audit.is_file()
    rows = [json.loads(line) for line in audit.read_text().splitlines()]
    assert any(r.get("status") == "final_give_up" for r in rows)


def test_core_build_verify_pass_classifies_success_family(tmp_path) -> None:
    """A passing verify (with version assertion + smoke evidence) drives
    the shared classifier to the success family."""
    verify_payload = {
        "passed": True,
        "results": [
            {"type": "container_status", "passed": True, "details": {}},
            {"type": "exec_check", "passed": True,
             "details": {"command": "drush --version",
                         "expected_stdout_contains": "8.5.0"}},
            {"type": "http_check", "passed": True,
             "details": {"url": "/", "content_check_performed": True}},
        ],
    }
    from core.llm.tool_use.types import ToolDef

    tools = [
        ToolDef(name="verify", description="verify",
                input_schema={"type": "object", "properties": {},
                              "required": []},
                handler=lambda args: json.dumps(verify_payload)),
        ToolDef(name="give_up", description="terminal",
                input_schema={"type": "object", "properties": {},
                              "required": []},
                handler=lambda args: json.dumps({"terminal": True})),
    ]
    responses = [
        TurnResponse(
            content=[ToolCall(id="t1", name="verify", input={})],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=100, output_tokens=50,
        ),
        TurnResponse(
            content=[TextBlock(text="environment verified")],
            stop_reason=StopReason.COMPLETE,
            input_tokens=100, output_tokens=20,
        ),
    ]
    out = _run_core(responses, tmp_path, tools=tools)
    assert out.verify_passed is True
    assert out.status in ("success", "verified_partial")
    assert out.stop_reason == "end_turn"


def test_core_build_refused_maps_to_interrupted(tmp_path) -> None:
    responses = [
        TurnResponse(
            content=[TextBlock(text="I can't help with that")],
            stop_reason=StopReason.REFUSED,
            input_tokens=100, output_tokens=10,
        ),
    ]
    out = _run_core(responses, tmp_path)
    assert out.status == "interrupted"
    assert out.refusals >= 1


def test_core_build_max_iterations_maps_to_turn_cap(tmp_path) -> None:
    from core.llm.tool_use.types import ToolDef

    tools = [
        ToolDef(name="nvd_lookup", description="lookup",
                input_schema={"type": "object", "properties": {},
                              "required": []},
                handler=lambda args: json.dumps({"ok": True})),
        ToolDef(name="give_up", description="terminal",
                input_schema={"type": "object", "properties": {},
                              "required": []},
                handler=lambda args: json.dumps({"terminal": True})),
    ]

    def tool_turn(i: int) -> TurnResponse:
        return TurnResponse(
            content=[ToolCall(id=f"t{i}", name="nvd_lookup", input={})],
            stop_reason=StopReason.NEEDS_TOOL_CALL,
            input_tokens=100, output_tokens=20,
        )

    from cve_env.agent.core_loop import build_core

    fake = _FakeProvider([tool_turn(i) for i in range(10)])
    with patch("cve_env.agent.core_loop._resolve_provider",
               return_value=fake), \
         patch("cve_env.agent.tools.ALL_TOOLS", tools):
        out = build_core(_cve(), _host(), run_id="cap-run",
                         audit_root=tmp_path, max_turns=3, max_cost_usd=5.0)
    assert out.status == "turn_cap"
    assert out.stop_reason == "max_turns_reached"


def test_resolve_provider_self_serves_dispatcher_for_bedrock(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dispatcher-only family (Bedrock) must go through the shared
    standalone-entry gate before provider construction — a bench/CLI
    invocation is its own parent (the raptor-llm-ask precedent)."""
    from cve_env.agent import core_loop

    ensured: list[str] = []
    monkeypatch.delenv("RAPTOR_LLM_SOCKET", raising=False)
    monkeypatch.setattr(
        "core.llm.dispatcher.lifecycle.ensure_route_for_model_configs",
        lambda mcs, *, label: ensured.append(
            f"{mcs[0].provider}:{mcs[0].model_name}:{label}"),
    )
    with patch("cve_env.agent.core_loop.create_provider",
               return_value="prov") as mk:
        out = core_loop._resolve_provider("anthropic.claude-opus-4-1")
    assert out == "prov"
    (mc,), _ = mk.call_args
    assert mc.provider == "bedrock"
    assert ensured == [
        "bedrock:anthropic.claude-opus-4-1:cve-env-core-backend"]



def _costed_provider(responses, cost_per_turn: float):
    fake = _FakeProvider(responses)
    fake.compute_cost = lambda response: cost_per_turn  # type: ignore[method-assign]
    return fake


def _launch_tools():
    from core.llm.tool_use.types import ToolDef

    schema = {"type": "object", "properties": {}, "required": []}
    return [
        ToolDef(name="docker_run", description="launch", input_schema=schema,
                handler=lambda args: json.dumps({"ok": True})),
        ToolDef(name="verify", description="verify", input_schema=schema,
                handler=lambda args: json.dumps({"passed": True,
                                                 "results": []})),
        ToolDef(name="give_up", description="terminal", input_schema=schema,
                handler=lambda args: json.dumps({"terminal": True})),
    ]


def _tool_turn(i: int, name: str) -> TurnResponse:
    return TurnResponse(
        content=[ToolCall(id=f"t{i}", name=name, input={})],
        stop_reason=StopReason.NEEDS_TOOL_CALL,
        input_tokens=100, output_tokens=20,
    )


def test_core_cost_cap_extension_rescues_productive_run(
    tmp_path, monkeypatch,
) -> None:
    """Bench finding (Baron Samedit): a productive run that crosses the
    soft cost cap must earn ONE extension and finish, instead of dying
    budget_exhausted with verify already passed."""
    from cve_env.agent.core_loop import build_core

    monkeypatch.setattr("cve_env.agent.core_loop.MAX_COST_EXTENSIONS", 1)
    monkeypatch.setattr("cve_env.agent.core_loop.COST_EXTENSION_PCT", 0.5)
    # 3 turns × $0.45: crosses the $1.00 soft cap after turn 3 with a
    # productive docker_run just behind it → extension to $1.50 → the
    # verify + completion turns fit.
    responses = [
        _tool_turn(1, "docker_run"),
        _tool_turn(2, "docker_run"),
        _tool_turn(3, "verify"),
        TurnResponse(content=[TextBlock(text="done")],
                     stop_reason=StopReason.COMPLETE,
                     input_tokens=50, output_tokens=10),
    ]
    fake = _costed_provider(responses, cost_per_turn=0.45)
    with patch("cve_env.agent.core_loop._resolve_provider",
               return_value=fake), \
         patch("cve_env.agent.tools.ALL_TOOLS", _launch_tools()):
        out = build_core(_cve(), _host(), run_id="ext-run",
                         audit_root=tmp_path, max_turns=20,
                         max_cost_usd=1.0)
    assert out.verify_passed is True
    assert out.status in ("success", "verified_partial", "verify_failed")
    assert out.status not in ("budget_exhausted",)
    rows = [json.loads(line) for line in
            (tmp_path / "ext-run" / "CVE-2018-7600.jsonl")
            .read_text().splitlines()]
    assert any("cost-cap auto-extended" in str(r.get("reason", ""))
               for r in rows)


def test_core_cost_cap_stops_unproductive_run_as_budget(
    tmp_path, monkeypatch,
) -> None:
    """No productive progress → no extension: the soft cap stops the
    loop and classifies budget_exhausted (cap-overrides-verify parity
    with the SDK path)."""
    from core.llm.tool_use.types import ToolDef

    from cve_env.agent.core_loop import build_core

    monkeypatch.setattr("cve_env.agent.core_loop.MAX_COST_EXTENSIONS", 1)
    schema = {"type": "object", "properties": {}, "required": []}
    tools = [
        ToolDef(name="nvd_lookup", description="research",
                input_schema=schema,
                handler=lambda args: json.dumps({"ok": False})),
        ToolDef(name="give_up", description="terminal", input_schema=schema,
                handler=lambda args: json.dumps({"terminal": True})),
    ]
    responses = [_tool_turn(i, "nvd_lookup") for i in range(1, 8)]
    fake = _costed_provider(responses, cost_per_turn=0.6)
    with patch("cve_env.agent.core_loop._resolve_provider",
               return_value=fake), \
         patch("cve_env.agent.tools.ALL_TOOLS", tools):
        out = build_core(_cve(), _host(), run_id="stop-run",
                         audit_root=tmp_path, max_turns=20,
                         max_cost_usd=1.0)
    assert out.status == "budget_exhausted"
    assert out.stop_reason == "budget_exceeded"

"""The agent engine: the CVE build driven by ``core.llm``'s ToolUseLoop.

This replaced the vendored claude-agent-sdk engine after the backend
A/B (two rounds, ten CVEs, fully symmetric verdicts; the SDK path was
deleted, not kept as a fallback). Any configured provider — Anthropic
API, dispatcher-routed Bedrock, the claudecode OAuth fallback — runs
cve-env builds through the same provider-agnostic loop.

Shared machinery (see :mod:`cve_env.agent.loop`): the system-prompt
composer, the per-tool-result state tracker, and the terminal
classification (``_map_status`` over ``_StreamState``) — the shapes
the whole classifier test corpus pins. The tool belt
(:data:`cve_env.agent.tools.ALL_TOOLS`) is declared directly in the
loop's ToolDef shape.

What maps natively: budgets are the loop's ``max_iterations`` /
``max_cost_usd`` caps (plus the adaptive soft-cost-cap extension the
bench showed earns its keep), ``give_up`` is the loop's
``terminal_tool``, refusal terminations arrive as the typed
``refused`` stop reason (plus the shared RefusalScanner over assistant
text), and the 529-overload classifier wires exception/provider-error
paths to the re-runnable ``rate_limited`` status. The retired engine's
remaining adaptive machinery (turn-cap bumps, force-resolve /
proprietary-verify continuations, wall budget, anti-thrash) showed no
verdict impact on the bench and was not ported.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from core.llm.config import ModelConfig
from core.llm.providers import create_provider
from core.llm.tool_use.loop import ToolUseLoop
from core.llm.tool_use.types import (
    CacheControl,
    LoopEvent,
    TextBlock,
    ToolCallDispatched,
    ToolCallReturned,
    TurnCompleted,
)

from cve_env.agent.audit import AuditEntry, AuditWriter
from cve_env.agent.loop import (
    _classify_api_overload,
    _compose_system_prompt,
    _map_status,
    _process_tool_result_for_recovery,
    _StreamState,
    _terminal_status_for_result,
    _track_tool_result,
)
from cve_env.agent.prompts import render_user_prompt
from cve_env.agent.refusals import RefusalScanner
from cve_env.agent.tools import (
    reset_all_tool_state,
    set_cve_id_context,
    set_cve_version_context,
)
from cve_env.config import (
    AGENTIC_AUDIT_ROOT,
    COST_EXTENSION_PCT,
    MAX_COST_EXTENSIONS,
    MAX_COST_USD_PER_CVE_SOFT,
    MODEL,
    TURN_CAP,
    over_budget_stages,
    should_extend_cost_cap,
    stage_for_tool,
)
from cve_env.models import CveRecord, HostInfo, Outcome

logger = logging.getLogger(__name__)

# ToolUseLoop terminated_by → the SDK-vocabulary stop_reason strings the
# shared _map_status classifier keys on. "terminal_tool" maps to
# end_turn because the give_up verdict rides state.give_up_reason (set
# by the shared tracker), exactly like the SDK path.
_TERMINATED_TO_STOP_REASON: dict[str, str] = {
    "complete": "end_turn",
    "terminal_tool": "end_turn",
    "max_iterations": "max_turns_reached",
    "max_cost_usd": "budget_exceeded",
    "max_seconds": "budget_wall_exceeded",
    "max_total_tokens": "budget_tokens_exceeded",
    "max_tokens": "max_tokens",
    "refused": "refusal",
    "tool_error": "error_tool",
    "tool_timeout": "error_tool_timeout",
    "context_overflow": "error_context_overflow",
    "provider_error": "error_provider",
    "credit_exhausted": "error_credit_exhausted",
    "give_up": "end_turn",
}


def _resolve_provider(model: str):
    """Provider resolution mirroring the cve-diff convention: family →
    provider, dispatcher when RAPTOR_LLM_SOCKET is up, Claude Code
    OAuth fallback for Anthropic-family models without an API key.

    Dispatcher-only families (Bedrock) self-serve an in-process
    dispatcher via the shared standalone-entry gate — pipeline runs get
    theirs from the launcher, but a bench/CLI invocation is its own
    parent (the raptor-llm-ask precedent)."""
    from core.security.llm_family import provider_of

    provider_name = provider_of(model) or "anthropic"
    via_dispatcher = bool(os.environ.get("RAPTOR_LLM_SOCKET"))
    if (
        provider_name == "anthropic"
        and not via_dispatcher
        and not os.environ.get("ANTHROPIC_API_KEY")
    ):
        provider_name = "claudecode"
    mc = ModelConfig(provider=provider_name, model_name=model)
    try:
        from core.llm.dispatcher.lifecycle import (
            ensure_route_for_model_configs,
        )

        ensure_route_for_model_configs([mc], label="cve-env-core-backend")
    except Exception as exc:  # noqa: BLE001 — create_provider surfaces it
        logger.warning("could not self-serve the LLM dispatcher: %s", exc)
    return create_provider(mc)


def build_core(
    cve: CveRecord,
    host: HostInfo,
    *,
    run_id: str,
    audit_root: Path | None = None,
    model: str = MODEL,
    max_turns: int = TURN_CAP,
    max_cost_usd: float = MAX_COST_USD_PER_CVE_SOFT,
    constraints: list[Any] | None = None,
    max_turn_extensions: int | None = None,  # accepted; extensions are
    turn_extension_pct: float | None = None,  # not replicated in v1
) -> Outcome:
    """Drive one agent session for ``cve`` on the core backend.

    Same Outcome contract as :func:`cve_env.agent.loop.build`; every
    turn is audited to ``<audit_root>/<run_id>/<cve_id>.jsonl``.
    """
    del max_turn_extensions, turn_extension_pct
    reset_all_tool_state()
    set_cve_version_context(cve.version)
    set_cve_id_context(cve.cve_id)

    writer = AuditWriter(run_id=run_id, root=audit_root or AGENTIC_AUDIT_ROOT)
    audit_path = writer._path_for(cve_id=cve.cve_id)
    refusal_scanner = RefusalScanner(
        project="cve-env",
        cve_id=cve.cve_id,
        run_id=run_id,
        audit_path=audit_path,
        model=model,
        host_arch=host.arch,
    )

    state = _StreamState()
    state.effective_max_turns = max_turns
    state.effective_max_cost_usd = max_cost_usd
    # Soft-cap enforcement state for the adaptive cost extension: the
    # loop holds the extended CEILING; when the events callback decides
    # the soft cap is spent and no extension is earned, this flag makes
    # should_continue stop the loop before the next provider call.
    _budget_stop = {"flag": False}

    from cve_env.agent import tools as _tools_mod

    tools = list(_tools_mod.ALL_TOOLS)
    system_prompt = _compose_system_prompt(
        constraints,
        max_turns=max_turns,
        max_cost_usd=max_cost_usd,
        max_extensions=0,
        extension_pct=0.0,
    )
    user_prompt = render_user_prompt(cve, host, run_id=run_id)

    def _on_event(event: LoopEvent) -> None:
        if isinstance(event, ToolCallDispatched):
            state.turn += 1
            name = event.call.name
            state.tool_name_by_id[event.call.id] = name
            state.tool_input_by_id[event.call.id] = dict(event.call.input)
            state.tool_uses_seen.append({"name": name,
                                         "input": dict(event.call.input)})
            state.last_tool_stage = stage_for_tool(name)
            state.stage_calls[state.last_tool_stage] = (
                state.stage_calls.get(state.last_tool_stage, 0) + 1
            )
            writer.write(
                cve_id=cve.cve_id,
                entry=AuditEntry(
                    turn=state.turn,
                    status="llm_turn",
                    tool_name=name,
                    tool_input=dict(event.call.input),
                ),
            )
        elif isinstance(event, ToolCallReturned):
            state.turn += 1
            tool_name = state.tool_name_by_id.get(event.call_id, "")
            try:
                payload = json.loads(event.result.content)
            except (json.JSONDecodeError, TypeError):
                payload = None
            if isinstance(payload, dict):
                _track_tool_result(
                    state, tool_name, payload,
                    refusal_event_count=len(refusal_scanner.events),
                )
            tool_status = ("tool_error" if event.result.is_error
                           else "tool_ok")
            writer.write(
                cve_id=cve.cve_id,
                entry=AuditEntry(
                    turn=state.turn,
                    status=tool_status,
                    tool_name=tool_name,
                    tool_input=state.tool_input_by_id.get(event.call_id, {}),
                    tool_result=(payload if payload is not None
                                 else str(event.result.content)[:4000]),
                ),
            )
            # Recovery telemetry: a build-path tool succeeding shortly
            # after a same-tool failure emits a dedicated audit row so
            # post-run analysis counts recoveries without re-deriving
            # them from raw state.
            recovery = _process_tool_result_for_recovery(
                state,
                tool_name=tool_name,
                turn=state.turn,
                tool_status=tool_status,
                tool_result=(payload if payload is not None else None),
            )
            if recovery is not None:
                writer.write(cve_id=cve.cve_id, entry=recovery)
        elif isinstance(event, TurnCompleted):
            state.turn += 1
            # Stage cost attribution: the turn's cost credits the stage
            # of the most recent tool (OTHER before any tool call) —
            # the single-path equivalent of the SDK backend's
            # dual-path estimate.
            state.stage_costs[state.last_tool_stage] = (
                state.stage_costs.get(state.last_tool_stage, 0.0)
                + float(event.cost_usd or 0.0)
            )
            state.last_cost_usd += float(event.cost_usd or 0.0)
            # Adaptive cost-cap extension (the one SDK-engine adaptive
            # behavior the backend A/B showed earns its port: a long
            # source-build run crossed the soft cap AFTER verify had
            # already passed and was misclassified budget_exhausted).
            # The loop itself holds the extended CEILING; the SOFT cap
            # is enforced here — on overrun, grant a productive-
            # progress extension (shared policy fn) or flip the stop
            # flag that should_continue consumes.
            if (
                state.last_cost_usd > state.effective_max_cost_usd
                and not _budget_stop["flag"]
            ):
                new_cap = should_extend_cost_cap(
                    current_cost_usd=state.last_cost_usd,
                    max_cost_usd=state.effective_max_cost_usd,
                    last_productive_turn=state.last_productive_turn,
                    current_turn=state.turn,
                    cost_extension_count=state.cost_extension_count,
                )
                if new_cap is not None:
                    state.cost_extension_count += 1
                    state.effective_max_cost_usd = new_cap
                    writer.write(
                        cve_id=cve.cve_id,
                        entry=AuditEntry(
                            turn=state.turn,
                            status="llm_turn",
                            reason=(
                                f"cost-cap auto-extended to "
                                f"${new_cap:.2f} (extension "
                                f"#{state.cost_extension_count}/"
                                f"{MAX_COST_EXTENSIONS}; "
                                f"spent=${state.last_cost_usd:.2f})"
                            ),
                        ),
                    )
                else:
                    _budget_stop["flag"] = True
            for block in event.response.content:
                if isinstance(block, TextBlock) and block.text:
                    state.final_text = block.text
                    refusal_scanner.scan_text(
                        turn=state.turn, text=block.text, tool_call=None
                    )
                    refusal_scanner.observe({
                        "turn": state.turn,
                        "kind": "assistant_text",
                        "text": block.text[:600],
                    })
                    writer.write(
                        cve_id=cve.cve_id,
                        entry=AuditEntry(
                            turn=state.turn,
                            status="llm_turn",
                            llm_message={"text": block.text[:4000]},
                        ),
                    )

    try:
        provider = _resolve_provider(model)
    except Exception as exc:  # noqa: BLE001 — surface as a typed outcome
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(turn=0, status="tool_error",
                             reason=f"provider init failed: {exc}"),
        )
        return Outcome(
            cve_id=cve.cve_id,
            status="error",
            reason=f"provider init failed: {type(exc).__name__}: {exc}",
            audit_path=audit_path,
            error=str(exc)[:400],
        )

    # The loop gets the extended CEILING (the SDK path plays the same
    # trick with sdk_max_turns): the SOFT cap + extension policy are
    # enforced in the events callback, so the loop's own cap only fires
    # as a hard backstop past every possible extension.
    cost_ceiling = max_cost_usd
    if MAX_COST_EXTENSIONS > 0:
        cost_ceiling = max_cost_usd * (
            1.0 + COST_EXTENSION_PCT * MAX_COST_EXTENSIONS)
    loop = ToolUseLoop(
        provider=provider,
        tools=tools,
        system=system_prompt,
        terminal_tool="give_up",
        max_iterations=max_turns,
        max_cost_usd=cost_ceiling,
        cache_control=CacheControl(system=True, tools=True),
        events=_on_event,
        terminate_on_handler_error=False,
        max_tokens_per_turn=4096,
        should_continue=lambda: not _budget_stop["flag"],
    )

    try:
        result = loop.run(user_prompt)
    except Exception as exc:  # noqa: BLE001 — every failure is an Outcome
        stop_reason = f"error:{type(exc).__name__}"
        # Runtime api_overload wiring (parity with the retired SDK
        # engine): a 529/overload exception is an EXTERNAL outage, not a
        # CVE-merit failure — classify rate_limited so humans, cards,
        # and retry harnesses treat the run as re-runnable instead of
        # "this CVE can't be built".
        if _classify_api_overload(str(exc)) == "api_overload":
            state.give_up_reason = "api_overload"
            state.give_up_detail = (
                f"API 529 Overloaded exception: {type(exc).__name__}: "
                f"{str(exc)[:200]}"
            )
            status, reason = "rate_limited", state.give_up_detail
        else:
            status, reason = _map_status(stop_reason, state)
        writer.write(
            cve_id=cve.cve_id,
            entry=AuditEntry(
                turn=state.turn,
                status=_terminal_status_for_result(state, stop_reason.lower()),
                reason=f"{type(exc).__name__}: {exc}"[:400],
            ),
        )
        return Outcome(
            cve_id=cve.cve_id,
            status=status,
            reason=f"{reason} ({type(exc).__name__}: {exc})",
            num_turns=state.turn,
            total_cost_usd=state.last_cost_usd,
            verify_passed=state.verify_passed,
            verify_result=state.last_verify_result,
            give_up_reason=state.give_up_reason,
            give_up_detail=state.give_up_detail,
            final_text=state.final_text,
            tool_names_called=[u.get("name", "") for u in state.tool_uses_seen],
            audit_path=audit_path,
            error=str(exc)[:400],
            refusals=len(refusal_scanner.events),
            daemon_corruption=state.daemon_corruption_seen,
            stage_costs=dict(state.stage_costs),
            stage_calls=dict(state.stage_calls),
            over_budget_stages_list=over_budget_stages(state.stage_costs),
        )

    # A refused termination is the typed equivalent of the SDK's
    # refusal-class ResultMessage — latch it for the classifier.
    if result.terminated_by == "refused":
        state.refusal_stop_reason_seen = True
        state.refusal_stop_reason_turn = state.turn
    state.result_received = True
    total_cost = max(state.last_cost_usd, result.total_cost_usd)
    state.last_cost_usd = total_cost
    state.total_input_tokens = result.total_input_tokens
    state.total_output_tokens = result.total_output_tokens
    if result.final_text:
        state.final_text = result.final_text

    stop_reason = _TERMINATED_TO_STOP_REASON.get(
        result.terminated_by, f"error:{result.terminated_by}"
    )
    # A should_continue stop reads as "give_up" to the loop; when it was
    # the soft-cost-cap enforcement that flipped the flag, the honest
    # stop reason is the budget one (cap-overrides-verify, same as the
    # SDK path).
    if _budget_stop["flag"] and result.terminated_by == "give_up":
        stop_reason = "budget_exceeded"
    if (
        result.terminated_by == "provider_error"
        and _classify_api_overload(state.final_text or "") == "api_overload"
    ):
        # Same external-outage wiring for the non-raising provider-error
        # termination: rate_limited = re-runnable.
        state.give_up_reason = "api_overload"
        state.give_up_detail = state.final_text[:200]
        status, reason = "rate_limited", state.give_up_detail
    else:
        status, reason = _map_status(stop_reason, state)
    outcome = Outcome(
        cve_id=cve.cve_id,
        status=status,
        reason=reason,
        num_turns=result.iterations,
        total_cost_usd=total_cost,
        stop_reason=stop_reason,
        verify_passed=state.verify_passed,
        verify_result=state.last_verify_result,
        give_up_reason=state.give_up_reason,
        give_up_detail=state.give_up_detail,
        final_text=state.final_text,
        tool_names_called=[u.get("name", "") for u in state.tool_uses_seen],
        audit_path=audit_path,
        refusals=(len(refusal_scanner.events)
                  + int(state.refusal_stop_reason_seen)),
        daemon_corruption=state.daemon_corruption_seen,
        stage_costs=dict(state.stage_costs),
        stage_calls=dict(state.stage_calls),
        over_budget_stages_list=over_budget_stages(state.stage_costs),
    )
    writer.write(
        cve_id=cve.cve_id,
        entry=AuditEntry(
            turn=state.turn,
            status=_terminal_status_for_result(state, stop_reason.lower()),
            reason=f"{status}: {reason}"[:400],
        ),
    )
    return outcome

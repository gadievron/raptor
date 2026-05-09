"""Default LLM dispatch for /understand --trace.

Implements ``TraceDispatchFn`` — runs one ToolUseLoop per model with the
sandboxed Read/Grep/Glob tools plus a terminal ``submit_verdicts`` tool.
The model receives a batch of pre-built traces and must return one
verdict per trace.

Signature: ``default_trace_dispatch(model, traces) -> List[Dict]``
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Callable, Dict, List, Optional

from core.llm.config import ModelConfig
from core.llm.providers import create_provider
from core.llm.tool_use import (
    CacheControl,
    ContextPolicy,
    CostBudgetExceeded,
    ToolDef,
    ToolUseLoop,
)

from packages.code_understanding.dispatch._tool_specs import build_shared_tools
from packages.code_understanding.dispatch.hunt_dispatch import _make_event_callback
from packages.code_understanding.dispatch.tools import SandboxedTools
from packages.code_understanding.prompts import TRACE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


DEFAULT_MAX_COST_USD = 1.50
DEFAULT_MAX_ITERATIONS = 30
DEFAULT_TOOL_TIMEOUT_S = 30.0
DEFAULT_MAX_SECONDS = 600.0


def default_trace_dispatch(
    model: ModelConfig,
    traces: List[Dict[str, Any]],
    repo_path: str,
    *,
    max_cost_usd: float = DEFAULT_MAX_COST_USD,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    tool_timeout_s: float = DEFAULT_TOOL_TIMEOUT_S,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    cost_collector: Optional[Callable[[float], None]] = None,
    verbose_logger: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Run one model's trace verdict pass.

    Signature: ``(model, traces, repo_path) -> List[Dict]`` — matches
    the ``TraceDispatchFn`` protocol from ``packages.code_understanding.trace``.

    Errors during dispatch are returned as a single-element list with
    an "error" key so the substrate filters them.

    Direct callers (not via the ``trace()`` orchestrator) get the same
    input validation that the orchestrator applies.
    """
    if not isinstance(traces, list) or not traces:
        return [{"error": "traces must be a non-empty list"}]
    # Validate per-trace shape upstream of LLM dispatch. A trace without
    # a string trace_id would let the LLM return verdicts the substrate
    # adapter then crashes on (item_id requires non-empty str).
    for i, t in enumerate(traces):
        if not isinstance(t, dict):
            return [{"error": f"traces[{i}] must be a dict"}]
        tid = t.get("trace_id")
        if not isinstance(tid, str) or not tid.strip():
            return [{
                "error": f"traces[{i}].trace_id must be a non-empty string",
            }]

    try:
        sandbox = SandboxedTools.for_repo(repo_path)
    except (FileNotFoundError, ValueError) as e:
        return [{"error": f"invalid repo_path: {e}"}]
    tools = _build_tools(sandbox)

    try:
        provider = create_provider(model)
    except Exception as e:  # noqa: BLE001 - any provider construction failure
        logger.warning(
            f"trace: model {model.model_name} provider creation failed: {e}",
            exc_info=True,
        )
        return [{"error": f"provider construction failed: {type(e).__name__}: {e}"}]
    try:
        user_message = _format_user_message(traces)
    except (TypeError, ValueError) as e:
        # Non-JSON-native values in traces (Path, datetime, etc.) reach
        # json.dumps and raise. Surface clearly rather than letting the
        # substrate catch a confusing TypeError from deep in dispatch.
        return [{"error": f"could not serialize traces: {e}"}]

    events = _make_event_callback(model.model_name, "trace", verbose_logger)

    loop = ToolUseLoop(
        provider=provider,
        tools=tools,
        system=TRACE_SYSTEM_PROMPT,
        terminal_tool="submit_verdicts",
        max_iterations=max_iterations,
        max_cost_usd=max_cost_usd,
        max_seconds=max_seconds,
        tool_timeout_s=tool_timeout_s,
        context_policy=ContextPolicy.RAISE,
        cache_control=CacheControl(system=True, tools=True),
        terminate_on_handler_error=False,
        events=events,
    )

    try:
        result = loop.run(user_message)
    except CostBudgetExceeded as e:
        logger.warning(f"trace: model {model.model_name} hit cost cap: {e}")
        if cost_collector is not None:
            cost_collector(max_cost_usd)
        return [{"error": f"cost budget exceeded: {e}"}]
    except Exception as e:  # noqa: BLE001 - dispatch boundary
        logger.warning(
            f"trace: model {model.model_name} loop failed: {e}",
            exc_info=True,
        )
        return [{"error": f"{type(e).__name__}: {e}"}]

    if cost_collector is not None:
        cost_collector(float(result.total_cost_usd or 0.0))

    if result.terminated_by != "terminal_tool":
        return [{
            "error": f"loop terminated without submit_verdicts: "
                     f"{result.terminated_by}",
        }]

    payload = result.terminal_tool_input or {}
    raw_verdicts = payload.get("verdicts")
    if not isinstance(raw_verdicts, list):
        return [{"error": "submit_verdicts payload missing 'verdicts' list"}]

    # Filter at dispatch boundary. CRITICAL: a verdict without trace_id
    # would crash TraceAdapter.item_id (and via _check_unique_ids, the
    # entire substrate run including OTHER models' valid results). Drop
    # malformed verdicts here so one buggy model can't break the run.
    valid: List[Dict[str, Any]] = []
    dropped = 0
    for v in raw_verdicts:
        if not isinstance(v, dict):
            dropped += 1
            continue
        tid = v.get("trace_id")
        if not isinstance(tid, str) or not tid.strip():
            dropped += 1
            continue
        valid.append(v)
    if dropped:
        logger.info(
            f"trace: model {model.model_name} returned {dropped} malformed "
            f"verdict(s) (missing/invalid trace_id) — filtered"
        )
    return valid


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


def _build_tools(sandbox: SandboxedTools) -> List[ToolDef]:
    """Trace's tool surface: shared Read/Grep/Glob plus submit_verdicts.

    The shared tools are identical to hunt's, so model behaviour on
    file inspection is consistent between modes.
    """
    return [
        *build_shared_tools(sandbox),
        ToolDef(
            name="submit_verdicts",
            description=(
                "TERMINAL — call this exactly once with one verdict per "
                "input trace. The loop terminates when this is called."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "verdicts": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "trace_id": {"type": "string"},
                                "verdict": {
                                    "type": "string",
                                    "enum": ["reachable", "not_reachable", "uncertain"],
                                },
                                "confidence": {
                                    "type": "string",
                                    "enum": ["high", "medium", "low"],
                                },
                                "reasoning": {"type": "string"},
                                "steps": {
                                    "type": "array",
                                    "items": {"type": "string"},
                                },
                            },
                            "required": ["trace_id", "verdict"],
                        },
                    },
                },
                "required": ["verdicts"],
            },
            handler=lambda args: json.dumps({"received": True}),
        ),
    ]


# ---------------------------------------------------------------------------
# User message
# ---------------------------------------------------------------------------


_CWE_RE = re.compile(r'\bCWE-(\d{1,5})\b', re.IGNORECASE)


def _format_user_message(traces: List[Dict[str, Any]]) -> str:
    """Build the initial user message with the trace batch.

    Traces are JSON-serialized inside delimiters so that any prompt
    injection in trace fields (entry-point names sourced from external
    docs, etc.) doesn't blend with operator instructions. The model is
    told upstream (system prompt) to treat content as data.

    When the traces' CWE ids or function/entry/sink vocabulary maps to
    a known cwe_strategies bug class, the operator-curated strategy
    block is appended *after* the closing ``</traces>`` tag so the
    model treats the lenses as trusted operator guidance.
    """
    base = (
        "Assess each of the following traces for reachability. Use the "
        "available tools to read code, walk call chains, and confirm "
        "or refute each path. Submit one verdict per trace via "
        "submit_verdicts.\n\n"
        "<traces>\n"
        f"{json.dumps(traces, indent=2)}\n"
        "</traces>"
    )
    strategy_block = _build_strategy_block(traces)
    if strategy_block:
        base += "\n\n" + strategy_block
    return base


def _build_strategy_block(traces: List[Dict[str, Any]]) -> str:
    """Render bug-class lenses for the trace batch, or empty if none.

    Trace dicts have an open schema (``trace_id`` is the only required
    field; everything else is producer-defined). Rather than hard-code
    field names like ``cwe`` / ``rule_id`` that may or may not be
    present, this serialises the whole trace list and:

      * Regex-scans the serialised text for ``CWE-NNN`` ids → fed as
        ``candidate_cwes`` to the picker (100pt pin per match).
      * Passes the same serialised text as ``function_name`` so the
        picker's keyword tokeniser matches function/entry/sink names
        anywhere in the trace dicts (``mutex_lock`` →
        ``concurrency``, ``parse`` → ``input_handling``, etc.) even
        when no CWE id is present.

    Failures (substrate ImportError, JSON serialisation failure on
    trace dicts containing non-JSON values, picker exception, render
    exception) return ``""`` — the trace verdict pass continues with
    the base user message unchanged. We never block the loop on
    strategy lookup.
    """
    try:
        from core.llm.cwe_strategies import pick_strategies, render_strategies
    except Exception:
        return ""

    try:
        signal_text = json.dumps(traces, default=str)
    except Exception:
        return ""

    candidate_cwes = tuple(
        f"CWE-{m.group(1)}" for m in _CWE_RE.finditer(signal_text)
    )
    try:
        picked = pick_strategies(
            file_path="",
            function_name=signal_text,
            candidate_cwes=candidate_cwes,
            max_strategies=3,
        )
        if not picked:
            return ""
        rendered = render_strategies(picked)
    except Exception:
        return ""

    return (
        "## Bug-class lenses for these traces\n\n"
        "These bug-class strategies are operator-curated and apply to "
        "the traces above. Use them as decision lenses while assessing "
        "reachability — each strategy lists the canonical primitives, "
        "key questions, and CVE exemplars for the bug class.\n\n"
        + rendered
    )

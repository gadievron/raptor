"""Default LLM dispatch for /understand --hunt.

Implements ``HuntDispatchFn`` — runs one ToolUseLoop per model with the
sandboxed Read/Grep/Glob tools plus a terminal ``submit_variants`` tool.
The model is expected to enumerate variants of a given pattern across
the target codebase, then call ``submit_variants`` exactly once.

Signature: ``default_hunt_dispatch(model, pattern, repo_path) -> List[Dict]``

This is a free function rather than a method so it satisfies the
``HuntDispatchFn`` Protocol from packages.code_understanding.hunt
without any wrapping.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, List, Optional

from core.llm.config import ModelConfig
from core.llm.providers import create_provider
from core.llm.tool_use import (
    CacheControl,
    ContextPolicy,
    CostBudgetExceeded,
    ToolCall,
    ToolDef,
    ToolUseLoop,
    TurnCompleted,
)

from packages.code_understanding.dispatch._tool_specs import build_shared_tools
from packages.code_understanding.dispatch.tools import SandboxedTools
from packages.code_understanding.prompts import HUNT_SYSTEM_PROMPT

logger = logging.getLogger(__name__)


# Per-model budget for one hunt run. Overall budget across N models is
# enforced by the substrate's CostGate; this is a per-task safety net.
DEFAULT_MAX_COST_USD = 1.50
DEFAULT_MAX_ITERATIONS = 30
DEFAULT_TOOL_TIMEOUT_S = 30.0
# Wall-clock limit per model. Hunt typically takes seconds; this is a
# safety net against a model getting stuck in a slow grep iteration.
DEFAULT_MAX_SECONDS = 600.0


def default_hunt_dispatch(
    model: ModelConfig,
    pattern: str,
    repo_path: str,
    *,
    max_cost_usd: float = DEFAULT_MAX_COST_USD,
    max_iterations: int = DEFAULT_MAX_ITERATIONS,
    tool_timeout_s: float = DEFAULT_TOOL_TIMEOUT_S,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    cost_collector: Optional[Callable[[float], None]] = None,
    verbose_logger: Optional[Callable[[str], None]] = None,
) -> List[Dict[str, Any]]:
    """Run one model's variant hunt and return the variant list.

    Errors during dispatch are returned as a single-element list with
    an "error" key so the substrate filters them and ``failed_models``
    captures the model name. The substrate convention (see
    ``core.llm.multi_model.dispatch._is_error``) is to treat any
    top-level ``"error"`` key as an error entry.

    Direct callers (not via the ``hunt()`` orchestrator) get the same
    input validation that the orchestrator applies — non-empty pattern,
    callable model, etc.
    """
    if not isinstance(pattern, str) or not pattern.strip():
        return [{"error": "pattern must be a non-empty string"}]
    # Strip after validation so user_message gets the canonical form,
    # matching what the orchestrator does (and what dispatch_fn writers
    # expect — leading/trailing whitespace shouldn't influence the model).
    pattern = pattern.strip()

    try:
        sandbox = SandboxedTools.for_repo(repo_path)
    except (FileNotFoundError, ValueError) as e:
        return [{"error": f"invalid repo_path: {e}"}]
    tools = _build_tools(sandbox)

    try:
        provider = create_provider(model)
    except Exception as e:  # noqa: BLE001 - any provider construction failure
        logger.warning(
            f"hunt: model {model.model_name} provider creation failed: {e}",
            exc_info=True,
        )
        return [{"error": f"provider construction failed: {type(e).__name__}: {e}"}]
    user_message = _format_user_message(pattern)

    events = _make_event_callback(model.model_name, "hunt", verbose_logger)

    loop = ToolUseLoop(
        provider=provider,
        tools=tools,
        system=HUNT_SYSTEM_PROMPT,
        terminal_tool="submit_variants",
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
        logger.warning(f"hunt: model {model.model_name} hit cost cap: {e}")
        if cost_collector is not None:
            cost_collector(max_cost_usd)  # we hit the cap
        return [{"error": f"cost budget exceeded: {e}"}]
    except Exception as e:  # noqa: BLE001 - dispatch boundary
        logger.warning(
            f"hunt: model {model.model_name} loop failed: {e}",
            exc_info=True,
        )
        return [{"error": f"{type(e).__name__}: {e}"}]

    if cost_collector is not None:
        cost_collector(float(result.total_cost_usd or 0.0))

    if result.terminated_by != "terminal_tool":
        # Loop ended without the model submitting variants.
        # Treat as failure for the substrate.
        return [{
            "error": f"loop terminated without submit_variants: "
                     f"{result.terminated_by}",
        }]

    payload = result.terminal_tool_input or {}
    raw_variants = payload.get("variants")
    if not isinstance(raw_variants, list):
        return [{"error": "submit_variants payload missing 'variants' list"}]

    # Filter at dispatch boundary. The schema marks file+line as required,
    # but providers vary in how strictly they enforce schemas — defensive
    # check ensures a malformed variant doesn't slip past and pollute the
    # substrate's correlation with phantom items.
    valid: List[Dict[str, Any]] = []
    dropped = 0
    for v in raw_variants:
        if not isinstance(v, dict):
            dropped += 1
            continue
        file_v = v.get("file")
        if not isinstance(file_v, str) or not file_v.strip():
            dropped += 1
            continue
        if "line" not in v or v["line"] is None:
            dropped += 1
            continue
        valid.append(v)
    if dropped:
        logger.info(
            f"hunt: model {model.model_name} returned {dropped} malformed "
            f"variant(s) (missing/invalid file or line) — filtered"
        )
    return valid


# ---------------------------------------------------------------------------
# Event callback for verbose logging
# ---------------------------------------------------------------------------


def _make_event_callback(
    model_name: str, mode: str, verbose_logger: Optional[Callable[[str], None]],
):
    """Build a LoopEvent callback for verbose tracing.

    When verbose_logger is None, returns None (substrate skips events).
    When provided, returns a callback that emits one line per turn:
    tool calls, tool results, and final text. Lines go through the
    consumer-supplied logger, which is typically print(file=sys.stderr).
    """
    if verbose_logger is None:
        return None

    def _on_event(event):
        # Only log the high-signal events. Skip low-signal ones (TurnStarted,
        # ToolCallReturned which would double-log).
        if isinstance(event, TurnCompleted):
            for blk in event.response.content:
                if isinstance(blk, ToolCall):
                    verbose_logger(
                        f"[{mode}/{model_name}] tool: {blk.name}"
                        f"({_short_args(blk.input)})"
                    )
                elif hasattr(blk, "text") and blk.text.strip():
                    snippet = blk.text.strip()[:120].replace("\n", " ")
                    verbose_logger(f"[{mode}/{model_name}] text: {snippet}")
    return _on_event


def _short_args(args: Dict[str, Any], max_len: int = 80) -> str:
    """One-line args summary for verbose logging."""
    parts = []
    for k, v in args.items():
        s = repr(v) if not isinstance(v, str) else f"'{v}'"
        if len(s) > 30:
            s = s[:27] + "..."
        parts.append(f"{k}={s}")
    line = ", ".join(parts)
    return line if len(line) <= max_len else line[:max_len - 3] + "..."


# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------


def _build_tools(sandbox: SandboxedTools) -> List[ToolDef]:
    """Hunt's tool surface: shared Read/Grep/Glob plus submit_variants.

    The shared tools come from ``_tool_specs.build_shared_tools`` so
    both hunt and trace dispatchers expose identical descriptions and
    schemas to the model — only the terminal tool differs.
    """
    return [
        *build_shared_tools(sandbox),
        ToolDef(
            name="submit_variants",
            description=(
                "TERMINAL — call this exactly once with the full list of "
                "variants you found. The loop terminates when this is "
                "called. Submit an empty list if you found nothing."
            ),
            input_schema={
                "type": "object",
                "properties": {
                    "variants": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "file": {"type": "string"},
                                "line": {"type": "integer"},
                                "function": {"type": "string"},
                                "snippet": {"type": "string"},
                                "confidence": {
                                    "type": "string",
                                    "enum": ["high", "medium", "low"],
                                },
                            },
                            "required": ["file", "line"],
                        },
                    },
                },
                "required": ["variants"],
            },
            # Handler returns success — actual variant collection happens
            # via terminal_tool_input on the loop result. This handler
            # is just the "ack" the loop dispatches before terminating.
            handler=lambda args: json.dumps({"received": True}),
        ),
    ]


# ---------------------------------------------------------------------------
# User message
# ---------------------------------------------------------------------------


def _format_user_message(pattern: str) -> str:
    """Build the initial user message with the pattern description.

    Pattern is wrapped in clear delimiters so prompt-injection attempts
    in the pattern text don't blend with the operator's instructions.
    """
    return (
        "Hunt the target codebase for variants of the following pattern. "
        "Use the available tools to enumerate the codebase, then call "
        "submit_variants with the full list.\n\n"
        "<pattern>\n"
        f"{pattern}\n"
        "</pattern>"
    )

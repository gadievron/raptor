"""Tool-use wire-shape types + multi-turn loop runner for ``core.llm``.

This package owns the wire-shape types (``Message`` / ``ToolDef`` /
``ToolCall`` / ``ToolResult`` / ``TurnResponse`` / ...) and the loop
runner (``ToolUseLoop``) that turns those types into multi-turn
agentic behaviour. Tool-use *implementations* live on the existing
:class:`core.llm.providers.LLMProvider` subclasses
(``AnthropicProvider.turn``, ``OpenAICompatibleProvider.turn``) — one
provider per backend, two ways to use it (single-shot ``generate()``
or multi-turn ``turn()``).

Pre-2026-05-03 a parallel ``ToolUseProvider`` Protocol +
``AnthropicToolUseProvider`` shipped in this package. Both have been
retired in favour of the unified ``LLMProvider`` API — there's now
no duplicate Anthropic SDK wiring across two class hierarchies.
"""

from .loop import ToolUseLoop
from .types import (
    CacheControl,
    ContextOverflow,
    ContextPolicy,
    CostBudgetExceeded,
    LoopEvent,
    LoopTerminated,
    Message,
    StopReason,
    TextBlock,
    ToolCall,
    ToolCallBlocked,
    ToolCallDispatched,
    ToolCallReturned,
    ToolDef,
    ToolHandlerTimeout,
    ToolLoopResult,
    ToolResult,
    TurnCompleted,
    TurnResponse,
    TurnStarted,
)

__all__ = [
    "CacheControl",
    "ContextOverflow",
    "ContextPolicy",
    "CostBudgetExceeded",
    "LoopEvent",
    "LoopTerminated",
    "Message",
    "StopReason",
    "TextBlock",
    "ToolCall",
    "ToolCallBlocked",
    "ToolCallDispatched",
    "ToolCallReturned",
    "ToolDef",
    "ToolHandlerTimeout",
    "ToolLoopResult",
    "ToolResult",
    "ToolUseLoop",
    "TurnCompleted",
    "TurnResponse",
    "TurnStarted",
]

"""Provider-agnostic tool-use loop substrate for ``core.llm``.

This package owns the wire-shape types and the loop runner that turns
those types into multi-turn agentic behaviour. Provider implementations
(``AnthropicToolUseProvider``, etc.) are sibling modules that translate
their native API onto these types and back.

Phase 1 ships types-only + the loop + an Anthropic provider. Multi-
provider support (OpenAI, Gemini, Ollama) follows in their own PRs as
each provider's :meth:`ToolUseProvider.turn` lands.
"""

from .loop import ToolUseLoop
from .providers import ToolUseProvider
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
    "ToolCallDispatched",
    "ToolCallReturned",
    "ToolDef",
    "ToolHandlerTimeout",
    "ToolLoopResult",
    "ToolResult",
    "ToolUseLoop",
    "ToolUseProvider",
    "TurnCompleted",
    "TurnResponse",
    "TurnStarted",
]

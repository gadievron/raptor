"""Code-understanding multi-model consumers (substrate of core.llm.multi_model).

Public API:
    hunt              — orchestrator for --hunt mode (set-style)
    trace             — orchestrator for --trace mode (verdict-style)
    VariantAdapter    — substrate adapter for hunt's set shape
    TraceAdapter      — substrate adapter for trace's verdict shape

PR2a: this package contains adapters + orchestrators only. The actual
LLM dispatch (prompts, tool-use loop wiring, libexec entry points)
lands in PR2b.
"""

from packages.code_understanding.adapters import TraceAdapter, VariantAdapter
from packages.code_understanding.hunt import HuntDispatchFn, hunt
from packages.code_understanding.trace import TraceDispatchFn, trace

__all__ = [
    "HuntDispatchFn",
    "TraceAdapter",
    "TraceDispatchFn",
    "VariantAdapter",
    "hunt",
    "trace",
]

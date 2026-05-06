"""Default LLM dispatch implementations for hunt and trace.

Public API:
    default_hunt_dispatch     — HuntDispatchFn using core.llm.tool_use
    default_trace_dispatch    — TraceDispatchFn using core.llm.tool_use

Internal:
    tools.py        — Read/Grep/Glob handlers, sandboxed to repo_path
"""

from packages.code_understanding.dispatch.hunt_dispatch import default_hunt_dispatch
from packages.code_understanding.dispatch.trace_dispatch import default_trace_dispatch

__all__ = [
    "default_hunt_dispatch",
    "default_trace_dispatch",
]

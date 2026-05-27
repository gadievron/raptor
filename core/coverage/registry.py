"""Tool registry: classify coverage tool labels by category and depth.

Coverage is keyed by tool label (e.g. ``semgrep``, ``claude:audit``,
``gcov:campaign-1``). The label's *base* (before ``:``) maps to a
category (static / llm / runtime) and a depth on the
scanned -> analysed -> dataflow-traced -> runtime-tested ladder.

The category is what consumers query on -- ``gaps(category="llm")`` =
"what has no LLM examined yet, regardless of scanner coverage". Depth is
a finer signal kept for later prioritisation; it does not gate gaps().

Unknown tools fall back to ``unknown`` / ``scanned`` -- the most
conservative depth -- so a new producer is never silently credited as
deep coverage. The mapping is intentionally small and easy to extend.
"""

from __future__ import annotations

from typing import Tuple

CATEGORY_STATIC = "static"
CATEGORY_LLM = "llm"
CATEGORY_RUNTIME = "runtime"
CATEGORY_UNKNOWN = "unknown"

# Depth ladder, shallow -> deep.
DEPTH_SCANNED = "scanned"
DEPTH_ANALYSED = "analysed"
DEPTH_DATAFLOW = "dataflow-traced"
DEPTH_RUNTIME = "runtime-tested"

# base tool -> (category, depth)
_REGISTRY = {
    "semgrep": (CATEGORY_STATIC, DEPTH_SCANNED),
    "coccinelle": (CATEGORY_STATIC, DEPTH_SCANNED),
    "codeql": (CATEGORY_STATIC, DEPTH_SCANNED),
    "claude": (CATEGORY_LLM, DEPTH_ANALYSED),
    "llm": (CATEGORY_LLM, DEPTH_ANALYSED),
    "understand": (CATEGORY_LLM, DEPTH_ANALYSED),
    "audit": (CATEGORY_LLM, DEPTH_ANALYSED),
    # checked_by source_labels are command:stage (all LLM-driven; scanners
    # use the file-level coverage records, not checked_by).
    "validate": (CATEGORY_LLM, DEPTH_ANALYSED),
    "agentic": (CATEGORY_LLM, DEPTH_ANALYSED),
    "annotations": (CATEGORY_LLM, DEPTH_ANALYSED),
    "gcov": (CATEGORY_RUNTIME, DEPTH_RUNTIME),
    "afl": (CATEGORY_RUNTIME, DEPTH_RUNTIME),
    "fuzz": (CATEGORY_RUNTIME, DEPTH_RUNTIME),
}
_DEFAULT: Tuple[str, str] = (CATEGORY_UNKNOWN, DEPTH_SCANNED)


def _base(tool_label: str) -> str:
    return tool_label.split(":", 1)[0]


def classify(tool_label: str) -> Tuple[str, str]:
    """Return ``(category, depth)`` for a tool label."""
    return _REGISTRY.get(_base(tool_label), _DEFAULT)


def category_of(tool_label: str) -> str:
    return classify(tool_label)[0]


def depth_of(tool_label: str) -> str:
    return classify(tool_label)[1]

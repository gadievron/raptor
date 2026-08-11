"""Safe environment and resource limits for audit tool execution.

Enforces resource limits, output size caps, filesystem isolation,
and network denial for every external tool invocation in the audit
pipeline.  Complements sandbox_policy.py (which maps tools to profiles)
with the runtime enforcement details.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResourceLimits:
    """Per-invocation resource limits for an external tool."""

    timeout_seconds: int
    memory_limit_mb: int
    network_deny: bool = True
    fs_read_only: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeout_seconds": self.timeout_seconds,
            "memory_limit_mb": self.memory_limit_mb,
            "network_deny": self.network_deny,
            "fs_read_only": self.fs_read_only,
        }


def _build_limits_from_policy() -> Dict[str, ResourceLimits]:
    """Derive resource limits from sandbox_policy (single source of truth)."""
    from .sandbox_policy import all_policies
    limits: Dict[str, ResourceLimits] = {}
    for policy in all_policies():
        if policy.timeout_seconds or policy.memory_limit_mb:
            limits[policy.tool] = ResourceLimits(
                timeout_seconds=policy.timeout_seconds,
                memory_limit_mb=policy.memory_limit_mb,
                network_deny=policy.network_deny,
                fs_read_only=policy.fs_read_only,
            )
    return limits


_TOOL_LIMITS: Optional[Dict[str, ResourceLimits]] = None


def get_resource_limits(tool: str) -> Optional[ResourceLimits]:
    global _TOOL_LIMITS
    if _TOOL_LIMITS is None:
        _TOOL_LIMITS = _build_limits_from_policy()
    return _TOOL_LIMITS.get(tool.lower())


@dataclass(frozen=True)
class OutputSizeLimit:
    """Maximum result count or line count for tool outputs fed into prompts."""

    tool: str
    max_results: int
    description: str


_OUTPUT_LIMITS: Dict[str, OutputSizeLimit] = {
    "joern_query": OutputSizeLimit(
        tool="joern_query", max_results=100,
        description="Joern query results",
    ),
    "strings": OutputSizeLimit(
        tool="strings", max_results=10000,
        description="extracted strings",
    ),
    "symbols": OutputSizeLimit(
        tool="symbols", max_results=50000,
        description="symbol table entries",
    ),
    "decompile": OutputSizeLimit(
        tool="decompile", max_results=10000,
        description="decompiled code lines per function",
    ),
}


def get_output_limit(tool: str) -> Optional[OutputSizeLimit]:
    return _OUTPUT_LIMITS.get(tool.lower())


def truncate_output(
    items: List[Any],
    tool: str,
) -> tuple:
    """Truncate tool output to the configured limit.

    Returns (truncated_items, truncation_note_or_None).
    """
    limit = get_output_limit(tool)
    if limit is None or len(items) <= limit.max_results:
        return items, None

    truncated = items[:limit.max_results]
    note = (
        f"{limit.max_results} of {len(items)} "
        f"{limit.description} shown"
    )
    return truncated, note


def format_limits_summary() -> str:
    """Human-readable summary of configured resource limits."""
    global _TOOL_LIMITS
    if _TOOL_LIMITS is None:
        _TOOL_LIMITS = _build_limits_from_policy()
    lines = ["Tool resource limits:"]
    for tool, limits in sorted(_TOOL_LIMITS.items()):
        parts = [f"timeout={limits.timeout_seconds}s"]
        if limits.memory_limit_mb:
            parts.append(f"mem={limits.memory_limit_mb}MB")
        if limits.network_deny:
            parts.append("net=deny")
        lines.append(f"  {tool}: {', '.join(parts)}")
    return "\n".join(lines)

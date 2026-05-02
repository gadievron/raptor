"""
Shared types for the agent loop.

``AgentContext`` / ``AgentOutput`` / ``AgentSurrender`` are separated from
``loop.py`` so the validator in ``invariants.py`` can reference them
without depending on the loop (which depends on ``tools.py``, which is
the right direction — not the reverse).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class AgentContext:
    """Immutable inputs the loop passes to the validator."""
    cve_id: str
    inputs: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class AgentOutput:
    """Success. ``value`` is a ``PatchTuple`` for the discover path."""
    value: Any
    rationale: str
    tool_calls: tuple[str, ...] = field(default_factory=tuple)
    tokens: int = 0
    cost_usd: float = 0.0
    elapsed_s: float = 0.0


@dataclass(frozen=True, slots=True)
class AgentSurrender:
    """Structured give-up. ``reason`` groups in the bench aggregator.

    ``verified_candidates`` carries (slug, sha) pairs that
    ``gh_commit_detail`` confirmed during the run. Empty for
    ``UnsupportedSource`` / ``no_evidence`` paths; populated when the
    agent ran out of budget after finding a candidate it never got to
    submit. The pipeline's retry orchestrator uses this to spawn a
    focused second pass with the candidate as context.
    """
    reason: str
    detail: str = ""
    tool_calls: tuple[str, ...] = field(default_factory=tuple)
    tokens: int = 0
    cost_usd: float = 0.0
    elapsed_s: float = 0.0
    verified_candidates: tuple[tuple[str, str], ...] = field(default_factory=tuple)


AgentResult = AgentOutput | AgentSurrender

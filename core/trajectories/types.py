"""Trajectory record schema.

A trajectory is the per-turn record of an LLM tool-use loop: what the
model said, which tools it called with what arguments, and what came
back. One :class:`TrajectoryStep` per turn; one
:class:`TrajectoryRecord` per loop run.

Used for operator-facing debugging ("which tool calls led here?"),
A/B analysis of prompt variants, and any downstream retrieval that
wants to rank past runs by tools_used / cost / outcome.

Schema discipline: this is a **persisted** format. Adding fields is
fine (consumers tolerate unknown keys), removing or renaming is not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "TrajectoryRecord",
    "TrajectoryStep",
]

# run_id must be safe as a directory name on disk. Same shape as
# LabeledAttempt's finding_signature: alphanumeric + dash/underscore,
# bounded length.
_VALID_RUN_ID = re.compile(r"^[A-Za-z0-9_\-.]{1,128}$")


@dataclass(frozen=True)
class TrajectoryStep:
    """One turn of conversation history, JSON-serialisable.

    Mirrors :class:`core.llm.tool_use.types.Message` but as plain
    dicts so the on-disk record doesn't break when the upstream
    Message dataclass evolves.

    ``text_blocks`` is the concatenated text from any TextBlock content
    items. ``tool_calls`` is a list of ``{id, name, input}`` dicts for
    assistant turns. ``tool_results`` is a list of
    ``{tool_use_id, content, is_error}`` dicts for user turns.

    Text and tool-result content are truncated at :data:`_MAX_TEXT_LEN`
    in :func:`store.serialize_messages` to keep individual trajectories
    bounded. Truncation is indicated with a ``...[truncated N chars]``
    suffix.
    """

    iteration: int
    role: str                                 # "user" | "assistant"
    text_blocks: list[str] = field(default_factory=list)
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_results: list[dict[str, Any]] = field(default_factory=list)


@dataclass(frozen=True)
class TrajectoryRecord:
    """One LLM tool-use loop run's trajectory.

    Spine: ``run_id`` + ``model_name`` (always present) + optional
    ``finding_id`` / ``cwe`` for security-finding-driven runs.
    ``run_id`` is the operator-chosen / auto-minted identifier that
    names the on-disk directory (``<base>/trajectories/<run_id>/``).

    ``finding_id`` and ``cwe`` default to ``""`` so consumers that
    aren't driven by a Finding (e.g. open-ended ``/agentic`` runs,
    interactive ``/understand`` queries) can persist trajectories
    without inventing identifiers. Producers that DO have a finding
    context pass the values for downstream filtering and ranking.
    """

    run_id: str
    model_name: str
    terminated_by: str
    iterations: int
    tool_calls_made: int
    cost_usd: float
    steps: list[TrajectoryStep]
    finding_id: str = ""
    cwe: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not _VALID_RUN_ID.match(self.run_id):
            raise ValueError(
                f"run_id must be alphanumeric/dash/underscore/dot, "
                f"1-128 chars; got {self.run_id!r}"
            )
        if ".." in self.run_id:
            # Even though `.` is allowed (version suffixes etc.),
            # `..` is the path-traversal vector. Block it here as
            # defense in depth; the disk layer rejects it too.
            raise ValueError(
                f"run_id must not contain '..'; got {self.run_id!r}"
            )

"""Trajectory persistence — per-iteration tool-call traces.

Substrate for any consumer of :mod:`core.llm.tool_use` that wants to
persist a structured record of "what the model said, which tools it
called, what came back" — useful for operator debugging, A/B analysis
of prompt variants, and post-hoc replay.

See ``store.py`` for the serialisation + write surface, ``types.py``
for the on-disk record shape, and ``auto.py`` for the opt-in
``RAPTOR_TRAJECTORY_DIR`` env-var integration that lets callers
persist without threading an output directory through their stack.
"""

from .auto import TRAJECTORY_DIR_ENV, persist_from_loop_result
from .store import (
    TRAJECTORY_FILENAME,
    serialize_messages,
    trajectory_path,
    write_trajectory,
)
from .types import (
    TrajectoryRecord,
    TrajectoryStep,
)

__all__ = [
    "TRAJECTORY_DIR_ENV",
    "TRAJECTORY_FILENAME",
    "TrajectoryRecord",
    "TrajectoryStep",
    "persist_from_loop_result",
    "serialize_messages",
    "trajectory_path",
    "write_trajectory",
]

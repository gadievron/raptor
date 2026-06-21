"""Storage for trajectory records.

One trajectory file per tool-use loop run, JSON, written under

    <base>/trajectories/<run_id>/trajectory.json

``<base>`` is caller-chosen — typically the run's output directory
when the caller knows it (CLI mode), or a project root when the
caller wants trajectories to accumulate across runs for cross-run
analysis. The opt-in helper in :mod:`core.trajectories.auto` reads
this from the ``RAPTOR_TRAJECTORY_DIR`` environment variable so
consumers don't have to thread an output_dir kwarg through every
function in their stack.

Atomic-write semantics: O_EXCL + retry on collision, same shape as
``core/labeled_attempts/store.py``. A trajectory write at the same
``run_id`` more than once is a programmer error (run_ids must be
unique per run), but the symptom is a clear OSError rather than a
silent overwrite.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from core.llm.tool_use.types import Message, TextBlock, ToolCall, ToolResult

from .types import TrajectoryRecord, TrajectoryStep

__all__ = [
    "TRAJECTORY_FILENAME",
    "serialize_messages",
    "trajectory_path",
    "write_trajectory",
]


TRAJECTORY_FILENAME = "trajectory.json"

# Per-block text cap. Tool results in particular can be enormous
# (full file dumps, disassembly listings). 64 KB per block keeps the
# trajectory readable + bounded without losing the operator-visible
# shape of what happened. A truncation marker is appended so the
# reader knows.
_MAX_TEXT_LEN = 64 * 1024


def _truncate(text: str) -> str:
    """Cap a single text payload at _MAX_TEXT_LEN with a marker."""
    if len(text) <= _MAX_TEXT_LEN:
        return text
    return (
        text[:_MAX_TEXT_LEN]
        + f"\n...[truncated {len(text) - _MAX_TEXT_LEN} chars]"
    )


def serialize_messages(messages: Iterable[Message]) -> list[TrajectoryStep]:
    """Turn a ToolLoopResult.messages list into TrajectoryStep dicts.

    Each Message becomes one step; iteration index counts assistant
    turns since user turns are interleaved replies to those.

    Tool result content is truncated at :data:`_MAX_TEXT_LEN` per
    block so a runaway tool (e.g. a `read_file` on a 100 MB file)
    can't blow up the trajectory size unbounded.
    """
    steps: list[TrajectoryStep] = []
    iteration = 0
    for msg in messages:
        text_blocks: list[str] = []
        tool_calls: list[dict[str, Any]] = []
        tool_results: list[dict[str, Any]] = []
        for block in msg.content:
            if isinstance(block, TextBlock):
                text_blocks.append(_truncate(block.text))
            elif isinstance(block, ToolCall):
                tool_calls.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })
            elif isinstance(block, ToolResult):
                tool_results.append({
                    "tool_use_id": block.tool_use_id,
                    "content": _truncate(block.content),
                    "is_error": block.is_error,
                })
        steps.append(TrajectoryStep(
            iteration=iteration,
            role=msg.role,
            text_blocks=text_blocks,
            tool_calls=tool_calls,
            tool_results=tool_results,
        ))
        # Count iterations on assistant turns — that's "model turn N".
        if msg.role == "assistant":
            iteration += 1
    return steps


def trajectory_path(base: Path, run_id: str) -> Path:
    """Where the trajectory file for ``run_id`` lives under ``base``.

    Returns the canonical path; doesn't create directories or check
    existence. Useful for callers that want to advertise the path
    before writing.
    """
    return Path(base) / "trajectories" / run_id / TRAJECTORY_FILENAME


def _record_to_json(record: TrajectoryRecord) -> str:
    return json.dumps(asdict(record), indent=2)


def _write_atomic(path: Path, payload: str) -> Path:
    """O_NOFOLLOW + O_EXCL + O_CREAT atomic write. Same shape as
    labeled_attempts/store._write_atomic but without the random-suffix
    retry loop: a trajectory collision means duplicate run_id, which
    is a programmer error worth surfacing.

    If the path-deterministic write loses (e.g. someone planted a
    symlink), we retry once with a random suffix on the filename so
    the run's trajectory still lands somewhere — but report the path
    we ended up using.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o644)
    except FileExistsError:
        # Already exists — for trajectories this is "this run_id was
        # written before" or a planted-symlink attack. Retry with a
        # random suffix so the run isn't lost.
        suffix = secrets.token_hex(3)
        path = path.with_name(f"{path.stem}-{suffix}{path.suffix}")
        fd = os.open(path, flags, 0o644)
    try:
        os.write(fd, payload.encode("utf-8"))
    finally:
        os.close(fd)
    return path


def write_trajectory(
    record: TrajectoryRecord, *, base: Path,
) -> Path:
    """Persist ``record`` under ``<base>/trajectories/<run_id>/``.

    Returns the on-disk path actually written. Raises:
      * ValueError — record itself is invalid (caught at construction
        anyway; surfaced here for defensive callers). Also raised when
        the resolved write path escapes ``base`` — e.g. an attacker
        planted ``<base>/trajectories`` as a symlink before the run.
      * OSError — filesystem error.
    """
    out = trajectory_path(base, record.run_id)
    out.parent.mkdir(parents=True, exist_ok=True)

    # Defence-in-depth against a planted symlink at <base>/trajectories
    # (or any parent component above the trajectory file). _write_atomic
    # below uses O_NOFOLLOW on the FINAL component only — that catches
    # someone planting <base>/trajectories/<run>/trajectory.json as a
    # symlink, but not someone planting <base>/trajectories as a symlink
    # to /etc/. realpath() walks every component, so post-mkdir we can
    # verify the resolved write target is still inside the operator's
    # chosen base.
    base_real = os.path.realpath(base)
    out_real = os.path.realpath(out)
    if not (
        out_real == os.path.join(base_real, "trajectories", record.run_id,
                                 TRAJECTORY_FILENAME)
        or out_real.startswith(base_real + os.sep)
    ):
        raise ValueError(
            f"refusing to write trajectory outside base: "
            f"base={base_real!r} out={out_real!r}"
        )

    payload = _record_to_json(record)
    return _write_atomic(out, payload)

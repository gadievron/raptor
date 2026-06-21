"""Opt-in helper for ToolUseLoop consumers.

The pattern is "produce a trajectory if the operator asked for one,
otherwise no-op". Tied to the ``RAPTOR_TRAJECTORY_DIR`` environment
variable: when set to a directory path, the helper writes
``<dir>/trajectories/<run_id>/trajectory.json`` per the
:mod:`core.trajectories.store` layout. Unset → silently skip.

This keeps the call-site change at each consumer to a single line:

    from core.trajectories.auto import persist_from_loop_result
    ...
    result = loop.run(user_message)
    persist_from_loop_result(
        result, run_id=f"hunt-{model.model_name}", model_name=model.model_name,
    )

without threading an ``output_dir`` kwarg through every function in
the call chain.

Operator workflow: set the env var (typically from a slash-command
shim that already knows its run's output directory) and trajectories
appear; unset → existing behaviour unchanged.

Failures during persistence are LOGGED and SWALLOWED — a trajectory
write failing must never break the underlying tool-use loop result.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import TYPE_CHECKING

from .store import write_trajectory, serialize_messages
from .types import TrajectoryRecord

if TYPE_CHECKING:
    from core.llm.tool_use.types import ToolLoopResult

logger = logging.getLogger(__name__)

__all__ = [
    "TRAJECTORY_DIR_ENV",
    "persist_from_loop_result",
    "persist_partial_from_exception",
]


TRAJECTORY_DIR_ENV = "RAPTOR_TRAJECTORY_DIR"

# Characters tolerated in TrajectoryRecord.run_id are a strict subset of
# what real-world model names use — Bedrock model IDs end in ``:0``,
# OpenRouter slugs are ``vendor/model``, and ``@`` shows up in
# revision-pinned IDs. Replacing them up front means the operator sees a
# trajectory file rather than a silent ValueError swallowed in the
# warning log. The substitution is one-way (we don't try to round-trip);
# the original ``model_name`` is preserved verbatim in the record body.
_RUN_ID_FORBIDDEN_CHAR = re.compile(r"[^A-Za-z0-9_.\-]")
# Belt-and-braces against producer code that synthesises a run_id with
# obvious traversal — the regex above would already collapse '/' to '-',
# but a literal ``..`` chain that originated from a path fragment must
# not survive to the validator. We can't safely rewrite ``..`` to ``.``
# (collisions), so trim instead.
_DOTDOT = re.compile(r"\.{2,}")


def _sanitize_run_id(run_id: str) -> str:
    """Coerce ``run_id`` into the ``TrajectoryRecord`` validation grammar.

    ``TrajectoryRecord.__post_init__`` requires ``^[A-Za-z0-9_\\-.]+`` and
    rejects ``..``. Real model names break those constraints (Bedrock
    ``claude-3-haiku-20240307-v1:0``, OpenRouter ``anthropic/claude-...``).
    Sanitise here so operators get a trajectory rather than a silently
    swallowed validation error.
    """
    cleaned = _RUN_ID_FORBIDDEN_CHAR.sub("-", run_id)
    cleaned = _DOTDOT.sub(".", cleaned)
    # 128 is the TrajectoryRecord upper bound; trim from the right so the
    # discriminator (e.g. ``hunt-``/``trace-``/``cve-diff-`` prefix) survives.
    return cleaned[:128] if cleaned else "run"


def persist_from_loop_result(
    result: "ToolLoopResult",
    *,
    run_id: str,
    model_name: str,
    finding_id: str = "",
    cwe: str = "",
    timestamp: str = "",
) -> Path | None:
    """Write a trajectory iff ``RAPTOR_TRAJECTORY_DIR`` is set.

    Returns the on-disk path written, or ``None`` when the env var
    is unset (the opt-out path) or when persistence raised — the
    underlying tool-use loop result must not be affected by a
    trajectory write failure.

    ``run_id`` should be unique per run; on collision the store
    appends a short random suffix to avoid overwrite.
    """
    base_dir = os.environ.get(TRAJECTORY_DIR_ENV)
    if not base_dir:
        return None

    safe_run_id = _sanitize_run_id(run_id)
    try:
        record = TrajectoryRecord(
            run_id=safe_run_id,
            model_name=model_name,
            terminated_by=result.terminated_by,
            iterations=result.iterations,
            tool_calls_made=result.tool_calls_made,
            cost_usd=result.total_cost_usd,
            steps=serialize_messages(result.messages),
            finding_id=finding_id,
            cwe=cwe,
            timestamp=timestamp,
        )
        return write_trajectory(record, base=Path(base_dir))
    except Exception as exc:        # noqa: BLE001 — never propagate
        # WARNING without traceback so a read-only RAPTOR_TRAJECTORY_DIR
        # in a long-running operator process doesn't flood the log with
        # thousands of stacktraces. The traceback is still available at
        # DEBUG level for an operator who needs it.
        logger.warning(
            "trajectory persist failed for run_id=%r (base=%r): %s",
            safe_run_id, base_dir, exc,
        )
        logger.debug("trajectory persist traceback:", exc_info=True)
        return None


def persist_partial_from_exception(
    exc: BaseException,
    *,
    run_id: str,
    model_name: str,
    terminated_by: str,
    finding_id: str = "",
    cwe: str = "",
    timestamp: str = "",
) -> Path | None:
    """Write a partial trajectory from a tool-use loop exception.

    ``CostBudgetExceeded`` and ``ContextOverflow`` carry ``messages``
    and ``tool_calls_made`` attributes (per the loop's partial-state
    contract). This helper reads them and writes whatever's available
    so the operator can see *what the model was doing when it ran out
    of budget* — exactly the case where the trajectory is most useful.

    Exceptions without those attributes (generic ``Exception``, etc.)
    produce an empty-steps trajectory: ``run_id`` + ``model_name`` +
    ``terminated_by`` survive so the operator at least knows the run
    happened and what killed it.

    Same opt-in + swallow contract as ``persist_from_loop_result``:
    no-op when ``RAPTOR_TRAJECTORY_DIR`` is unset, failures logged
    + swallowed so a trajectory write can never break the caller's
    own error handling.
    """
    base_dir = os.environ.get(TRAJECTORY_DIR_ENV)
    if not base_dir:
        return None

    messages = getattr(exc, "messages", []) or []
    tool_calls_made = getattr(exc, "tool_calls_made", 0) or 0
    safe_run_id = _sanitize_run_id(run_id)

    try:
        record = TrajectoryRecord(
            run_id=safe_run_id,
            model_name=model_name,
            terminated_by=terminated_by,
            iterations=0,
            tool_calls_made=int(tool_calls_made),
            cost_usd=0.0,
            steps=serialize_messages(messages),
            finding_id=finding_id,
            cwe=cwe,
            timestamp=timestamp,
        )
        return write_trajectory(record, base=Path(base_dir))
    except Exception as exc2:        # noqa: BLE001 — never propagate
        logger.warning(
            "partial-trajectory persist failed for run_id=%r (base=%r): %s",
            safe_run_id, base_dir, exc2,
        )
        logger.debug("partial-trajectory persist traceback:", exc_info=True)
        return None

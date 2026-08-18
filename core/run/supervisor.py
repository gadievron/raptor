"""External-supervisor detection — Claude Code subagent shell caps.

The Claude Code harness caps each SUBAGENT background shell at
``CLAUDE_SUBAGENT_BG_SHELL_MAX_MS`` (default 3,600,000 ms): a timer
armed when the shell is backgrounded kills the whole process group at
the cap, regardless of what the process is doing. Main-thread
background shells are uncapped. A long audit launched from a subagent
therefore dies mid-run at cap + ~0s unless it bounds itself first.

This module answers one question — "are we under a capped supervisor,
and what wall bound should a long run default to?" — from the process
environment:

* under a Claude session at all: ``CLAUDECODE`` (the harness's own
  trust marker) or a ``claude`` process ancestor
  (``core.run.metadata._find_claude_ancestor``);
* subagent shell (vs main thread): the harness stamps subagent shells
  with an ``AI_AGENT`` value ending in ``_agent`` and sets
  ``CLAUDE_CODE_CHILD_SESSION``. (``CLAUDE_CODE_SUBAGENT_MODEL`` is
  NOT a signal — ``bin/raptor`` bridges it into every shell.)

Failure directions are deliberately asymmetric and both safe:

* false positive (main thread misread as subagent): the run
  self-bounds and concludes gracefully with a remainder note — the
  operator loses nothing and the opt-out flag exists;
* false negative (subagent misread as main thread): the harness kill
  lands as before, the run's failure path holds, and
  ``raptor-audit resume`` recovers it.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)

#: Harness knob naming the per-subagent background-shell cap (ms).
SUBAGENT_BG_SHELL_CAP_ENV = "CLAUDE_SUBAGENT_BG_SHELL_MAX_MS"

#: The harness default when the knob is unset (3,600,000 ms).
DEFAULT_SUBAGENT_CAP_S = 3600.0

#: Headroom reserved for the graceful drain: harvest in-flight
#: reviews, flush ledgers/journal, write the report — all comfortably
#: inside 300s. 3600 - 300 = the documented 3300s default bound.
DRAIN_MARGIN_S = 300.0

#: Never bound below this — a sub-minute wall budget reviews nothing.
MIN_BOUND_S = 60.0


@dataclass(frozen=True)
class SupervisorBound:
    """A derived wall bound under a capped supervisor shell."""

    bound_s: float
    cap_s: float


def _under_claude_session() -> bool:
    if os.environ.get("CLAUDECODE"):
        return True
    try:
        from core.run.metadata import _find_claude_ancestor
        return _find_claude_ancestor() is not None
    except Exception:
        logger.debug("claude-ancestry walk failed", exc_info=True)
        return False


def is_subagent_shell() -> bool:
    """Best-effort: are we inside a Claude SUBAGENT background shell?"""
    if not _under_claude_session():
        return False
    if os.environ.get("AI_AGENT", "").endswith("_agent"):
        return True
    return bool(os.environ.get("CLAUDE_CODE_CHILD_SESSION"))


def subagent_shell_cap_s() -> float:
    """The supervisor's shell cap in seconds (env override or the
    harness default). Non-numeric / non-positive values warn once at
    debug and fall back to the default."""
    raw = os.environ.get(SUBAGENT_BG_SHELL_CAP_ENV)
    if raw:
        try:
            cap = float(raw) / 1000.0
            if cap > 0:
                return cap
            logger.debug(
                "%s=%r is non-positive — using the %gs default",
                SUBAGENT_BG_SHELL_CAP_ENV, raw, DEFAULT_SUBAGENT_CAP_S,
            )
        except ValueError:
            logger.debug(
                "%s=%r is not numeric — using the %gs default",
                SUBAGENT_BG_SHELL_CAP_ENV, raw, DEFAULT_SUBAGENT_CAP_S,
            )
    return DEFAULT_SUBAGENT_CAP_S


def supervisor_wall_bound() -> SupervisorBound | None:
    """The wall bound a long run should default to, or ``None``.

    ``None`` in main-thread / interactive / non-Claude contexts —
    those are unaffected. Under a subagent shell: the cap minus the
    drain margin, floored at :data:`MIN_BOUND_S` (3300s under the
    harness default).
    """
    if not is_subagent_shell():
        return None
    cap = subagent_shell_cap_s()
    return SupervisorBound(
        bound_s=max(MIN_BOUND_S, cap - DRAIN_MARGIN_S),
        cap_s=cap,
    )

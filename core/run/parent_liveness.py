"""Parent-liveness watchdog for RAPTOR-spawned long-lived children.

Long-lived analysis children (the static-analysis scanner, phase
subprocesses) are spawned with ``start_new_session=True`` so the
spawner can ``killpg`` the whole tree on a phase timeout. That same
detachment means a SIGKILLed / OOM-killed spawner leaves the child
tree running forever: PR_SET_PDEATHSIG at the spawn chokepoint covers
the common case, but the kernel clears it across setuid exec and
``unshare(CLONE_NEWUSER)``, it fires on death of the spawning THREAD
rather than the spawning process, and it does not exist off Linux.

This module is the belt-and-braces layer that runs INSIDE the child:
a daemon thread polls ``os.getppid()`` and, when the recorded parent
is gone (the child re-parented to init or a subreaper), SIGKILLs the
child's own process group — taking down the grandchildren the child
itself started in that group — and exits.

Opt-in by contract, never ambient: the watchdog only arms when the
spawner set :data:`WATCHDOG_ENV` in the child's environment. Setting
the variable asserts two things about the child:

* it was spawned with ``start_new_session=True`` (it leads its own
  process group, so ``killpg(0, ...)`` can never reach the spawner's
  siblings), and
* nothing about it may legitimately outlive the spawner (a child an
  operator deliberately detaches — ``nohup``, a bare-shell run — must
  NOT get the variable).

The value is the spawner's pid when known (lets the child detect a
parent that died inside the spawn window, before the watchdog could
record it), or the literal ``"1"`` for a plain enable. Any other
value disarms with a debug log — a garbled knob must never make a
process kill itself. ``core.config.RaptorConfig.get_safe_env`` does
not allowlist the variable, so grandchildren spawned through the safe
env never inherit the opt-in.

Import-light by the same convention as :mod:`core.run.tmp_reaper`
(no core.config / core.sandbox imports): the consumers arm this
before heavier subsystems are importable.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time

logger = logging.getLogger(__name__)

__all__ = [
    "WATCHDOG_ENV",
    "maybe_start_orphan_watchdog",
    "start_orphan_watchdog",
]

#: Spawner-set opt-in. Value: the spawner's pid, or "1".
WATCHDOG_ENV = "RAPTOR_PARENT_WATCHDOG"

#: Poll cadence. Orphan cleanup is a resource-hygiene bound, not a
#: latency contract — seconds of grace are fine, and the poll is two
#: syscalls.
_DEFAULT_POLL_S = 5.0


def _terminate_group(label: str) -> None:
    """SIGKILL the calling process's own group, then hard-exit.

    Raw ``os.write(2, ...)``: the process is tearing itself down on an
    async event, logging handlers may be locked or gone. ``os._exit``
    is the backstop for the (never-observed) case where ``killpg`` on
    our own group does not deliver.
    """
    try:
        os.write(
            2,
            (
                f"raptor: {label}: parent process died; terminating "
                "own process group\n"
            ).encode("utf-8", errors="replace"),
        )
    except OSError:
        pass
    try:
        os.killpg(0, signal.SIGKILL)
    except OSError:
        pass
    os._exit(1)


def start_orphan_watchdog(
    label: str,
    *,
    expected_parent: int | None = None,
    poll_s: float = _DEFAULT_POLL_S,
) -> threading.Thread:
    """Arm the watchdog unconditionally; see the module docstring for
    the ``start_new_session`` contract the caller asserts.

    ``expected_parent`` narrows the liveness reference to the pid the
    spawner recorded parent-side; when the current ``getppid()``
    already differs (the parent died before this child got here — the
    child sees init or a subreaper instead), the orphan action fires
    immediately. Without it the current ``getppid()`` is recorded and
    only a CHANGE fires — a child that was already re-parented at
    arm time would then never fire, which is why spawners pass their
    pid when they can.
    """
    parent = expected_parent if expected_parent else os.getppid()

    def _watch() -> None:
        while os.getppid() == parent:
            time.sleep(poll_s)
        _terminate_group(label)

    thread = threading.Thread(
        target=_watch,
        name=f"raptor-orphan-watchdog-{label}",
        daemon=True,
    )
    thread.start()
    return thread


def maybe_start_orphan_watchdog(
    label: str,
    *,
    poll_s: float = _DEFAULT_POLL_S,
) -> threading.Thread | None:
    """Arm the watchdog iff the spawner opted this process in.

    Returns the watchdog thread, or ``None`` when :data:`WATCHDOG_ENV`
    is unset (a directly-invoked / deliberately-detached process) or
    carries a value that is neither ``"1"`` nor a pid — both directions
    fail toward NOT self-killing.
    """
    raw = os.environ.get(WATCHDOG_ENV, "").strip()
    if not raw:
        return None
    expected: int | None = None
    if raw != "1":
        if not raw.isdigit():
            logger.debug(
                "%s=%r is neither '1' nor a pid; watchdog disarmed",
                WATCHDOG_ENV, raw,
            )
            return None
        expected = int(raw)
    return start_orphan_watchdog(
        label, expected_parent=expected, poll_s=poll_s,
    )

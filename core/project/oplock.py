"""Operation-granular project locking (``<project_dir>/.op.lock``).

Two kinds of contention share this module:

* **Mutating project-manager subcommands** (set/unset, trust/untrust,
  binary add/remove/clear, create, clean) hold the flock for the
  duration of the mutation via :func:`project_op_lock`. Contenders get
  a silent 3 s grace (mutations are sub-second), then ONE stderr-bound
  message naming the holder and a non-zero exit; ``--wait`` blocks
  indefinitely instead.

* **Run starts** hold the flock only across the contention-check +
  metadata-write window (see ``core.run.metadata.start_run``). The
  run itself is NOT represented by the flock — a flock dies with the
  process that took it, and the stub-based ``raptor-run-lifecycle
  start``/``complete`` flow spans processes. Run-in-progress is the
  run's own metadata (``status=running`` + a live recorded session
  pid), which has the crash semantics a flock can't give: a crashed
  run leaves a dead pid behind and is detectably NOT contention.

The flock is the truth. The lock file's CONTENT is diagnostic only —
holders stamp ``{pid, session_pid, operation, since}`` AFTER acquiring
so contenders can name who they're waiting on; stale content behind a
free lock is never read (contenders only read it after flock refused).

The lock file is deliberately never unlinked (same doctrine as
``project_file_lock`` / ``_metadata_lock``): unlink-after-unlock races
can split lockers across two inodes.
"""

from __future__ import annotations

import contextlib
import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

OP_LOCK_NAME = ".op.lock"

# Silent grace for mutating subcommands: a healthy mutation holds the
# lock well under a second, so a short quiet retry window avoids
# noising up scripts for the common in-and-out case.
MUTATOR_GRACE_S = 3.0

_POLL_INTERVAL_S = 0.1


class OpLockContention(RuntimeError):
    """The project op lock (or run slot) is held by another operation.

    ``str(exc)`` is the single operator-facing line; ``holder`` carries
    the parsed diagnostic fields when available.
    """

    def __init__(self, message: str, holder: dict | None = None) -> None:
        super().__init__(message)
        self.holder = holder or {}


class ProjectRunContention(OpLockContention):
    """A live run owns the project (run-start vs live-run conflict)."""


def op_lock_path(project_dir: Path) -> Path:
    return Path(project_dir) / OP_LOCK_NAME


def _session_pid() -> int | None:
    """Best-effort session id for the holder stamp (diagnostic only)."""
    try:
        from core.run.metadata import _get_session_pid
        return _get_session_pid()
    except Exception:  # noqa: BLE001 — stamp stays useful without it
        return None


def read_holder(lock_path: Path) -> dict:
    """Parse the holder stamp. Diagnostic only — callers must consult
    it exclusively AFTER flock refused (a free lock's stale content
    must never produce a message)."""
    try:
        data = json.loads(Path(lock_path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def describe_holder(holder: dict) -> str:
    """One operator-facing line. The stamp is FILE CONTENT (any writer
    in the project dir can forge it), so every field is terminal-
    sanitised and the pid coerced — no raw escape bytes or floods
    reach the operator's terminal via a contention message."""
    from core.security.log_sanitisation import sanitise_for_terminal
    pid = holder.get("pid")
    pid_s = str(pid) if isinstance(pid, int) and not isinstance(pid, bool) \
        else "unknown"
    op = sanitise_for_terminal(str(holder.get("operation") or "unknown"),
                               max_len=64)
    since = sanitise_for_terminal(str(holder.get("since") or "unknown"),
                                  max_len=64)
    return f"pid {pid_s}, op {op}, held since {since}"


def _stamp_holder(fd: int, operation: str) -> None:
    """Write the holder diagnostic AFTER acquiring. Failure is ignored
    — the flock, not the content, is the mutual exclusion."""
    record = {
        "pid": os.getpid(),
        "session_pid": _session_pid(),
        "operation": operation,
        "since": datetime.now(timezone.utc).isoformat(),
    }
    with contextlib.suppress(OSError, ValueError):
        payload = (json.dumps(record) + "\n").encode("utf-8")
        os.ftruncate(fd, 0)
        os.lseek(fd, 0, os.SEEK_SET)
        os.write(fd, payload)


@contextlib.contextmanager
def project_op_lock(project_dir: Path, operation: str,
                    grace: float | None = None,
                    wait: bool = False):
    """Exclusive per-project operation lock.

    Silent for ``grace`` seconds of retries (default: the module's
    ``MUTATOR_GRACE_S``, read at call time so tests can shrink it),
    then raises :class:`OpLockContention` whose message names the
    holder and suggests retry / ``--wait``. ``wait=True`` blocks
    indefinitely.
    Degrades to a no-op without fcntl or when the lock file is
    uncreatable (read-only dir, ENOSPC) — same fail direction as the
    sibling RMW locks: proceed unserialised rather than refuse.
    """
    if not _HAS_FCNTL:
        yield
        return
    if grace is None:
        grace = MUTATOR_GRACE_S
    project_dir = Path(project_dir)
    lock_path = op_lock_path(project_dir)
    try:
        project_dir.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
    except OSError:
        yield
        return
    try:
        acquired = False
        if wait:
            fcntl.flock(fd, fcntl.LOCK_EX)
            acquired = True
        else:
            deadline = time.monotonic() + max(grace, 0.0)
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    acquired = True
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        break
                    time.sleep(_POLL_INTERVAL_S)
        if not acquired:
            holder = read_holder(lock_path)
            msg = (
                f"project is locked by another operation "
                f"({describe_holder(holder)}) — retry shortly or pass "
                f"--wait"
            )
            raise OpLockContention(
                msg,
                holder,
            )
        _stamp_holder(fd, operation)
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)

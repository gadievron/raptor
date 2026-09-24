"""Cross-process lock for a binary run's artifact read-modify-write
seams.

``append_fuzz_evidence_to_run``, ``append_runtime_evidence_to_run``
and the harness checklist update all load a run artifact
(binary-evidence.json / binary-checklist.json / the context map),
mutate it, and save it back. ``save_json``'s per-file atomicity makes
a concurrent lost update clean and invisible: two unserialised
writers each load the same base state and the second save silently
discards the first's records — evidence the validation handoff and
the graph cite. Real interleaves exist: the fuzz orchestrator folds
evidence back post-campaign while an operator runs ``trace-parser``
or ``harness`` against the same run dir.

Same idiom as ``core.run.metadata._metadata_lock``: flock a sibling
lock file (never the JSON itself, which save_json atomically
replaces), hold it across the whole load → mutate → save window,
degrade to a no-op without fcntl (non-POSIX). The lock file is
deliberately left behind — unlinking after unlock races another
process's open fd against a third's fresh create, splitting lockers
across two inodes.
"""

from __future__ import annotations

import contextlib
import functools
import logging
import os
import stat as _stat
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TypeVar

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

_LOCK_NAME = ".binary-artifacts.lock"

_F = TypeVar("_F", bound=Callable[..., Any])


@contextlib.contextmanager
def run_artifacts_lock(run_dir: Path) -> Iterator[None]:
    """Exclusive cross-process lock over ``run_dir``'s artifact RMW
    window. Never raises for lock-infrastructure reasons — an
    uncreatable lock file (read-only dir mid-teardown, ENOSPC)
    degrades to the unserialised pre-lock behaviour rather than
    failing the append."""
    if not _HAS_FCNTL:
        yield
        return
    lock_path = Path(run_dir) / _LOCK_NAME
    # The run dir is (or was) inside a sandboxed child's write grant,
    # so the open must not trust what it finds at the lock name:
    # O_NOFOLLOW keeps a planted symlink from making this process
    # create and flock an attacker-chosen path; O_NONBLOCK plus the
    # fstat S_ISREG refusal keeps a planted reader-less FIFO from
    # wedging every artifact append forever. Same flag shape as
    # core.fs_lock / core.run.metadata's locks.
    fd = None
    try:
        fd = os.open(
            str(lock_path),
            os.O_WRONLY | os.O_CREAT
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NONBLOCK", 0),
            0o600,
        )
        if not _stat.S_ISREG(os.fstat(fd).st_mode):
            raise OSError(
                f"lock path {lock_path} is not a regular file")
    except OSError as exc:
        if fd is not None:
            with contextlib.suppress(OSError):
                os.close(fd)
        logger.warning(
            "binary artifact lock %s: refusing to open (%s); "
            "proceeding WITHOUT cross-process lock — concurrent "
            "appends may drop each other's records; investigate a "
            "planted symlink or FIFO at that path", lock_path, exc,
        )
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def with_run_artifacts_lock(func: _F) -> _F:
    """Decorate an append/refresh seam whose keyword ``out_dir`` names
    the run directory: the whole call runs under
    :func:`run_artifacts_lock`."""
    @functools.wraps(func)
    def wrapper(*args: Any, out_dir: Path, **kwargs: Any) -> Any:
        out_dir = Path(out_dir).resolve()
        with run_artifacts_lock(out_dir):
            return func(*args, out_dir=out_dir, **kwargs)
    return wrapper  # type: ignore[return-value]

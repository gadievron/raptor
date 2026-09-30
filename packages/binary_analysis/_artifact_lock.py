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

The lock itself is ``core.atomic_fs.fs_lock``'s hoisted sidecar
idiom (hardened open, foreign-uid refusal, bounded LOCK_NB-first
acquisition, loud degrade on every lock-unavailable shape), pointed
at the run-dir-level ``.binary-artifacts.lock``. The parent dir is
never created here — a missing run dir keeps degrading instead of
being conjured for the lock's sake — and the lock file is
deliberately left behind (unlinking after unlock races another
process's open fd against a third's fresh create, splitting lockers
across two inodes).
"""

from __future__ import annotations

import functools
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any, TypeVar

from core.atomic_fs.fs_lock import sidecar_flock

_LOCK_NAME = ".binary-artifacts.lock"

_F = TypeVar("_F", bound=Callable[..., Any])


def run_artifacts_lock(run_dir: Path) -> AbstractContextManager[None]:
    """Exclusive cross-process lock over ``run_dir``'s artifact RMW
    window. Never raises for lock-infrastructure reasons — an
    uncreatable lock file (read-only dir mid-teardown, ENOSPC), a
    tamper-shaped or foreign-uid one, and a holder that outlives the
    wait deadline all degrade to the unserialised pre-lock behaviour
    (loudly) rather than failing the append."""
    return sidecar_flock(
        Path(run_dir) / _LOCK_NAME,
        subject="binary artifact",
        create_parent=False,
    )


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

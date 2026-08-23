"""Scratch-directory context manager — the one way to make a temp
work area.

Consolidates the hand-rolled ``tempfile.mkdtemp`` idiom repeated across
the tree (mkdtemp inside ``try``, best-effort ``rmtree`` in
``finally``, optional ``TMPDIR`` export, optional run-output parent).
Two shapes exist in the wild and both are supported:

* **system-tmp scratch** (``dir=None``) — lives directly under
  ``tempfile.gettempdir()``. The prefix is auto-registered with
  :mod:`core.run.tmp_reaper` so a scratch dir orphaned by a crashed
  RAPTOR process in the SAME long-lived process family is reclaimed by
  the next run's sweep. (Registration is per-process; prefixes that
  must survive across unrelated processes still belong in the reaper's
  static ``_DIR_PREFIXES`` tuple, where each entry documents its
  owner's cleanup contract.)
* **run-output scratch** (``dir=...``) — created under an operator-
  visible output directory (which is created ``exist_ok`` first, the
  shared preamble every ``dir=`` call site repeated). Deliberately NOT
  reaper-registered: the reaper only sweeps the system tmp root.

Cleanup is best-effort (``ignore_errors=True``) unless ``keep=True``
(ownership transfer / ``--keep`` debugging escape hatch — the caller
owns deletion from then on).

While a system-tmp scratch is live, a keepalive thread refreshes its
mtime periodically so a long-quiet session (nothing written to the
dir for longer than the reaper's age floor) is never false-reaped by
a concurrent process's sweep — mtime is the sweep's own liveness
signal, so no reaper-side protocol is needed, and the refresh stops
with the owning process so true orphans still age out.

Import-light by the same convention as ``tmp_reaper`` (no core.config /
core.sandbox imports): several consumers construct scratch dirs before
heavier subsystems are importable.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import tempfile
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Iterator, MutableMapping

logger = logging.getLogger(__name__)

__all__ = ["keepalive_register", "keepalive_unregister", "scratch_dir"]

#: Keepalive refresh period. Must sit well below the reaper's age
#: floor (default 24 h; operators can shrink it via
#: ``RAPTOR_TMP_REAP_MAX_AGE_H`` — 15 min keeps floors down to ~30 min
#: safe).
_KEEPALIVE_INTERVAL_S: float = 900.0

_keepalive_lock = threading.Lock()
#: Live system-tmp scratch paths (str) whose mtime the tick refreshes.
_keepalive_paths: set[str] = set()
_keepalive_thread: threading.Thread | None = None


def _keepalive_tick() -> None:
    """Refresh the mtime of every live system-tmp scratch dir.

    Best-effort: a path that vanished underneath us (operator ``rm``,
    a ``keep=True`` caller's own deletion) is skipped silently.
    ``follow_symlinks=False`` where the platform supports it: /tmp is
    world-writable, so a symlink squatting on a vanished path must
    never earn a touch on its target.
    """
    with _keepalive_lock:
        paths = list(_keepalive_paths)
    no_follow = os.utime in os.supports_follow_symlinks
    refreshed = 0
    for p in paths:
        try:
            if no_follow:
                os.utime(p, follow_symlinks=False)
            else:  # pragma: no cover — platform-dependent fallback
                os.utime(p)
            refreshed += 1
        except OSError:
            continue
    if paths:
        # A registered dir that stopped refreshing (vanished, or an
        # owner that wedged without unregistering) is otherwise
        # invisible — surface the count for diagnosis.
        logger.debug(
            "scratch keepalive: refreshed %d/%d registered dir(s)",
            refreshed, len(paths),
        )


def _keepalive_loop() -> None:
    while True:
        time.sleep(_KEEPALIVE_INTERVAL_S)
        _keepalive_tick()


def keepalive_register(path: str | Path) -> None:
    """Keep *path*'s mtime fresh until :func:`keepalive_unregister`.

    For scratch owners whose system-tmp directory legitimately
    outlives a lexical scope (ownership transferred to a teardown
    method, a returned handle, or a caller's ``finally``) and can sit
    mtime-quiet past the reaper's age floor while still in use — a
    sandbox rootfs whose mtime froze at export, a staging tree bound
    into a running stack, a read-only excerpt tree feeding a multi-day
    run. ``scratch_dir`` calls this itself for the system-tmp shape.

    Every non-context-manager owner whose prefix is listed in the
    reaper MUST pair this with :func:`keepalive_unregister` at its
    cleanup site; registration is what makes the prefix listing safe
    for long-lived dirs (presence past the floor then always means the
    owning process is gone, because a live owner keeps refreshing).

    Lazily starts the daemon ticker. The liveness re-check covers
    ``fork()`` children: they inherit the parent's thread OBJECT but
    not the running thread, so the first registration in a forked
    child restarts its own ticker.
    """
    global _keepalive_thread
    with _keepalive_lock:
        _keepalive_paths.add(str(path))
        if _keepalive_thread is None or not _keepalive_thread.is_alive():
            _keepalive_thread = threading.Thread(
                target=_keepalive_loop,
                name="raptor-scratch-keepalive",
                daemon=True,
            )
            _keepalive_thread.start()


def keepalive_unregister(path: str | Path) -> None:
    """Stop refreshing *path*. Idempotent; unknown paths are a no-op."""
    with _keepalive_lock:
        _keepalive_paths.discard(str(path))


@contextlib.contextmanager
def scratch_dir(
    prefix: str,
    *,
    dir: str | Path | None = None,
    env: MutableMapping[str, str] | None = None,
    keep: bool = False,
) -> Iterator[Path]:
    """Create a scratch directory, yield it as a :class:`Path`, and
    best-effort-remove it on exit.

    Args:
        prefix: mkdtemp prefix. Also the reaper-registration key for
            system-tmp scratch (see module docstring).
        dir: optional parent directory (run-output scratch). Created
            ``exist_ok`` when given. ``None`` = system tmp.
        env: optional environment mapping to point at the scratch dir:
            ``env["TMPDIR"] = str(path)`` is set on entry, so child
            tools that honour ``TMPDIR`` (spatch et al.) strand their
            own temp litter inside the scratch dir where the exit
            cleanup collects it. The mapping is the caller's (usually a
            ``get_safe_env()`` copy) — nothing is restored on exit.
        keep: skip cleanup; the caller takes ownership of deletion.

    The directory is created on ``__enter__`` — if creation raises,
    nothing is cleaned up; if the body raises, cleanup still runs
    before the exception propagates (same ordering as the hand-rolled
    ``try/finally`` sites this replaces).
    """
    parent: str | None = None
    if dir is not None:
        parent = str(dir)
        Path(parent).mkdir(parents=True, exist_ok=True)
    else:
        # Same-process backstop: a long-lived orchestrator's next
        # start_run sweep can reclaim strays with this prefix.
        from core.run import tmp_reaper
        tmp_reaper.register_dir_prefix(prefix)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    if parent is None:
        # Keepalive for the reaper-swept shape: a live-but-quiet
        # session must never age past the sweep's floor. Run-output
        # scratch (dir=...) is never swept, so it is not tracked.
        keepalive_register(path)
    if env is not None:
        env["TMPDIR"] = str(path)
    try:
        yield path
    finally:
        if parent is None:
            # The keepalive window is the context-manager window —
            # a keep=True dir ages out normally once its owner stops
            # using it, same contract as other --keep survivors.
            keepalive_unregister(path)
        if not keep:
            shutil.rmtree(path, ignore_errors=True)

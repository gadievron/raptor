"""Dead-owner reclamation for self-cleaning system-tmp scratch dirs.

Long-lived components (the Joern server workspace, the in-process LLM
dispatcher socket dir) mint a ``mkdtemp`` dir and remove it on their
exit path. Exit-path cleanup misses SIGKILL, OOM, and unhandled
SIGTERM (Python does not run ``atexit`` hooks on SIGTERM), so every
hard-killed owner strands its dir until the age-based sweep in
:mod:`core.run.tmp_reaper` claims it a day later — workspaces can be
hundreds of MB each, so a day is too long.

This module closes that gap with an ownership handshake:

  - :func:`write_owner_marker` stamps a fresh dir with the creating
    pid, immediately after ``mkdtemp``.
  - :func:`sweep_dead_owner_dirs` runs at the NEXT component boot and
    removes same-prefix siblings whose recorded owner pid is dead.

Safety posture matches :mod:`core.run.tmp_reaper` (world-writable
/tmp on a shared box): ``lstat``-only candidate checks so a symlink
squatting on a matching name is never followed, resolved-path
containment under the temp dir, current-euid ownership, in-use probes
(live cwd references, answering sockets) before any removal, and a
validation-to-delete identity re-check. Best-effort by contract —
the sweep never raises.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path

# Import-light (stdlib-only at module level) — shares the reaper's
# in-use probes so both sweeps judge liveness the same way.
from core.run.tmp_reaper import _dir_in_use, _live_cwds

logger = logging.getLogger(__name__)

OWNER_MARKER_NAME = ".owner.json"

# A real marker is ~50 bytes; the cap keeps a planted oversize file
# unread (same posture as tmp_reaper's run-metadata gate).
_MARKER_MAX_BYTES = 4096

# Marker-less dirs predate the ownership handshake, so pid liveness
# cannot be judged — fall back to the same 24 h age floor the
# age-based reaper uses.
LEGACY_MAX_AGE_S = 24.0 * 3600.0


def write_owner_marker(dir_path: str | Path) -> None:
    """Stamp *dir_path* with an ownership marker (best-effort).

    The marker records the creating pid and creation time so a later
    :func:`sweep_dead_owner_dirs` can distinguish orphans (owner pid
    dead) from live components. 0600: the pid is only meaningful to
    the same euid that will run the sweep.
    """
    marker = Path(dir_path) / OWNER_MARKER_NAME
    payload = json.dumps({"pid": os.getpid(), "created": time.time()})
    try:
        fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
    except OSError:
        # A missing marker only degrades the dir to the legacy age
        # gate — never worth failing the component boot over.
        logger.debug("owner marker write failed for %s",
                     dir_path, exc_info=True)


def remove_owner_marker(dir_path: str | Path) -> None:
    """Unlink the ownership marker (best-effort, missing tolerated).

    For owners whose teardown removes the dir with ``rmdir`` rather
    than ``rmtree`` — the marker must not turn a clean shutdown into
    an ENOTEMPTY leak.
    """
    try:
        (Path(dir_path) / OWNER_MARKER_NAME).unlink(missing_ok=True)
    except OSError:
        logger.debug("owner marker unlink failed for %s",
                     dir_path, exc_info=True)


def _owner_pid(marker: Path) -> int | None:
    """The pid recorded in *marker*, or ``None`` when absent/invalid.

    Gated read on the OPEN fd — markers live in world-writable /tmp
    (the module's stated threat model), so the type/size gate must
    hold on the inode actually read: the old lstat-then-read pair
    could be raced (regular file at the lstat, FIFO at the read —
    reader blocks forever) and O_NOFOLLOW keeps the lstat semantics
    (a symlinked marker is refused, not followed).
    """
    flags = (
        os.O_RDONLY
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
        | getattr(os, "O_CLOEXEC", 0)
    )
    fd = -1
    try:
        fd = os.open(str(marker), flags)
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MARKER_MAX_BYTES:
            return None
        with os.fdopen(fd, "rb") as fh:
            fd = -1  # fdopen owns it now
            raw = fh.read(_MARKER_MAX_BYTES + 1)
        if len(raw) > _MARKER_MAX_BYTES:
            return None
        data = json.loads(raw)
    except (OSError, ValueError):
        return None
    finally:
        if fd >= 0:
            try:
                os.close(fd)
            except OSError:
                pass
    pid = data.get("pid") if isinstance(data, dict) else None
    if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0:
        return pid
    return None


def _pid_alive(pid: int) -> bool:
    """Plain existence probe — the owners here are ordinary Python
    processes, so :func:`core.run.metadata._pid_alive`'s
    ``comm == claude`` cross-check would misread every one of them as
    dead. Residual pid-reuse risk fails safe: a reused pid keeps a
    stale dir until the age-based reaper claims it.
    """
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # exists, owned by another user
    return True


def sweep_dead_owner_dirs(
    prefix: str,
    *,
    exclude: Path | None = None,
    legacy_max_age_s: float = LEGACY_MAX_AGE_S,
) -> list[Path]:
    """Remove ``<tempdir>/<prefix>*`` dirs whose owner is dead.

    ``exclude`` names a dir that must survive regardless (the one the
    caller is creating right now). Returns the removed paths. Never
    raises — a sweep failure must never block a component boot.
    """
    try:
        return _sweep(prefix, exclude, legacy_max_age_s)
    except Exception:  # noqa: BLE001 — best-effort by contract
        logger.debug("dead-owner sweep for %r aborted", prefix,
                     exc_info=True)
        return []


def _sweep(
    prefix: str,
    exclude: Path | None,
    legacy_max_age_s: float,
) -> list[Path]:
    tmp_root = Path(tempfile.gettempdir()).resolve()
    names = os.listdir(tmp_root)
    excluded = Path(exclude).resolve() if exclude is not None else None
    euid = os.geteuid()
    now = time.time()
    removed: list[Path] = []
    live_cwds: set[str] | None = None

    for name in names:
        if not name.startswith(prefix):
            continue
        path = tmp_root / name
        try:
            st = path.lstat()
        except OSError:
            continue
        if not stat.S_ISDIR(st.st_mode):
            continue  # symlink or file squatting on the prefix
        if st.st_uid != euid:
            continue
        try:
            resolved = path.resolve()
        except OSError:
            continue
        # Containment: only entries that genuinely live directly under
        # the temp dir are eligible — anything resolving elsewhere
        # (mount tricks, a relocated tempdir) is left alone.
        if resolved.parent != tmp_root:
            continue
        if excluded is not None and resolved == excluded:
            continue

        pid = _owner_pid(path / OWNER_MARKER_NAME)
        if pid is not None:
            if _pid_alive(pid):
                continue
        # Marker-less dirs get an age gate instead of pid liveness.
        # Both directions matter: no gate could race a sibling process
        # between its mkdtemp and its marker write (a milliseconds
        # window, but real), while a gate longer than the age-based
        # reaper's floor would make this sweep pointless for legacy
        # dirs. 24 h covers pre-marker legacy dirs at the reaper's own
        # floor and dwarfs the marker-write window.
        elif now - st.st_mtime < legacy_max_age_s:
            continue

        # In-use probes (live cwd references, answering sockets) guard
        # dirs whose real user outlives the marker pid: a Joern JVM in
        # its own session survives its dead Python parent with the
        # workspace as cwd, and a marker-less dispatcher dir may hold
        # a socket a live process still answers on.
        if live_cwds is None:
            live_cwds = _live_cwds()
        if _dir_in_use(path, live_cwds):
            continue

        # Validation-to-delete identity pin (same as tmp_reaper): a
        # same-uid writer swapping a different entry — or a symlink —
        # into this name between the checks above and the rmtree is
        # skipped this sweep.
        try:
            st2 = path.lstat()
        except OSError:
            continue
        if ((st2.st_dev, st2.st_ino) != (st.st_dev, st.st_ino)
                or not stat.S_ISDIR(st2.st_mode)):
            logger.debug(
                "dead-owner sweep: %s changed identity between "
                "validation and delete; skipping this sweep", path,
            )
            continue
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            removed.append(path)

    if removed:
        logger.info(
            "reclaimed %d orphaned %s* scratch dir(s) from dead owners",
            len(removed), prefix,
        )
    return removed

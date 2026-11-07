"""Canonical workspace for RAPTOR-executed temp artifacts.

RAPTOR compiles and runs small artifacts of its own as part of normal
operation — dark-verify witnesses, dynamic-sweep harnesses, PoC
compile-verification stubs, toolchain probes. When those land at the
top level of the system temp dir, endpoint-security (EDR) products
flag the generic "execution from /tmp" heuristic on every scan. This
module gives every executed artifact ONE documentable home:

    <base>/raptor-<euid>/session-<pid>-<rand>/

That is the exact family the ``bin/raptor`` launcher already
establishes as the per-session ``TMPDIR``, so under the launcher this
module is a no-op: :func:`exec_workdir` returns ``None`` (= "use the
default temp dir") whenever :func:`tempfile.gettempdir` already lies
inside a ``raptor-<euid>`` family dir, and artifact paths are
byte-identical to before. Outside the launcher (direct ``python3
raptor.py``, orchestrator children with a scrubbed environment, CI) it
creates the family dir itself with the launcher's safety posture: 0700
modes, symlink/squat refusal, and a dead-pid sweep of stale sibling
session dirs (the launcher's own sweep reclaims ours too — same name
shape on purpose).

``RAPTOR_WORK_DIR`` overrides ``<base>`` (default: the system temp
dir); the launcher consumes the same variable for its session base, so
one operator setting yields one exclusion prefix either way. See
docs/environment.md for the variable and docs/troubleshooting.md
("Running under endpoint security / EDR") for the operator doctrine.

This changes WHERE RAPTOR's own executed artifacts live, never what
they do: sandbox containment, witness content, and execution semantics
are untouched, and nothing here applies to code from scanned targets.

Import-light by the same convention as :mod:`core.run.tmp_reaper` and
:mod:`core.run.scratch` (no core.config / core.sandbox imports).
"""

from __future__ import annotations

import atexit
import logging
import os
import re
import stat
import tempfile
import threading
from pathlib import Path

from core.atomic_fs import rmtree_hardened

logger = logging.getLogger(__name__)

__all__ = ["exec_workdir"]

#: Session-dir name shape shared with the ``bin/raptor`` launcher —
#: its launch-time sweep matches ``^session-([0-9]+)-[0-9]+$`` and
#: removes entries whose pid is dead, so dirs created here are
#: reclaimed by the next launcher start even if this process is
#: SIGKILLed (atexit never runs on SIGKILL/SIGTERM).
_SESSION_RE = re.compile(r"^session-([0-9]+)-[0-9]+$")

_ENV_VAR = "RAPTOR_WORK_DIR"

_lock = threading.Lock()
_resolved = False
_cached: Path | None = None
_cached_identity: tuple[int, int] | None = None


def _reset_after_fork() -> None:
    # Locks and cached allocations belong to the parent process. A child
    # must neither wait for a vanished thread nor reuse its parent's scratch.
    global _lock, _resolved, _cached, _cached_identity
    _lock = threading.Lock()
    _resolved = False
    _cached = None
    _cached_identity = None


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_after_fork)


def _same_session(path: Path, identity: tuple[int, int] | None) -> bool:
    try:
        info = path.lstat()
    except OSError:
        return False
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and (info.st_dev, info.st_ino) == identity)


def _remove_owned_session(path: Path, identity: tuple[int, int], owner_pid: int) -> None:
    """Exit cleanup may remove only this process's original allocation."""
    if os.getpid() != owner_pid or not _same_session(path, identity):
        return
    try:
        if not rmtree_hardened(path):
            logger.warning("workdir: could not fully remove owned session %s", path)
    except OSError:
        logger.warning("workdir: owned session cleanup failed for %s", path, exc_info=True)


def _family_name() -> str:
    return f"raptor-{os.geteuid()}"


def _inside_family(path: Path) -> bool:
    """True when *path* already lies inside a ``raptor-<euid>`` dir."""
    fam = _family_name()
    return any(part == fam for part in path.parts)


def _sweep_dead_sessions(root: Path) -> None:
    """Remove sibling ``session-<pid>-<rand>`` dirs whose pid is dead.

    Mirrors the launcher's launch-time sweep (lstat-only, never follows
    symlinks, same-owner only). pid reuse merely delays cleanup one
    cycle — the safe direction. Directories carrying launcher metadata
    belong to the session lifecycle and must never be reclaimed here.
    Best-effort throughout.
    """
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for entry in entries:
        m = _SESSION_RE.match(entry.name)
        if m is None:
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if not entry.is_dir(follow_symlinks=False):
            continue
        if st.st_uid != os.geteuid():
            continue
        # Reserve any metadata entry for the launcher/session lifecycle,
        # including partial, invalid or dangling entries. Never follow it or
        # interpret an inspection failure as permission to delete scratch.
        try:
            os.lstat(os.path.join(entry.path, "metadata"))
        except FileNotFoundError:
            pass  # Legacy workdir without a session-lifecycle marker.
        except OSError:
            continue
        else:
            continue
        pid = int(m.group(1))
        if pid == os.getpid():
            continue
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OverflowError):
            # dead — or a pid beyond pid_t (a planted huge-digit dir
            # name), which no live process can hold; reclaim below.
            # OverflowError is not an OSError and crashed the sweep.
            pass
        except OSError:
            continue      # EPERM etc.: someone lives there; skip
        else:
            continue      # alive; skip
        rmtree_hardened(entry.path)


def _create_session_dir() -> tuple[Path, tuple[int, int]] | None:
    base = os.environ.get(_ENV_VAR, "").strip() or tempfile.gettempdir()
    root = Path(base) / _family_name()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        logger.debug("workdir: cannot create %s (%s)", root, exc)
        return None
    # Squat check, same as the launcher: mkdir exist_ok "succeeds" on
    # an attacker-created dir. Refuse symlinks and foreign owners and
    # fall back to the default temp dir (today's behaviour) instead.
    try:
        st = os.lstat(root)
    except OSError:
        return None
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) \
            or st.st_uid != os.geteuid():
        logger.debug(
            "workdir: %s is not a directory owned by this user — "
            "falling back to the default temp dir", root,
        )
        return None
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    _sweep_dead_sessions(root)
    for _ in range(5):
        # All-digits suffix on purpose: the launcher sweep only
        # reclaims names matching ``session-<digits>-<digits>``.
        candidate = root / (
            f"session-{os.getpid()}-"
            f"{int.from_bytes(os.urandom(4), 'big') % 10**9}"
        )
        try:
            candidate.mkdir(mode=0o700)
        except FileExistsError:
            continue
        except OSError as exc:
            logger.debug("workdir: cannot create %s (%s)", candidate, exc)
            return None
        # Pin the allocation before handing it to the cache or exit handler.
        # A failed registration must not strand newly allocated scratch.
        identity = None
        try:
            info = candidate.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid():
                return None
            identity = (info.st_dev, info.st_ino)
            atexit.register(_remove_owned_session, candidate, identity, os.getpid())
        except BaseException:
            # lstat itself may fail; only a confirmed identity permits removal.
            if identity is not None:
                try:
                    _remove_owned_session(candidate, identity, os.getpid())
                except BaseException:
                    logger.warning("workdir: allocation rollback failed for %s", candidate,
                                   exc_info=True)
            raise
        if not _same_session(candidate, identity):
            return None
        return candidate, identity
    return None


def exec_workdir() -> Path | None:
    """Parent directory for RAPTOR-executed temp artifacts, or ``None``.

    ``None`` means "use the default temp dir" and is returned when
    :func:`tempfile.gettempdir` already lies inside the
    ``raptor-<euid>`` family (the ``bin/raptor`` launcher's per-session
    ``TMPDIR``) or when the family dir cannot be created safely — both
    preserve today's behaviour exactly. Callers pass the result
    straight to the ``dir=`` parameter of :mod:`tempfile` factories::

        with tempfile.TemporaryDirectory(
            prefix="raptor_dyn_", dir=exec_workdir(),
        ) as tmpdir:
            ...

    The resolved value is cached per process while its directory identity
    remains unchanged. Forked children allocate independently; exit cleanup
    removes only the creating process's original allocation.
    """
    global _resolved, _cached, _cached_identity
    # Temp-root placement advisory (WSL): every executed-artifact
    # temp resolution funnels through here, making it the second
    # entry chokepoint (with core.run.scratch.scratch_dir) for the
    # per-process drvfs/9p temp-root warning. Probes the base THIS
    # module resolves — RAPTOR_WORK_DIR when set, else gettempdir()
    # (the same precedence _create_session_dir applies) — so a
    # WORK_DIR pointed at a Windows-interop mount warns even when
    # TMPDIR is clean. Latched in core.startup.wsl; free off WSL.
    # Fires whether or not the launcher family dir is in play —
    # either way the resolved base is the root artifacts land on.
    from core.startup.wsl import warn_tmpdir_windows_interop
    warn_tmpdir_windows_interop(
        os.environ.get(_ENV_VAR, "").strip() or None,
    )
    with _lock:
        # A cached dir someone removed mid-run must not surface as a
        # tempfile failure downstream — drop the cache and re-resolve.
        if _resolved and _cached is not None and not _same_session(_cached, _cached_identity):
            _resolved = False
            _cached = None
            _cached_identity = None
        if not _resolved:
            if _inside_family(Path(tempfile.gettempdir()).resolve()):
                _cached = None
            else:
                allocation = _create_session_dir()
                if allocation is not None:
                    _cached, _cached_identity = allocation
                else:
                    _cached = None
                    _cached_identity = None
            _resolved = True
        return _cached

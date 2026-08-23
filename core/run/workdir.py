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
import shutil
import stat
import tempfile
import threading
from pathlib import Path

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
    cycle — the safe direction. Best-effort throughout.
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
        pid = int(m.group(1))
        if pid == os.getpid():
            continue
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            pass          # dead — reclaim below
        except OSError:
            continue      # EPERM etc.: someone lives there; skip
        else:
            continue      # alive; skip
        shutil.rmtree(entry.path, ignore_errors=True)


def _create_session_dir() -> Path | None:
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
        atexit.register(shutil.rmtree, str(candidate), ignore_errors=True)
        return candidate
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

    The resolved value is cached for the life of the process (one
    session dir per process, like the launcher's one per session).
    """
    global _resolved, _cached
    with _lock:
        # A cached dir someone removed mid-run must not surface as a
        # tempfile failure downstream — drop the cache and re-resolve.
        if _resolved and _cached is not None and not _cached.is_dir():
            _resolved = False
            _cached = None
        if not _resolved:
            if _inside_family(Path(tempfile.gettempdir()).resolve()):
                _cached = None
            else:
                _cached = _create_session_dir()
            _resolved = True
        return _cached

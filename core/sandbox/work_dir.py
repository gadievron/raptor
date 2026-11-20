"""Work-subdirectory convention for hostile children sharing a run dir.

A run directory ROOT is parent-attributed state: ``.raptor-run.json``,
findings files, coverage manifests and trust markers all live there,
and the parent re-reads them after the child exits. Passing a HOSTILE
child ``output=<run-root>`` grants it write access to every one of
those artifacts — the child can rewrite the run's recorded outcome or
plant oversized/malformed artifacts for the parent-side readers.

The convention split:

* Hostile lanes (target binaries, PoC drivers, target build scripts)
  write into a dedicated work subdirectory created here — the run
  root stays parent-owned.
* Trusted-agent lanes whose contract IS "write run artifacts"
  (Claude Code dispatches producing the run's own outputs)
  acknowledge the grant with ``output_run_root_ok=True`` on the
  ``sandbox()`` / ``run()`` / ``run_untrusted*`` call.

:func:`is_run_root` is the content-based detection the ``sandbox()``
seam warning uses; :func:`hostile_work_subdir` mints the subdirectory
a hostile call site should pass as ``output=``.
"""

from __future__ import annotations

import os
import re
import stat
import threading
from pathlib import Path

from core.run.metadata import RUN_METADATA_FILE

from ._fake_home import _DIR_FLAGS, _open_directory
from ._pathpin import canonical_bind_path

__all__ = ["WORK_SUBDIR_PREFIX", "adopt_subdir_identity",
           "exported_subdir_identity", "hostile_work_subdir",
           "is_run_root", "verified_subdir_identity"]

#: Every work subdirectory carries this prefix so run-dir consumers
#: (artifact walkers, cleanup) can recognise child scratch space.
WORK_SUBDIR_PREFIX = "work-"

#: Lane labels are code-authored constants, never target-derived:
#: a strict charset keeps the minted path shell- and log-safe and
#: forecloses traversal ("." / ".." cannot match).
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")

#: Verified-identity registry: canonical bind path of a minted work
#: subdir → (verification-time walk path, st_dev, st_ino) of the
#: fd-verified directory. The spawn layer's bind-source pin step
#: (``core.sandbox._spawn._pin_bind_sources``) consults this so a
#: symlink swapped in AFTER :func:`hostile_work_subdir` returned is
#: refused at pin time instead of being followed by a fresh
#: ``realpath``. Lock discipline mirrors ``core.sandbox.state``:
#: brief holds around every read/write.
_identity_lock = threading.Lock()
_verified_subdirs: dict[str, tuple[str, int, int]] = {}


def verified_subdir_identity(
        canonical_path: str) -> tuple[str, int, int] | None:
    """Recorded identity for a work subdir minted by
    :func:`hostile_work_subdir`, keyed by its canonical bind path
    (``core.sandbox._pathpin.canonical_bind_path``).

    Returns ``(walk_path, st_dev, st_ino)`` — the symlink-resolved
    path the verification walked (resolved BEFORE the fd-verified
    creation, so pinning along it refuses any later-planted symlink
    with ELOOP) and the verified directory's inode identity — or
    ``None`` for paths this module never minted.
    """
    with _identity_lock:
        return _verified_subdirs.get(canonical_path)


def exported_subdir_identity(
        work: str | os.PathLike[str]) -> dict[str, str | int] | None:
    """JSON-safe identity record for a minted work subdir, for
    shipping across a process boundary.

    The registry is process-local, but the pin step that consults it
    may run in a DIFFERENT process: the netns coordinator receives
    ``output=<work subdir>`` over its request pipe and calls
    ``sandbox_run`` in a fresh interpreter, where an unseeded registry
    would silently fall back to the realpath walk — the exact
    swapped-symlink window :func:`hostile_work_subdir` exists to
    close. The minting parent ships this record alongside the path and
    the receiver seeds its registry with
    :func:`adopt_subdir_identity`.

    Returns ``None`` for paths this process never minted.
    """
    key = canonical_bind_path(os.fspath(work))
    identity = verified_subdir_identity(key)
    if identity is None:
        return None
    walk_path, st_dev, st_ino = identity
    return {"path": key, "walk_path": walk_path,
            "st_dev": st_dev, "st_ino": st_ino}


def adopt_subdir_identity(identity: object) -> str:
    """Seed the registry from a TRUSTED parent's exported identity
    (:func:`exported_subdir_identity`), returning the registry key.

    Trust boundary: the record must arrive over a channel only the
    minting parent writes (the coordinator's request pipe) — a
    registered identity steers the pin step's WALK, so an attacker
    who could inject one would choose the walk path. It cannot
    weaken an already-registered path (the seed verifies nothing
    itself; ``_pin_one_source`` still fstat-matches the pinned inode
    against the shipped dev/ino and refuses with the tamper errno on
    mismatch), but it must never be fed target-derived data.

    Raises ``ValueError`` on any malformed record — a shape drift
    between exporter and adopter must fail the spawn loudly, never
    degrade to the realpath fallback.
    """
    if not isinstance(identity, dict):
        msg = ("adopt_subdir_identity: identity must be a dict, got "
               f"{type(identity).__name__}")
        raise ValueError(msg)
    path = identity.get("path")
    walk_path = identity.get("walk_path")
    st_dev = identity.get("st_dev")
    st_ino = identity.get("st_ino")
    for name, value in (("path", path), ("walk_path", walk_path)):
        if (not isinstance(value, str)
                or value != canonical_bind_path(value)):
            msg = (f"adopt_subdir_identity: {name!r} must be a "
                   f"canonical absolute path")
            raise ValueError(msg)
    for name, value in (("st_dev", st_dev), ("st_ino", st_ino)):
        if type(value) is not int or value < 0:
            msg = (f"adopt_subdir_identity: {name!r} must be a "
                   f"non-negative int, got {type(value).__name__}")
            raise ValueError(msg)
    with _identity_lock:
        _verified_subdirs[path] = (walk_path, st_dev, st_ino)
    return path


def is_run_root(path: str | os.PathLike[str]) -> bool:
    """Return True when *path* is a run-directory root.

    Content-based: a run root is exactly a directory carrying the run
    metadata marker (``.raptor-run.json``). Unreadable or malformed
    paths answer False — detection feeds a warning, never a refusal.
    """
    try:
        return os.path.isfile(
            os.path.join(os.fspath(path), RUN_METADATA_FILE))
    except (OSError, ValueError, TypeError):
        return False


def hostile_work_subdir(run_root: str | os.PathLike[str],
                        label: str) -> Path:
    """Create (0o700) and return the work subdir for a hostile lane.

    ``label`` names the lane (e.g. ``"target"``) and must be a
    code-authored constant matching ``[A-Za-z0-9][A-Za-z0-9._-]*``
    (max 64 chars) — never target-derived text. The subdirectory is
    ``<run_root>/work-<label>``.

    Symlink defence mirrors ``core.sandbox._fake_home.prepare_home``:
    a prior sandboxed child holding the run-root write grant could
    replace the work subdir with a symlink so parent-side file
    operations land outside the run dir — and it can re-plant at any
    instant, so an advisory ``lstat`` before ``mkdir`` proves nothing
    about what ``mkdir`` then operated on. The materialisation is
    therefore fd-anchored end to end: the run root is walked with
    O_DIRECTORY|O_NOFOLLOW dir fds, the subdir is created and opened
    through the pinned parent fd, and the opened fd is fstat-verified
    (directory, owned by this euid, mode 0o700 — re-asserted via
    ``fchmod`` on the fd when a pre-existing owned dir drifted).
    Anything pre-existing that is not a plain owned directory refuses
    with ``ValueError`` — including a regular file raced in under the
    mkdir, which must never escape as ``FileExistsError``.

    The verified identity is recorded for the spawn layer's pin step
    (see :func:`verified_subdir_identity`).
    """
    if not _LABEL_RE.fullmatch(label):
        msg = (
            f"hostile_work_subdir: invalid lane label {label!r} — "
            f"labels are code-authored constants matching "
            f"[A-Za-z0-9][A-Za-z0-9._-]* (max 64 chars)"
        )
        raise ValueError(msg)
    work = Path(run_root) / f"{WORK_SUBDIR_PREFIX}{label}"
    name = work.name

    def _refuse(detail: str) -> ValueError:
        return ValueError(
            f"hostile_work_subdir refuses to materialise: "
            f"{str(work)!r} {detail}. A prior sandboxed process "
            f"may have replaced it to redirect parent-side file "
            f"operations. Clean the run dir or use a fresh one."
        )

    # realpath BEFORE the pinned walk (the _pathpin contract): benign
    # pre-existing symlinks in the run-root ancestry resolve here, and
    # any symlink appearing after this point refuses mid-walk.
    parent_real = os.path.realpath(os.fspath(run_root))
    parent_fd = _open_directory(parent_real)
    work_fd = -1
    try:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            # Something already sits at the name — a prior mint, or a
            # planted entry. Never trust the name: the fd open +
            # fstat below is the only verification.
            pass
        try:
            work_fd = os.open(name, _DIR_FLAGS, dir_fd=parent_fd)
        except OSError as exc:
            # ELOOP (symlink), ENOTDIR/ENOENT (regular file / raced
            # unlink): every planted shape lands here, converted to
            # the module's refusal type so callers that catch
            # ValueError never see a raw FileExistsError/OSError.
            raise _refuse(
                "exists but is not a regular directory "
                f"({exc.strerror or exc.__class__.__name__})") from exc
        st = os.fstat(work_fd)
        if not stat.S_ISDIR(st.st_mode):
            raise _refuse("exists but is not a regular directory")
        if st.st_uid != os.geteuid():
            raise _refuse(
                f"is owned by uid {st.st_uid}, not this process "
                f"(euid {os.geteuid()})")
        if stat.S_IMODE(st.st_mode) != 0o700:
            # Pre-existing owned dir with drifted bits: re-assert via
            # the verified fd, never the name.
            try:
                os.fchmod(work_fd, 0o700)
            except OSError as exc:
                raise _refuse(
                    "exists with mode "
                    f"0o{stat.S_IMODE(st.st_mode):o} that cannot be "
                    "re-asserted to 0o700") from exc
            st = os.fstat(work_fd)
            if stat.S_IMODE(st.st_mode) != 0o700:
                raise _refuse(
                    "did not hold mode 0o700 after fchmod "
                    f"(mode=0o{stat.S_IMODE(st.st_mode):o})")
        with _identity_lock:
            _verified_subdirs[canonical_bind_path(os.fspath(work))] = (
                os.path.join(parent_real, name), st.st_dev, st.st_ino)
    finally:
        if work_fd >= 0:
            try:
                os.close(work_fd)
            finally:
                os.close(parent_fd)
        else:
            os.close(parent_fd)
    return work

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
from pathlib import Path

from core.run.metadata import RUN_METADATA_FILE

__all__ = ["WORK_SUBDIR_PREFIX", "hostile_work_subdir", "is_run_root"]

#: Every work subdirectory carries this prefix so run-dir consumers
#: (artifact walkers, cleanup) can recognise child scratch space.
WORK_SUBDIR_PREFIX = "work-"

#: Lane labels are code-authored constants, never target-derived:
#: a strict charset keeps the minted path shell- and log-safe and
#: forecloses traversal ("." / ".." cannot match).
_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")


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

    Symlink defence mirrors the fake-home materialisation in
    :mod:`core.sandbox.context`: a prior sandboxed child holding the
    run-root write grant could have replaced the work subdir with a
    symlink so THIS parent-side mkdir/chmod lands outside the run
    dir. Anything pre-existing that is not a plain directory refuses
    with ``ValueError``.
    """
    if not _LABEL_RE.fullmatch(label):
        msg = (
            f"hostile_work_subdir: invalid lane label {label!r} — "
            f"labels are code-authored constants matching "
            f"[A-Za-z0-9][A-Za-z0-9._-]* (max 64 chars)"
        )
        raise ValueError(msg)
    work = Path(run_root) / f"{WORK_SUBDIR_PREFIX}{label}"
    try:
        st = os.lstat(work)
    except FileNotFoundError:
        pass
    else:
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
            msg = (
                f"hostile_work_subdir refuses to materialise: "
                f"{str(work)!r} exists but is not a regular directory "
                f"(mode=0o{st.st_mode:o}). A prior sandboxed process "
                f"may have replaced it to redirect parent-side file "
                f"operations. Clean the run dir or use a fresh one."
            )
            raise ValueError(msg)
    work.mkdir(mode=0o700, exist_ok=True)
    return work

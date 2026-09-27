"""Executable staging for run-dir artifacts.

Env-built artifacts are extracted mode 0444 (``core/env/build.py``
strips execute/setuid/setgid: the bytes came from the attacker's
build, and the run dir must never hold an executable file). The
dynamic tier is allowed to RUN those bytes — but only behind its
explicit consent gates and inside the sandbox. This module bridges
the two invariants: at the consented exec point, stage a private
0o500 copy in a fresh owner-only temp dir and exec the copy. The
original artifact and the run dir stay non-executable throughout;
without the staging step the sandbox child's execve fails EACCES,
which the spawn layer reports as a per-invocation spawn failure
("X: exec: permission denied") and the whole dynamic probe degrades.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from core.run.workdir import exec_workdir


@contextmanager
def executable_stage(binary_path: str | os.PathLike) -> Iterator[Path]:
    """Yield a runnable path for *binary_path*.

    An already-executable file — a self-compiled harness, an
    operator-supplied binary — is yielded unchanged, as is anything
    that is not a regular file (the caller's existing missing-binary
    handling stays authoritative). A non-executable regular file (the
    env-built 0444 shape) is copied into a fresh ``mkdtemp``-private
    directory with mode 0o500 and the copy is yielded; everything is
    removed when the context exits. The copy keeps the original
    basename: address-space consumers match ``/proc/<pid>/maps``
    entries by name.

    The staging dir lives under :func:`core.run.workdir.exec_workdir`
    (executable even when the system tmp is mounted noexec, swept with
    the session); the ``raptor-exec-stage-`` prefix is additionally
    reaper-registered so the default-temp-dir fallback cannot strand
    an executable copy past a SIGKILL.
    """
    p = Path(binary_path)
    if not p.is_file() or os.access(p, os.X_OK):
        yield p
        return
    with tempfile.TemporaryDirectory(
            prefix="raptor-exec-stage-", dir=exec_workdir()) as td:
        staged = Path(td) / p.name
        shutil.copy2(p, staged)
        staged.chmod(0o500)
        yield staged

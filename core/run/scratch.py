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
from collections.abc import Iterator, MutableMapping
from pathlib import Path

logger = logging.getLogger(__name__)

__all__ = ["scratch_dir"]


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
        os.makedirs(parent, exist_ok=True)
    else:
        # Same-process backstop: a long-lived orchestrator's next
        # start_run sweep can reclaim strays with this prefix.
        from core.run import tmp_reaper
        tmp_reaper.register_dir_prefix(prefix)
    path = Path(tempfile.mkdtemp(prefix=prefix, dir=parent))
    if env is not None:
        env["TMPDIR"] = str(path)
    try:
        yield path
    finally:
        if not keep:
            shutil.rmtree(path, ignore_errors=True)

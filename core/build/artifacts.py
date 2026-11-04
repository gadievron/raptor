"""Best-effort teardown of caller-owned synthesized build artifacts."""

import stat
from pathlib import Path

from core.atomic_fs import rmtree_hardened
from core.logging import get_logger

logger = get_logger()


def cleanup_build_paths(paths: list[Path]) -> None:
    """Remove owned nodes without following links; retain failures for retry.

    Build subprocesses can leave restricted directories or replace a script
    with another node type. Only real directories need recursive removal;
    symlinks and special files are unlinked directly. Missing paths count as
    cleaned. OS failures must neither mask the workflow error nor prevent the
    remaining artifacts from being reclaimed.
    """
    remaining = []
    for path in paths:
        try:
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if stat.S_ISDIR(info.st_mode):
                if not rmtree_hardened(path):
                    remaining.append(path)
                    logger.warning("Build artifact cleanup incomplete: %r", path)
            else:
                path.unlink(missing_ok=True)
        except OSError as exc:
            remaining.append(path)
            logger.warning("Build artifact cleanup failed for %r: %s", path, exc)
    paths[:] = remaining

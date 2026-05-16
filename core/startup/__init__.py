import os
from pathlib import Path

# core/startup/__init__.py → core/ → raptor/ (repo root)
REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = Path.home() / ".raptor" / "projects"
ACTIVE_LINK = PROJECTS_DIR / ".active"


def get_active_name():
    """Read active project name from .active symlink, or None.

    Lightweight — no ProjectManager import.

    TOCTOU-safe: pre-fix the function did `is_symlink()` then
    `readlink()`, then `(PROJECTS_DIR/target).exists()`. Each gap
    between checks is a window where another process can flip the
    symlink target or delete it; the original guards then either
    (a) returned a stale name when the file was concurrently
    deleted, or (b) crashed with `OSError` when the symlink was
    deleted between `is_symlink()` and `readlink()`.

    Restructure: call `os.readlink` first and catch `OSError`
    (covers both not-a-symlink and deleted-between-checks). Skip
    the existence pre-check — the caller's next operation against
    the project file is itself the authoritative test, and the
    pre-check just adds a TOCTOU window that doesn't buy any
    safety.
    """
    try:
        target = os.readlink(ACTIVE_LINK)
    except OSError:
        return None
    if target.endswith(".json") and "/" not in target and "\\" not in target:
        return target[:-5]
    return None

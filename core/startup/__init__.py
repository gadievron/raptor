import os
from pathlib import Path

# core/startup/__init__.py → core/ → raptor/ (repo root)
REPO_ROOT = Path(__file__).resolve().parents[2]
PROJECTS_DIR = Path.home() / ".raptor" / "projects"
ACTIVE_LINK = PROJECTS_DIR / ".active"


def get_active_name():
    """Read active project name from .active symlink, or None.

    Lightweight — no ProjectManager import.
    """
    if not ACTIVE_LINK.is_symlink():
        return None
    target = os.readlink(ACTIVE_LINK)
    if target.endswith(".json") and "/" not in target and "\\" not in target:
        if (PROJECTS_DIR / target).exists():
            return target[:-5]
    return None

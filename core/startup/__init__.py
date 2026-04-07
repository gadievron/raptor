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


def sync_project_env_file():
    """Write current RAPTOR_PROJECT_* env vars to CLAUDE_ENV_FILE.

    Preserves non-project lines. Removes project lines if no project is active.
    """
    env_file = os.environ.get("CLAUDE_ENV_FILE")
    if not env_file:
        return

    env_path = Path(env_file)
    try:
        existing = env_path.read_text() if env_path.exists() else ""
    except OSError:
        return

    lines = [l for l in existing.splitlines()
             if not l.startswith("export RAPTOR_PROJECT_")]

    project_dir = os.environ.get("RAPTOR_PROJECT_DIR")
    if project_dir:
        def _sh(v):
            return v.replace('\\', '\\\\').replace('"', '\\"')
        lines.append(f'export RAPTOR_PROJECT_DIR="{_sh(project_dir)}"')
        lines.append(f'export RAPTOR_PROJECT_NAME="{_sh(os.environ.get("RAPTOR_PROJECT_NAME", ""))}"')
        lines.append(f'export RAPTOR_PROJECT_TARGET="{_sh(os.environ.get("RAPTOR_PROJECT_TARGET", ""))}"')

    try:
        env_path.write_text("\n".join(lines) + "\n" if lines else "")
    except OSError:
        pass

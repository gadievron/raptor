"""Output directory resolution.

Centralises the logic for choosing where a command writes its output.
Checks (in order): explicit --out argument, active project, default out/ dir.
"""

import logging
import os
import time
from pathlib import Path
from typing import Optional, Tuple

from core.config import RaptorConfig

logger = logging.getLogger(__name__)


class TargetMismatchError(ValueError):
    """Raised when the scan target differs from the active project's target."""
    pass


def _resolve_active_project() -> Optional[Tuple[str, str, str]]:
    """Resolve the current active project from the .active symlink.

    Returns (output_dir, name, target) or None if no project is active.
    The symlink is the single source of truth — no env var fallback.
    """
    try:
        from core.project.project import ProjectManager
        mgr = ProjectManager()
        active_name = mgr.get_active()
        if active_name:
            project = mgr.load(active_name)
            if project:
                return project.output_dir, project.name, project.target
    except Exception:
        pass

    return None


def get_output_dir(command: str, target_name: str = "", explicit_out: str = None,
                   target_path: str = None) -> Path:
    """Resolve the output directory for a command run.

    Priority:
    1. explicit_out (from --out argument) — used as-is, no project check
    2. Active project (.active symlink, then env var) — timestamped subdir
    3. Default: RaptorConfig.get_out_dir() with command prefix + timestamp

    Args:
        command: Command name (scan, agentic, validate, etc.)
        target_name: Target name for directory naming (e.g. repo name)
        explicit_out: Explicit output path from --out argument
        target_path: Actual path being analyzed (for project target validation)

    Returns:
        Path to the output directory (not yet created).

    Raises:
        TargetMismatchError: If target_path is outside the active project's target.
    """
    if explicit_out:
        active = _resolve_active_project()
        if active:
            logger.warning("--out overrides active project '%s' output directory", active[1])
        return Path(explicit_out).resolve()

    active = _resolve_active_project()

    if active:
        project_dir, project_name, project_target = active

        # Validate target matches the project
        effective_target = target_path or os.environ.get("RAPTOR_CALLER_DIR")
        if effective_target and project_target:
            _check_target_mismatch(effective_target, project_name, project_target)

        # Project mode: command-YYYYMMDD-HHMMSS (hyphens throughout)
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        return Path(project_dir) / f"{command}-{timestamp}"

    # Standalone mode: command_target_timestamp (underscores, backwards
    # compatible with existing directories created before project support)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    if target_name:
        dirname = f"{command}_{target_name}_{timestamp}"
    else:
        dirname = f"{command}_{timestamp}"

    return RaptorConfig.get_out_dir() / dirname


def _check_target_mismatch(target_path: str, project_name: str,
                           project_target: str) -> None:
    """Raise TargetMismatchError if target is outside the active project's target."""
    resolved = Path(target_path).resolve()
    project_resolved = Path(project_target).resolve()

    # Exact match or subdirectory — OK
    try:
        resolved.relative_to(project_resolved)
        return
    except ValueError:
        pass

    raise TargetMismatchError(
        f"target {resolved} is outside project {project_name} ({project_resolved})\n"
        f"  A project tracks one target. To analyze a different codebase:\n"
        f"    /project create <name> --target {resolved}\n"
        f"    /project use none"
    )

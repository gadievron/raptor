"""Clean old runs from a project, keeping latest N per command type."""

import shutil
from pathlib import Path
from typing import Any, Dict, List


def plan_clean(project, keep=1) -> Dict[str, Any]:
    """Plan which runs to delete. Returns stats with directory paths.

    Does not modify the filesystem.
    """
    if keep < 1:
        raise ValueError(f"keep must be >= 1, got {keep}")
    groups = project.get_run_dirs_by_type()
    stats: Dict[str, Any] = {
        "delete_dirs": [], "deleted": [], "kept": [], "freed_bytes": 0,
        "by_type": {},
    }

    for cmd_type, dirs in groups.items():
        to_keep = dirs[:keep]
        to_delete = dirs[keep:]
        type_freed = 0

        for d in to_keep:
            stats["kept"].append(d.name)

        for d in to_delete:
            size = sum(
                f.stat().st_size for f in d.rglob("*")
                if f.is_file() and not f.is_symlink()
            )
            stats["freed_bytes"] += size
            type_freed += size
            stats["delete_dirs"].append(d)
            stats["deleted"].append(d.name)

        stats["by_type"][cmd_type] = {
            "total": len(dirs),
            "keep": len(to_keep),
            "delete": len(to_delete),
            "freed_bytes": type_freed,
        }

    return stats


def execute_clean(plan: Dict[str, Any]) -> None:
    """Execute a clean plan by deleting the planned directories."""
    for d in plan["delete_dirs"]:
        if d.exists():
            shutil.rmtree(d)


def clean_project(project, keep=1, dry_run=False) -> Dict[str, Any]:
    """Clean old runs from a project. Returns stats dict.

    Keeps latest `keep` runs per command type.
    Convenience wrapper around plan_clean + execute_clean.
    """
    stats = plan_clean(project, keep=keep)
    if not dry_run:
        execute_clean(stats)
    return stats

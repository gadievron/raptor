"""Clean old runs from a project, keeping latest N per command type."""

import os
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
            # `Path.rglob` follows symlinks under Python <3.13 with no
            # opt-out; a malicious or accidental symlink under the run
            # dir (e.g. `out/run-X/incoming -> /var/log`) would walk
            # into and stat-sum unrelated trees, double-counting bytes
            # and (worse) reading from arbitrary file descriptors. Use
            # os.walk(followlinks=False) so we stay inside the run dir
            # tree on every supported Python version.
            size = 0
            for root, _dirs, files in os.walk(d, followlinks=False):
                for fname in files:
                    fp = Path(root) / fname
                    try:
                        st = fp.stat()
                    except OSError:
                        continue
                    if not fp.is_symlink():
                        size += st.st_size
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
    """Execute a clean plan by deleting the planned directories.

    Per-dir containment check before delete: refuse to rmtree any
    path that resolves outside the project's expected output area.
    Pre-fix `execute_clean` trusted whatever paths the planner
    produced — but `delete_dirs` can be operator-supplied (a future
    `--delete-dirs path1,path2,...` flag) or planner-corrupted (a
    bug elsewhere produces a path with `..` that escapes the
    project root). `shutil.rmtree` would happily walk anywhere
    its argument resolved to.

    Worst case the unguarded rmtree could hit operator data outside
    `~/.raptor/projects/<name>/`. The containment check refuses any
    delete that, after `resolve()`, is not under the plan's expected
    parent (the plan dir is the union of all `delete_dirs`'
    common parent — operator can override with explicit env var
    if their layout has a non-standard root).
    """
    delete_dirs = plan["delete_dirs"]
    if not delete_dirs:
        return
    # The expected containment root is the closest common ancestor
    # of all paths in `delete_dirs`. A delete that resolves outside
    # that ancestor is almost certainly a bug.
    try:
        roots = [Path(d).resolve().parent for d in delete_dirs]
        common = Path(os.path.commonpath([str(r) for r in roots]))
    except (OSError, ValueError):
        common = None
    for d in delete_dirs:
        if not d.exists():
            continue
        try:
            real = Path(d).resolve()
        except OSError:
            continue
        if common is not None:
            try:
                real.relative_to(common)
            except ValueError:
                # Resolved path escapes the common parent. Refuse.
                raise RuntimeError(
                    f"execute_clean refusing to rmtree {d!r}: resolved "
                    f"path {real!r} escapes containment root {common!r}"
                )
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

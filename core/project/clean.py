"""Clean old runs from a project, keeping latest N per command type."""

import os
import shutil
from pathlib import Path
from typing import Any


def _run_dir_size(d: Path) -> int:
    # `Path.rglob` follows symlinks under Python <3.13 with no opt-out; a
    # malicious or accidental symlink under the run dir (e.g.
    # `out/run-X/incoming -> /var/log`) would walk into and stat-sum
    # unrelated trees, double-counting bytes and (worse) reading from
    # arbitrary file descriptors. Use os.walk(followlinks=False) so we stay
    # inside the run dir tree on every supported Python version.
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
    return size


def run_is_live(d: Path) -> bool:
    """Is *d* a run some in-flight process still owns?

    A run is *live* when its metadata says ``status=running`` AND
    either its recorded tool worker OR its owning SESSION is still
    alive — deleting, merging, or renaming it would yank the directory
    out from under an in-flight process. The session leg matters for
    lifecycle-stub runs: their ``tool_pid`` is the stub's shell,
    dead seconds after start while the run's work continues across
    later tool calls — the run-start contention gate keys on session
    liveness, and this predicate must not diverge from it (a run the
    gate refuses to start next to must not be deletable). Runs whose
    worker AND session are both dead are stale abandons; the sweep
    machinery marks them failed, and clean may reclaim them.

    Runs that recorded NO pids at all (pre-recording legacy metadata)
    are unjudgeable by liveness: they get a grace-age gate — recent
    write activity inside the run dir reads as live — instead of
    falling open to deletable.
    """
    from core.json import load_json
    from core.run.metadata import (
        RUN_METADATA_FILE,
        _run_recently_active,
        _session_alive_for_meta,
        _tool_pid_alive,
    )
    try:
        meta = load_json(Path(d) / RUN_METADATA_FILE,
                         max_bytes=1024 * 1024)
    except Exception:  # noqa: BLE001 — unreadable metadata is not live
        meta = None
    if not (isinstance(meta, dict) and meta.get("status") == "running"):
        return False
    if (_tool_pid_alive(meta.get("tool_pid"))
            or _session_alive_for_meta(meta)):
        return True
    if meta.get("session_pid") is None and meta.get("tool_pid") is None:
        return _run_recently_active(Path(d))
    return False


def split_live_runs(dirs) -> tuple[list, list]:
    """Partition run dirs into ``(rest, live)`` — see :func:`run_is_live`."""
    live: list = []
    rest: list = []
    for d in dirs:
        (live if run_is_live(Path(d)) else rest).append(d)
    return rest, live


def plan_clean(project, keep: int=1) -> dict[str, Any]:
    """Plan which runs to delete. Returns stats with directory paths.

    ``keep=0`` is valid: delete as aggressively as possible, bounded by the
    clean-safety invariant that the last (newest) run of each command type is
    never deleted (design: project.md). The durable coverage store retains the
    verdicts of deleted runs (clean/examined coverage is snapshotted before
    deletion; sole-source findings flip to ``found_then_lost``).
    Does not modify the filesystem.
    """
    if keep < 0:
        msg = f"keep must be >= 0, got {keep}"
        raise ValueError(msg)
    groups = project.get_run_dirs_by_type()
    stats: dict[str, Any] = {
        "delete_dirs": [], "deleted": [], "kept": [], "freed_bytes": 0,
        "by_type": {}, "skipped_live": [],
    }

    for cmd_type, dirs in groups.items():
        # Never plan a live run (status=running with a live worker)
        # for deletion — it counts as kept, outside the keep quota.
        dirs, live = split_live_runs(dirs)
        for d in live:
            stats["skipped_live"].append(d.name)
            stats["kept"].append(d.name)
        to_keep = dirs[:keep]
        to_delete = dirs[keep:]
        # Clean-safety invariant (project.md): never delete the last run of a
        # command type, even with --keep 0. Preserve the newest (dirs are
        # newest-first) when the keep slice would otherwise empty the type.
        if not to_keep and dirs:
            to_keep, to_delete = dirs[:1], dirs[1:]
        type_freed = 0

        for d in to_keep:
            stats["kept"].append(d.name)

        for d in to_delete:
            size = _run_dir_size(d)
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


def plan_dedup(project) -> dict[str, Any]:
    """Lossless dedup plan: per command type, drop runs fully subsumed (same
    files examined, no unique findings) by a surviving run, keeping the newest
    representative. Same shape as :func:`plan_clean` so the clean machinery
    (coverage snapshot-before-delete, containment-checked execute) is reused.

    Unlike recency-based ``--keep N``, this is provably lossless: only
    duplicates are removed, and the to-be-deleted run's coverage is snapshotted
    into the durable store before deletion. Does not modify the filesystem.
    """
    from core.coverage.clean import dedup_runs

    groups = project.get_run_dirs_by_type()
    stats: dict[str, Any] = {
        "delete_dirs": [], "deleted": [], "kept": [], "freed_bytes": 0,
        "by_type": {}, "skipped_live": [],
    }
    for cmd_type, dirs in groups.items():
        # Never dedup away a live run (status=running with a live
        # worker) — and never let a half-written live run subsume a
        # completed sibling either.
        dirs, live = split_live_runs(dirs)
        for d in live:
            stats["skipped_live"].append(d.name)
            stats["kept"].append(d.name)
        droppable, _ = dedup_runs(dirs)
        drop_set = set(droppable)
        type_freed = 0
        for d in dirs:
            if d in drop_set:
                size = _run_dir_size(d)
                stats["freed_bytes"] += size
                type_freed += size
                stats["delete_dirs"].append(d)
                stats["deleted"].append(d.name)
            else:
                stats["kept"].append(d.name)
        stats["by_type"][cmd_type] = {
            "total": len(dirs),
            "keep": len(dirs) - len(droppable),
            "delete": len(droppable),
            "freed_bytes": type_freed,
        }
    return stats


def execute_clean(plan: dict[str, Any],
                  output_path: Path | None = None) -> None:
    """Execute a clean plan by deleting the planned directories.

    Per-dir containment check before delete: refuse to rmtree any
    path that resolves outside the project's expected output area.
    `delete_dirs` can be operator-supplied (a future
    `--delete-dirs path1,path2,...` flag) or planner-corrupted (a
    bug elsewhere produces a path with `..` that escapes the
    project root). `shutil.rmtree` would happily walk anywhere
    its argument resolved to.

    ``output_path`` is the containment root — the project's output
    directory, passed by the caller that planned against it. Pre-fix
    the root was derived from the delete paths themselves (the
    closest common ancestor of ``delete_dirs``' parents), which is a
    tautology: a plan whose every path pointed at the same wrong tree
    contained itself perfectly. The self-derived ancestor is kept
    only as a fallback for legacy callers that don't pass a root.
    """
    delete_dirs = plan["delete_dirs"]
    if not delete_dirs:
        return
    common = None
    if output_path is not None:
        try:
            common = Path(output_path).resolve()
        except OSError:
            common = None
    if common is None:
        # Legacy fallback: closest common ancestor of the plan's own
        # paths. Weaker (self-referential) but still catches a single
        # corrupted entry escaping its siblings.
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
                # Resolved path escapes the containment root. Refuse.
                msg = (
                    f"execute_clean refusing to rmtree {d!r}: resolved "
                    f"path {real!r} escapes containment root {common!r}"
                )
                raise RuntimeError(msg) from None
        # Liveness re-check immediately before the delete: the plan can
        # be arbitrarily stale by now (an unbounded operator confirm
        # sits between plan and execute, and a planned run can be
        # resumed — or a new one started at the same name — in that
        # gap). A plan-time check alone rmtree'd in-flight runs.
        if run_is_live(Path(d)):
            skipped = plan.setdefault("skipped_live", [])
            name = Path(d).name
            if name not in skipped:
                skipped.append(name)
            continue
        try:
            shutil.rmtree(d)
        except FileNotFoundError:
            pass


def clean_project(project, keep: int=1, dry_run: bool=False) -> dict[str, Any]:
    """Clean old runs from a project. Returns stats dict.

    Keeps latest `keep` runs per command type.
    Convenience wrapper around plan_clean + execute_clean.
    """
    stats = plan_clean(project, keep=keep)
    if not dry_run:
        execute_clean(stats, output_path=project.output_path)
    return stats

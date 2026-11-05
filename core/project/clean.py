"""Clean old runs from a project, keeping latest N per command type."""

import os
import re
import stat
import time
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from core.atomic_fs import rmtree_hardened


def _run_dir_size(d: Path) -> int:
    # Directory-symlink recursion stays off explicitly: `Path.rglob`
    # follows dir symlinks only via 3.13's `recurse_symlinks=True`
    # opt-in (`glob.glob(recursive=True)` is what followed them by
    # default), and a malicious or accidental symlink under the run dir
    # (e.g. `out/run-X/incoming -> /var/log`) walked into would
    # stat-sum unrelated trees, double-counting bytes. Use
    # os.walk(followlinks=False) so we stay inside the run dir tree on
    # every supported Python version.
    size = 0
    for root, _dirs, files in os.walk(d, followlinks=False):
        for fname in files:
            fp = Path(root) / fname
            try:
                st = fp.lstat()
            except OSError:
                continue
            if stat.S_ISREG(st.st_mode):
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

    Runs that recorded no SESSION (bare-shell / detached starts, and
    pre-recording legacy metadata) are not fully judgeable by worker
    liveness alone: they get a grace-age gate — recent write activity
    inside the run dir reads as live — instead of falling open to
    deletable.
    """
    from core.run.metadata import (
        _run_recently_active,
        _session_alive_for_meta,
        load_run_metadata,
        worker_liveness_for_meta,
    )
    try:
        # The budgeted metadata loader — the shared 1 MiB budget stays
        # single-homed in core.run.metadata instead of re-spelled here.
        meta = load_run_metadata(Path(d))
    except Exception:  # noqa: BLE001 — unreadable metadata is not live
        meta = None
    if not (isinstance(meta, dict) and meta.get("status") == "running"):
        return False
    if (worker_liveness_for_meta(meta)[0]
            or _session_alive_for_meta(meta)):
        return True
    session_pid = meta.get("session_pid")
    if session_pid is None or (
        isinstance(session_pid, int)
        and not isinstance(session_pid, bool)
        and session_pid <= 1
    ):
        # No checkable owner: session-less runs (bare shell, legacy
        # pid-less metadata) and legacy DETACHED records
        # (session_pid<=1, written before the recorder refused
        # reparented-to-init pids — owner-LESS, not owner-dead; the
        # orchestrator may still be running). The recorded worker may
        # be a transient stub shell, dead seconds after a healthy
        # start while the run's work continues, and a pid-1 stamp
        # proves nothing either way — so neither may read as deletable
        # on its own. Recent write activity keeps the run live — the
        # same grace the abandon sweep applies.
        return _run_recently_active(Path(d))
    return False


def split_live_runs(dirs) -> tuple[list, list]:
    """Partition run dirs into ``(rest, live)`` — see :func:`run_is_live`."""
    live: list = []
    rest: list = []
    for d in dirs:
        (live if run_is_live(Path(d)) else rest).append(d)
    return rest, live


def _directory_identity(path: Path) -> tuple[int, int] | None:
    try:
        info = path.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(info.st_mode):
        return None
    return info.st_dev, info.st_ino


def _remember_delete(plan: dict[str, Any], path: Path) -> bool:
    identity = _directory_identity(path)
    if identity is None:
        return False
    plan.setdefault("_delete_meta", {})[str(path)] = identity
    return True


def _finish_clean(plan, candidates, deleted, sizes) -> None:
    """Replace prospective counters with completed removals, even on error."""
    removed = set(deleted)
    plan["delete_dirs"] = list(deleted)
    plan["deleted"] = [path.name for path in deleted]
    plan["freed_bytes"] = sum(sizes.values())
    typed = plan.get("_type_dirs", {})
    if typed:
        kept: list[str] = []
        for command, paths in typed.items():
            paths = list(dict.fromkeys(Path(path) for path in paths))
            survivors = [path for path in paths if os.path.lexists(path)]
            victims = [path for path in paths if path in removed]
            kept.extend(path.name for path in survivors)
            plan["by_type"][command] = {
                "total": len(survivors) + len(victims),
                "keep": len(survivors), "delete": len(victims),
                "freed_bytes": sum(sizes[path] for path in victims),
            }
        plan["kept"] = list(dict.fromkeys(kept))
    else:
        kept = list(plan.get("kept", []))
        kept.extend(path.name for path in candidates
                    if path not in removed and os.path.lexists(path))
        plan["kept"] = list(dict.fromkeys(kept))


def eligible_clean_dirs(project, keep: int=1, dedup: bool=False) -> set[Path]:
    """Recheck policy after confirmation; failure permits no deletions.

    This computes eligibility only, without rescanning run byte sizes. The
    executor still intersects it with the confirmed paths and identities.
    """
    try:
        allowed: set[Path] = set()
        for dirs in project.get_run_dirs_by_type().values():
            closed, _ = split_live_runs(dirs)
            if dedup:
                from core.coverage.clean import dedup_runs
                victims, _ = dedup_runs(closed)
            else:
                victims = closed[max(1, keep):]
            allowed.update(Path(path) for path in victims)
        return allowed
    except Exception as exc:  # noqa: BLE001 — retain data on an incomplete census
        import logging
        logging.getLogger(__name__).warning(
            "clean policy revalidation failed; retaining runs (%s)",
            type(exc).__name__)
        return set()


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
        stats.setdefault("_type_dirs", {})[cmd_type] = list(dirs)
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
        to_delete = [d for d in to_delete if _remember_delete(stats, d)]
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
        stats.setdefault("_type_dirs", {})[cmd_type] = list(dirs)
        # Never dedup away a live run (status=running with a live
        # worker) — and never let a half-written live run subsume a
        # completed sibling either.
        dirs, live = split_live_runs(dirs)
        for d in live:
            stats["skipped_live"].append(d.name)
            stats["kept"].append(d.name)
        droppable, _ = dedup_runs(dirs)
        drop_set = {d for d in droppable if _remember_delete(stats, d)}
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
            "keep": len(dirs) - len(drop_set),
            "delete": len(drop_set),
            "freed_bytes": type_freed,
        }
    return stats


def execute_clean(
    plan: dict[str, Any], output_path: Path | None = None, *,
    eligible_dirs: Iterable[Path] | None = None,
    before_delete: Callable[[Path], None] | None = None,
) -> None:
    """Delete confirmed directories and report only completed removals.

    Planner-created plans pin directory identities. An explicit containment
    root must resolve and cannot itself be a victim. Legacy callers without
    a root retain the common-parent fallback. Optional fresh eligibility may
    only shrink the confirmed set; the callback snapshots an accepted run
    immediately before removal. Identity and liveness are checked again
    after the callback. Counters are finalized on partial failures too.
    """
    candidates = list(dict.fromkeys(Path(path) for path in plan["delete_dirs"]))
    deleted: list[Path] = []
    sizes: dict[Path, int] = {}
    if not candidates:
        _finish_clean(plan, candidates, deleted, sizes)
        return
    try:
        if output_path is not None:
            common = Path(output_path).resolve()
        else:
            roots = [path.resolve().parent for path in candidates]
            common = Path(os.path.commonpath([str(root) for root in roots]))
    except (OSError, RuntimeError) as exc:
        raise RuntimeError("execute_clean cannot resolve containment root") from exc
    allowed = None if eligible_dirs is None else {Path(path) for path in eligible_dirs}

    def skipped(key, path):
        names = plan.setdefault(key, [])
        if path.name not in names:
            names.append(path.name)

    def accepted(path, identity):
        if _directory_identity(path) != identity:
            skipped("skipped_changed", path)
            return False
        if run_is_live(path):
            skipped("skipped_live", path)
            return False
        return True

    try:
        for path in candidates:
            if not os.path.lexists(path):
                continue
            try:
                real = path.resolve()
                real.relative_to(common)
            except ValueError:
                raise RuntimeError(
                    f"execute_clean refusing to rmtree {path!r}: "
                    f"outside containment root {common!r}") from None
            except (OSError, RuntimeError):
                skipped("skipped_changed", path)
                continue
            if real == common:
                raise RuntimeError("execute_clean refusing to delete containment root itself")
            if allowed is not None and path not in allowed:
                skipped("skipped_retained", path)
                continue
            identity = plan.get("_delete_meta", {}).get(str(path))
            if identity is None:
                identity = _directory_identity(path)
            if identity is None or not accepted(path, identity):
                continue
            size = _run_dir_size(path)
            if not accepted(path, identity):
                continue
            if before_delete is not None:
                before_delete(path)
                if not accepted(path, identity):
                    continue
            if not rmtree_hardened(path):
                raise OSError(f"could not remove run directory {path}")
            deleted.append(path)
            sizes[path] = size
    finally:
        _finish_clean(plan, candidates, deleted, sizes)


#: safe_cache_name shape: <sanitised-archive-name>-<sha256 hex>.
_SOURCES_ENTRY_RE = re.compile(r"-([0-9a-f]{64})$")

#: Grace window before an unreferenced _sources entry may be swept.
#: Lower bound: a concurrently STARTING run publishes its extraction
#: dir moments before start_run seals the marker that references it —
#: sweeping inside that gap would yank the tree out from under a live
#: run, so the window must comfortably exceed extraction-to-seal
#: (seconds). Upper bound: this is only a leak-tolerance knob — a
#: longer window merely delays reclaim of an orphan by one clean
#: cycle, so generous beats clever. One hour.
_SOURCES_SWEEP_GRACE_SECONDS = 3600


def _referenced_archive_shas(project, delete_dirs) -> set[str]:
    """sha256s the project still references after the clean: every
    surviving run's recorded acquisition stamp, plus the project's own
    target when it is an archive (its extraction is the cache the NEXT
    run and /describe reuse — deleting it would only force a
    re-extract of bytes still on the operator's disk)."""
    from core.run.metadata import load_run_metadata
    from core.run.provenance import run_target

    victims = {Path(d).resolve() for d in delete_dirs}
    shas: set[str] = set()
    for d in project.get_run_dirs(sweep=False):
        try:
            if Path(d).resolve() in victims:
                continue
            stamp = run_target(load_run_metadata(Path(d)))
        except Exception:  # noqa: BLE001
            # An unreadable stamp contributes no sha. Deliberate: a
            # single corrupt run must not pin every cache entry
            # forever, and the worst case of a wrongly-swept entry is
            # a re-extract of archive bytes still on disk — a cache
            # miss, never data loss.
            continue
        if isinstance(stamp, dict):
            sha = stamp.get("archive_sha256")
            if isinstance(sha, str) and sha:
                shas.add(sha)
    try:
        target = getattr(project, "target", None)
        if target and Path(target).is_file():
            from core.run.provenance import archive_snapshot
            snap = archive_snapshot(target)
            if snap is not None:
                shas.add(snap["archive_sha256"])
    except Exception:  # noqa: BLE001 — best-effort retention widening
        pass
    return shas


def plan_sources_sweep(project, delete_dirs=()) -> dict[str, Any]:
    """Plan removal of ``_sources`` extraction-cache entries no longer
    referenced once *delete_dirs* are gone. Same plan shape as
    :func:`plan_clean` so :func:`execute_clean` (containment check,
    liveness re-check) is reused unchanged. Does not modify the
    filesystem.

    Bounded by construction:

    * only DIRECT children of ``<project output dir>/_sources`` whose
      name carries the content-addressed ``-<sha256>`` suffix
      (``core.archive.safe_cache_name``) are candidates — anything
      else in there was not written by the extraction cache and is
      left alone;
    * symlinked entries are never candidates (rmtree through a link
      could escape containment);
    * entries whose sha is referenced by ANY surviving run's
      acquisition stamp — or by the project's own archive target —
      are kept;
    * entries younger than the grace window are kept (a racing run
      publishes its extraction before sealing the marker that
      references it).
    """
    stats: dict[str, Any] = {
        "delete_dirs": [], "deleted": [], "kept": [], "freed_bytes": 0,
        "by_type": {}, "skipped_live": [],
    }
    sources_root = Path(project.output_dir) / "_sources"
    try:
        entries = sorted(p for p in sources_root.iterdir())
    except OSError:
        return stats
    referenced: set[str] | None = None
    now = time.time()
    for entry in entries:
        m = _SOURCES_ENTRY_RE.search(entry.name)
        try:
            if (m is None or entry.is_symlink() or not entry.is_dir()):
                continue
            mtime = entry.stat().st_mtime
        except OSError:
            continue
        if now - mtime < _SOURCES_SWEEP_GRACE_SECONDS:
            stats["kept"].append(entry.name)
            continue
        if referenced is None:  # lazy: most cleans have no _sources
            referenced = _referenced_archive_shas(project, delete_dirs)
        if m.group(1) in referenced:
            stats["kept"].append(entry.name)
            continue
        if not _remember_delete(stats, entry):
            continue
        size = _run_dir_size(entry)
        stats["freed_bytes"] += size
        stats["delete_dirs"].append(entry)
        stats["deleted"].append(entry.name)
    return stats


def refresh_sources_plan(project, plan: dict[str, Any],
                         delete_dirs=()) -> dict[str, Any]:
    """Re-vet a :func:`plan_sources_sweep` plan IMMEDIATELY before
    execution. The operator confirm wait between plan and execute is
    unbounded, and a cache HIT does not bump an entry's mtime — so an
    entry old+unreferenced at plan time can be re-referenced by a run
    that starts during the wait, and the age gate alone would never
    notice. Same discipline as :func:`execute_clean`'s pre-delete
    liveness re-check, applied to the reference set.

    Returns a plan containing only entries the fresh computation STILL
    selects — never more than was shown and confirmed (entries only
    the fresh plan selects are ignored); entries no longer selected
    are reported in ``skipped_referenced``. A re-plan failure fails
    toward retention: nothing is deleted.
    """
    out: dict[str, Any] = {
        "delete_dirs": [], "deleted": [],
        "kept": list(plan.get("kept", [])), "freed_bytes": 0,
        "by_type": {}, "skipped_live": [], "skipped_referenced": [],
        "_delete_meta": dict(plan.get("_delete_meta", {})),
    }
    try:
        fresh_names = set(
            plan_sources_sweep(project, delete_dirs)["deleted"])
    except Exception:  # noqa: BLE001 — fail toward retention
        fresh_names = set()
    for d in plan.get("delete_dirs", []):
        name = Path(d).name
        if name in fresh_names:
            if str(d) not in out["_delete_meta"] and not _remember_delete(out, Path(d)):
                continue
            out["delete_dirs"].append(d)
            out["deleted"].append(name)
            out["freed_bytes"] += _run_dir_size(Path(d))
        else:
            out["skipped_referenced"].append(name)
    return out


def execute_sources_sweep(project, plan: dict[str, Any], delete_dirs=(),
                          output_path: Path | None = None) -> dict[str, Any]:
    """THE executor for :func:`plan_sources_sweep` plans — the re-vet
    is applied here, at the last moment, so every caller gets it (the
    run-dir arm's liveness re-check lives inside its executor for the
    same reason; a caller handing a stale plan straight to
    ``execute_clean`` would bypass the race protection). Returns the
    refreshed plan that was actually executed (``skipped_referenced``
    names the entries the re-vet rescued)."""
    # A caller may hand us the original run-deletion plan, including runs
    # an execution-time safety check spared. Existing runs still own their
    # archive references regardless of what was intended at plan time.
    gone = [path for path in delete_dirs if not os.path.lexists(path)]
    refreshed = refresh_sources_plan(project, plan, gone)
    if refreshed["delete_dirs"]:
        execute_clean(refreshed,
                      output_path=output_path or project.output_path)
    return refreshed


def clean_project(project, keep: int=1, dry_run: bool=False) -> dict[str, Any]:
    """Clean old runs from a project. Returns stats dict.

    Keeps latest `keep` runs per command type.
    Convenience wrapper around plan_clean + execute_clean.
    """
    stats = plan_clean(project, keep=keep)
    if not dry_run:
        execute_clean(stats, output_path=project.output_path,
                      eligible_dirs=eligible_clean_dirs(project, keep=keep))
    return stats

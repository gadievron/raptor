"""Project-wide review-journal reindex sweep.

Motivation (live incident): healing a project index whose rows a
version-skewed merge had damaged took TWO manual
``journal reindex <run-dir>`` invocations — the tampered rows' intact
source of truth was a PRIOR run's journal, so reindexing the current
run re-merged as a no-op and the damage stayed. The remedy should be
one command: re-project EVERY run of the project through the exact
single-run merge path.

Ordering — oldest→newest, and why. The merge is order-commutative for
almost everything: cross-timestamp content resolves by latest-wins (a
max), and the same-``ts`` repair tie-break is monotone toward the
verifying copy. The one genuinely order-sensitive case is same key,
EQUAL ``ts``, different bodies where the stored copy is not
out-verified — the first-merged copy wins (an incoming row never
replaces a same-``ts`` stored copy it cannot out-verify). Sweeping
oldest→newest replays the chronology the original run-completion
merges applied, so the sweep converges the index to the state it
would have had absent damage. Pinned by
``test_sweep_order_is_oldest_first``.

Safety:

* The project ``.op.lock`` is held for the sweep's WHOLE duration —
  live-writer gate, index pre-flight, and every merge run inside it.
  Without it the gate was check-then-act: a run that STARTED
  mid-sweep was unfenced, and the window was two-sided (a run
  start's own contention gate holds this flock across its
  check-and-write window, so a lockless sweep was invisible to it).
  Lock order and acquisition posture: see the rationale comment in
  :func:`reindex_project_journals`.
* Wholesale refusal BEFORE any merge while a live run owns the
  project (``core.run.metadata._live_conflicting_run`` — the same
  gate run starts use), with ``self_session_pid=None`` so even this
  session's own runs contend: the sweep rewrites the shared index and
  a racing completion merge could interleave with it. Stale-lock
  semantics are inherited from the gate: dead recorded pids, legacy
  pid-less metadata, imported-run markers, and foreign-stamped
  holders past the 24h ceiling with a write-quiet dir never block.
* THE RUN PIN decides, per run — the sweep resolves each run through
  ``core.run.metadata._journal_project_dir`` (the resolution run
  completion's merge uses) and skips runs that resolve to no project
  or to a different one; nothing is ever force-merged.
* Import-restored runs are skipped wholesale (their journals were
  minted on the exporting machine), matching
  ``core.run.metadata.project_run_projections``.
* Index-only writes: every merge goes through
  ``core.coverage.journal.merge_run_into_index`` — no run's journal
  file is ever mutated.
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # import cycle: project.py imports core.coverage
    from core.project.project import Project

from core.coverage.journal import (
    INDEX_FILENAME,
    IndexUnreadable,
    _load_index,
    merge_run_into_index,
)

logger = logging.getLogger("raptor")


class SweepRefused(RuntimeError):
    """The sweep cannot run safely: unknown or invalid project (a
    hard error by the project-flag contract — never a fallback), an
    unreadable project index, or a live run writing the project."""


@dataclass
class RunOutcome:
    """Per-run sweep result: merge counts, or the skip reason.

    ``unreadable`` counts journal locations in the run whose read
    failed or yielded no rows despite non-empty content (malformed
    JSON, permission-refused open, journal path is a directory) —
    the merge degrades those to ``merged=0`` for the location, so
    without this count the run is indistinguishable from a genuinely
    empty one.
    """
    run_name: str
    merged: int = 0
    stripped: int = 0
    healed: int = 0
    unreadable: int = 0
    skipped_reason: str | None = None


@dataclass
class SweepReport:
    """Aggregate result of one project sweep."""
    project_name: str
    project_dir: Path
    index_path: Path
    outcomes: list[RunOutcome] = field(default_factory=list)

    @property
    def total_merged(self) -> int:
        return sum(o.merged for o in self.outcomes)

    @property
    def total_stripped(self) -> int:
        return sum(o.stripped for o in self.outcomes)

    @property
    def total_healed(self) -> int:
        return sum(o.healed for o in self.outcomes)

    @property
    def swept(self) -> int:
        return sum(1 for o in self.outcomes if o.skipped_reason is None)

    @property
    def skipped(self) -> int:
        return sum(1 for o in self.outcomes if o.skipped_reason is not None)

    @property
    def unreadable_runs(self) -> int:
        return sum(1 for o in self.outcomes if o.unreadable)


def reindex_project_journals(project_name: str) -> SweepReport:
    """Re-project every run of *project_name* into its review-journal
    index, oldest→newest, through the single-run merge path.

    Returns a :class:`SweepReport` with one :class:`RunOutcome` per
    enumerated run dir. Raises :class:`SweepRefused` for an invalid or
    unknown project name, an unreadable index, a live conflicting
    run — always before any index write in the live-run case — or a
    held project op lock.
    """
    from core.project.project import ProjectManager
    try:
        ProjectManager._validate_name(project_name)
    except ValueError as exc:
        raise SweepRefused(f"invalid project name: {exc}") from exc
    manager = ProjectManager()
    project = manager.load(project_name)
    if project is None:
        raise SweepRefused(
            f"unknown project: '{project_name}' is not in the registry")
    project_dir = project.output_path
    report = SweepReport(
        project_name=project.name,
        project_dir=project_dir,
        index_path=project_dir / INDEX_FILENAME,
    )
    if not project_dir.is_dir():
        # A registered project whose output dir was never created (or
        # was cleaned away) has no runs and no index — an empty sweep,
        # not an error. Deliberately BEFORE the lock acquisition:
        # taking the op lock mkdirs the project dir and mints the lock
        # file, a write side effect a read-only no-op must not have.
        return report

    from core.project.oplock import OpLockContention, project_op_lock

    # Hold the project ``.op.lock`` for the sweep's WHOLE duration.
    # Why: the live-writer gate below is otherwise check-then-act —
    # it runs once, so a run that STARTS mid-sweep is unfenced, and
    # the window is two-sided: run starts hold this flock across
    # their own [contention check → metadata write] window
    # (``core.run.metadata._project_run_gate``), so a lockless sweep
    # was invisible to them too. With the lock held, a mid-sweep run
    # start queues behind it (the run gate enters with ``wait=True``)
    # and proceeds only after the sweep releases.
    #
    # LOCK ORDER (no ABBA by construction): ``.op.lock`` is strictly
    # OUTERMOST — acquired here before ANY journal-stack lock, and
    # every lock taken inside is from that stack: the per-merge index
    # flock (``merge_into_index``), and the journal shard/sidecar
    # flocks whose own total order is ``sidecar < shard_1 < …``
    # (``journal_compact.SidecarWriter.open``). Nothing in
    # ``core.coverage`` ever acquires ``.op.lock`` (it lives in
    # ``core.project.oplock``; the journal stack does not import it),
    # so no path waits for ``.op.lock`` while holding a journal-stack
    # lock — the existing holders (run-start gate, mutating /project
    # subcommands, whose ``adopt`` already merges into the index
    # under it) all acquire in this same outermost-first direction.
    #
    # Acquisition posture: non-waiting with the bounded mutator grace
    # — contention (a run start's check-and-write window, a mutating
    # /project subcommand) converts to ``SweepRefused`` naming the
    # holder, never an unbounded wait; the sweep is a retryable
    # remedy command. The other direction (waiting) would silently
    # serialise behind a wedged holder with no operator signal.
    # Without fcntl or with an uncreatable lock file, the lock
    # degrades to unserialised (its documented posture, same fail
    # direction as every sibling RMW lock) — identical to the
    # pre-lock sweep, never a new refusal on degraded hosts.
    try:
        with project_op_lock(project_dir, "journal-reindex-sweep"):
            _sweep_project_locked(project, project_dir, report)
    except OpLockContention as exc:
        raise SweepRefused(f"refusing to sweep: {exc}") from exc
    return report


def _sweep_project_locked(project: "Project", project_dir: Path,
                          report: SweepReport) -> None:
    """Gate, pre-flight, and per-run merge loop — the caller holds the
    project op lock for this whole call."""
    import core.run.metadata as metadata

    # Refuse wholesale BEFORE any merge while a run is writing the
    # project. self_dir is a dot-prefixed sentinel no real run dir can
    # collide with (the gate skips dot-prefixed children, so it only
    # ever serves as the "not myself" name); self_session_pid=None so
    # even this session's own live runs contend.
    holder = metadata._live_conflicting_run(
        project_dir, project_dir / ".journal-reindex-sweep", None)
    if holder is not None:
        # Holder fields arrive pre-sanitised from the gate.
        raise SweepRefused(
            "a run is writing this project right now (pid "
            f"{holder['pid']}, {holder['operation']}, run dir "
            f"{holder['run_dir']}, since {holder['since']}) — re-run "
            "the sweep after it completes")

    # Pre-flight the index BEFORE any merge: the per-merge writer
    # swallows an unreadable index (logs, merges nothing, returns 0),
    # which would let a corrupt index sweep to a clean-looking
    # "0 merged; 0 skipped" success — the opposite of what a remedy
    # command owes the operator. Every remaining merge would hit the
    # same wall, and "starting fresh" is exactly what the writer
    # refuses, so surface it as the sweep's refusal.
    if report.index_path.is_file():
        try:
            _load_index(report.index_path, for_write=True)
        except IndexUnreadable as exc:
            raise SweepRefused(f"refusing to sweep: {exc}") from exc

    from core.project.findings_utils import run_is_imported
    resolved_project = project_dir.resolve()
    # Oldest→newest (get_run_dirs returns newest-first; see the module
    # docstring for the ordering rationale). sweep=False: this is a
    # read-only enumeration of run dirs — never damage active runs.
    for run_dir in reversed(project.get_run_dirs(sweep=False)):
        outcome = RunOutcome(run_name=run_dir.name)
        report.outcomes.append(outcome)
        try:
            imported = run_is_imported(run_dir)
        except OSError:
            imported = False
        if imported:
            outcome.skipped_reason = (
                "imported run (journals were minted on the exporting "
                "machine and never re-project here)")
            continue
        pinned = metadata._journal_project_dir(run_dir)
        if pinned is None:
            outcome.skipped_reason = (
                "no project pin resolves (standalone or pin-refused "
                "run)")
            continue
        if pinned != resolved_project:
            outcome.skipped_reason = "pinned to a different project"
            continue
        stats: dict[str, int] = {}
        try:
            outcome.merged = merge_run_into_index(
                resolved_project, run_dir, stats=stats)
        except Exception as exc:  # noqa: BLE001 — per-run containment
            # One unreadable run journal must not abort the other
            # runs' re-projection. (An index that turns unreadable
            # MID-sweep degrades the same way the single-run merge
            # does — per-run log errors — because the writer swallows
            # IndexUnreadable internally; the pre-flight above is the
            # refusal point for a corrupt index.)
            logger.warning(
                "journal sweep: %s failed to merge: %s",
                run_dir.name, exc)
            outcome.skipped_reason = f"merge failed: {exc}"
            continue
        outcome.stripped = stats.get("stripped", 0)
        outcome.healed = stats.get("healed", 0)
        outcome.unreadable = stats.get("unreadable", 0)

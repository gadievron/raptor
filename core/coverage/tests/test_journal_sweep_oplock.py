"""The journal reindex sweep holds the project ``.op.lock``.

Defect: the sweep's active-writer gate was check-then-act — it ran
ONCE, before any merge, so a run that STARTED mid-sweep was unfenced.
The window was two-sided: the sweep took no project ``.op.lock``
either, so a run start's own contention gate (which holds that flock
across its check-and-write window — ``core.run.metadata.
_project_run_gate``) could not see an in-flight sweep.

Fix shape under test: the sweep holds ``.op.lock`` for its whole
duration — live-writer gate, index pre-flight, and every merge happen
inside it. A run start that lands mid-sweep now blocks on the flock
until the sweep releases (the run gate enters with ``wait=True``);
the sweep itself enters non-waiting and converts contention to
``SweepRefused`` after the bounded mutator grace, so no acquisition
in this stack ever waits unbounded on a held lock.

Lock order (no ABBA with the journal stack): ``.op.lock`` is strictly
OUTERMOST — see the rationale comment in
``core.coverage.journal_sweep.reindex_project_journals``.

Determinism: no sleeps-as-synchronization anywhere below. flock(2)
locks belong to the open file description, so a second ``os.open`` of
the lock path IN THIS PROCESS contends for real — the probes observe
the held/free state at exact points inside the sweep via monkeypatched
seams. The held-lock refusal test runs the sweep in a daemon thread
under a bounded join: the shrunken module grace keeps the healthy
refusal prompt, and the join bound converts a regression to a
BLOCKING acquire — whose unbounded ``flock(LOCK_EX)`` would deadlock
against the test's same-process holder — into a fast hard failure
(the bound is a ceiling on a direction that must not block, not a
synchronization wait).
"""

import json
import os
import shutil
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

fcntl = pytest.importorskip("fcntl")

from core.coverage.journal import (  # noqa: E402 — after importorskip
    INDEX_FILENAME,
    ReviewJournalEntry,
    append_entry,
    now_iso,
)
from core.project.oplock import (  # noqa: E402 — after importorskip
    OP_LOCK_NAME,
    OpLockContention,
    project_op_lock,
)


def _entry(function: str = "check_pw") -> ReviewJournalEntry:
    return ReviewJournalEntry(
        ts=now_iso(),
        run_id="run_1",
        file="src/a.c",
        function=function,
        verdict="clean",
        source_hash="deadbeef",
        body="reviewed, no concern",
        producer="audit",
    )


@pytest.fixture()
def project_env(tmp_path, monkeypatch):
    """A real registry project whose output dir is containment-
    probeable (``coverage.json`` marks it project-shaped)."""
    import core.project.project as project_mod
    registry = tmp_path / "registry"
    registry.mkdir()
    monkeypatch.setattr(project_mod, "PROJECTS_DIR", registry)
    target = tmp_path / "target"
    target.mkdir()
    proj_dir = tmp_path / "proj-out"
    manager = project_mod.ProjectManager()
    manager.create("locktest", str(target), output_dir=str(proj_dir))
    (proj_dir / "coverage.json").write_text("{}", encoding="utf-8")
    return SimpleNamespace(
        name="locktest", dir=proj_dir, manager=manager,
        registry=registry, target=target)


def _make_run(project_dir: Path, name: str) -> Path:
    run = project_dir / name
    run.mkdir(parents=True)
    return run


def _sweep(name: str):
    from core.coverage.journal_sweep import reindex_project_journals
    return reindex_project_journals(name)


def _op_lock_is_free(project_dir: Path) -> bool:
    """Non-blocking flock probe on a FRESH fd (a separate open file
    description contends with any holder, same process included)."""
    fd = os.open(str(project_dir / OP_LOCK_NAME),
                 os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return False
        fcntl.flock(fd, fcntl.LOCK_UN)
        return True
    finally:
        os.close(fd)


class TestSweepHoldsOpLock:
    def test_gate_and_merges_run_under_the_lock(
        self, project_env, monkeypatch,
    ):
        """HEADLINE: the live-writer gate AND every per-run merge
        observe a HELD ``.op.lock``, and the lock is free again after
        the sweep returns."""
        import core.run.metadata as metadata

        import core.coverage.journal_sweep as sweep_mod

        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())

        seen: dict[str, bool] = {}
        real_gate = metadata._live_conflicting_run
        real_merge = sweep_mod.merge_run_into_index

        def probing_gate(project_dir, self_dir, self_session_pid):
            seen["gate_under_lock"] = not _op_lock_is_free(
                project_env.dir)
            return real_gate(project_dir, self_dir, self_session_pid)

        def probing_merge(project_dir, run_dir, **kwargs):
            seen["merge_under_lock"] = not _op_lock_is_free(
                project_env.dir)
            return real_merge(project_dir, run_dir, **kwargs)

        monkeypatch.setattr(
            metadata, "_live_conflicting_run", probing_gate)
        monkeypatch.setattr(
            sweep_mod, "merge_run_into_index", probing_merge)

        report = _sweep(project_env.name)

        assert report.total_merged == 1
        assert seen == {"gate_under_lock": True,
                        "merge_under_lock": True}
        assert _op_lock_is_free(project_env.dir)

    def test_mid_sweep_run_start_acquisition_contends(
        self, project_env, monkeypatch,
    ):
        """A run start landing MID-SWEEP is fenced: the run gate's own
        acquisition primitive (``project_op_lock``) contends against
        the in-flight sweep and can name it as the holder. (The real
        gate enters with ``wait=True`` — it queues behind the sweep
        instead of interleaving; the ``grace=0`` probe here observes
        the same flock without blocking the single-threaded test.)"""
        import core.coverage.journal_sweep as sweep_mod

        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())

        outcome: dict[str, object] = {}
        real_merge = sweep_mod.merge_run_into_index

        def probing_merge(project_dir, run_dir, **kwargs):
            try:
                with project_op_lock(project_env.dir, "run-start:scan",
                                     grace=0.0):
                    outcome["contended"] = False
            except OpLockContention as exc:
                outcome["contended"] = True
                outcome["holder_op"] = exc.holder.get("operation")
            return real_merge(project_dir, run_dir, **kwargs)

        monkeypatch.setattr(
            sweep_mod, "merge_run_into_index", probing_merge)

        report = _sweep(project_env.name)

        assert report.total_merged == 1
        assert outcome.get("contended") is True
        assert outcome.get("holder_op") == "journal-reindex-sweep"

    def test_sweep_refuses_while_the_lock_is_held(
        self, project_env, monkeypatch,
    ):
        """The other side of the fence: a held ``.op.lock`` (a run
        start's check-and-write window, a mutating /project
        subcommand) refuses the sweep after the bounded grace — never
        an unbounded wait, never a merge behind the holder's back."""
        import core.project.oplock as oplock

        from core.coverage.journal_sweep import SweepRefused

        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        # The shrunken grace keeps the HEALTHY refusal prompt. It does
        # NOT bound a regression to a blocking acquire (wait=True):
        # that path passes the grace poll and then executes an
        # unbounded flock(LOCK_EX) which deadlocks against this
        # test's same-process holder. That direction is bounded by
        # the daemon thread + join(timeout) below — a sweep still
        # alive after the bound is a fast hard failure, never a hang.
        monkeypatch.setattr(oplock, "MUTATOR_GRACE_S", 0.05)

        lock_path = project_env.dir / OP_LOCK_NAME
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(fd, json.dumps({
                "pid": os.getpid(), "operation": "run-start:scan",
                "since": now_iso()}).encode("utf-8"))

            outcome: dict[str, str] = {}

            def sweep_under_test() -> None:
                try:
                    _sweep(project_env.name)
                    outcome["result"] = "returned"
                except SweepRefused as exc:
                    outcome["result"] = "refused"
                    outcome["message"] = str(exc)
                except BaseException as exc:  # noqa: BLE001 — surfaced by the assertion below
                    outcome["result"] = f"raised {exc!r}"

            worker = threading.Thread(
                target=sweep_under_test, daemon=True)
            worker.start()
            worker.join(timeout=10.0)
            if worker.is_alive():
                pytest.fail(
                    "sweep still running after the join bound — its "
                    "acquisition is BLOCKING on the held .op.lock "
                    "instead of refusing after the bounded grace")
            assert outcome.get("result") == "refused", outcome
            message = outcome.get("message", "")
            assert "locked by another operation" in message
            assert "run-start:scan" in message
            assert not (project_env.dir / INDEX_FILENAME).exists()
        finally:
            os.close(fd)

    def test_lock_released_when_a_refusal_raises_inside_it(
        self, project_env,
    ):
        """A ``SweepRefused`` raised INSIDE the locked region (corrupt
        index pre-flight) must release the flock on unwind — a wedged
        lock would block every future run start on the project."""
        from core.coverage.journal_sweep import SweepRefused

        run = _make_run(project_env.dir, "scan-20260101-000000")
        append_entry(run, _entry())
        (project_env.dir / INDEX_FILENAME).write_text(
            "{ not json\n", encoding="utf-8")

        with pytest.raises(SweepRefused):
            _sweep(project_env.name)
        assert _op_lock_is_free(project_env.dir)

    def test_missing_project_dir_takes_no_lock(self, project_env):
        """The empty-sweep fast path (registered project, output dir
        never created / cleaned away) stays BEFORE the acquisition —
        taking the lock there would mkdir the project dir and mint an
        ``.op.lock`` as a side effect of a read-only no-op."""
        shutil.rmtree(project_env.dir)

        report = _sweep(project_env.name)

        assert report.outcomes == []
        assert not project_env.dir.exists()

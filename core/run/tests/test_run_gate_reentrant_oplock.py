"""Re-entrant run starts queue behind the project ``.op.lock``.

Defect: ``_project_run_gate``'s re-entrant arm — a start_run on a dir
whose OWN metadata already reads ``status=running`` (the documented
enrichment flows, but equally a crashed-run-dir restart into the same
output dir) — yielded immediately, skipping the flock entirely. The
journal reindex sweep holds ``.op.lock`` for its whole duration
precisely so run starts queue behind it; the re-entrant shape was the
one start class that still wrote mid-sweep behind the sweep's back.

Fix under test: the re-entrant arm acquires the op lock with the same
``wait=True`` posture as a fresh start and holds it across its yield
(the metadata read-modify-write window). It still skips the SIBLING
contention refusal — gating an enrichment against siblings could kill
a run whose parent already passed the gate — and the lock order is
unchanged (``.op.lock`` outermost, then the metadata lock).

Determinism: flock(2) locks belong to the open file description, so a
fresh ``os.open`` of the lock path IN THIS PROCESS contends for real —
the probes observe held/free state at exact points. The one bounded
wait below guards a direction that must not happen (entering the
gate while the lock is held), not a synchronization point.
"""

import contextlib
import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

fcntl = pytest.importorskip("fcntl")

import core.run.metadata as metadata  # noqa: E402 — after importorskip
from core.project.oplock import (  # noqa: E402 — after importorskip
    OP_LOCK_NAME,
)


@pytest.fixture(autouse=True)
def _user_state_in_tmp(tmp_path: Path,
                       monkeypatch: pytest.MonkeyPatch) -> None:
    """User registries stay out of the real home (the root-conftest
    layer doing this is stripped from release extracts, so the pin
    travels in-file)."""
    from core.testing.state_isolation import pin_user_state_dirs
    pin_user_state_dirs(monkeypatch, tmp_path)


SELF_SESSION = 11111


@pytest.fixture()
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """A managed registry project plus a run dir whose own metadata
    already reads ``status=running`` — the re-entrant start shape."""
    import core.project.project as project_mod
    from core.project.project import ProjectManager

    projects_dir = tmp_path / "projects"
    target = tmp_path / "code"
    target.mkdir()
    project_out = tmp_path / "out" / "myapp"
    mgr = ProjectManager(projects_dir=projects_dir)
    mgr.create("myapp", str(target), output_dir=str(project_out))
    monkeypatch.setattr(project_mod, "PROJECTS_DIR", projects_dir)
    monkeypatch.setattr(metadata, "_get_session_pid",
                        lambda: SELF_SESSION)

    run_dir = project_out / "agentic_20260102_000000"
    run_dir.mkdir(parents=True)
    (run_dir / metadata.RUN_METADATA_FILE).write_text(json.dumps({
        "version": 2,
        "command": "agentic",
        "status": "running",
        # Fresh stamp: keeps _cleanup_abandoned's freshness gate from
        # sweeping the dir as an Esc-abandon before the gate runs.
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "session_pid": SELF_SESSION,
    }), encoding="utf-8")
    return SimpleNamespace(project_dir=project_out, run_dir=run_dir)


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


class TestReentrantGateOpLock:
    def test_reentrant_gate_holds_the_op_lock(self, env):
        """HEADLINE (gate level): the re-entrant arm holds ``.op.lock``
        across its yield — the metadata-write window it guards — and
        releases it on exit."""
        with metadata._project_run_gate(
            env.project_dir, env.run_dir, "agentic", SELF_SESSION,
        ):
            assert not _op_lock_is_free(env.project_dir)
        assert _op_lock_is_free(env.project_dir)

    def test_reentrant_gate_enters_the_queue_like_a_fresh_start(
        self, env, monkeypatch,
    ):
        """The acquisition is the fresh path's own: one
        ``project_op_lock`` entry, holder-stamped ``run-start:<cmd>``,
        ``wait=True`` (queue behind a held lock, never refuse and
        never bypass)."""
        import core.project.oplock as oplock

        calls: list[tuple[str, bool, bool]] = []
        real = oplock.project_op_lock

        @contextlib.contextmanager
        def recording(project_dir, operation, grace=None, wait=False):
            with real(project_dir, operation, grace=grace, wait=wait):
                calls.append((operation, wait,
                              not _op_lock_is_free(env.project_dir)))
                yield

        monkeypatch.setattr(oplock, "project_op_lock", recording)
        with metadata._project_run_gate(
            env.project_dir, env.run_dir, "agentic", SELF_SESSION,
        ):
            pass
        # The ``wait=True`` element is load-bearing on its own: the
        # end-to-end queue test below can observe a proceed-on-
        # contention regression only if it completes inside that
        # test's bounded window — a slower bypass (any grace/retry
        # posture that gives up on the queue and proceeds after a
        # few seconds) is caught ONLY by this exact-tuple pin. Do
        # not relax it to a held-at-yield check.
        assert calls == [("run-start:agentic", True, True)]

    def test_reentrant_gate_still_skips_sibling_contention(
        self, env, monkeypatch,
    ):
        """Direction pin: the re-entrant arm's PURPOSE is untouched —
        it never consults the sibling gate (a live sibling would
        refuse a fresh start, but must not kill an enrichment whose
        parent already passed the gate)."""
        def poisoned_gate(project_dir, self_dir, self_session_pid):
            raise AssertionError(
                "re-entrant start consulted the sibling gate")

        monkeypatch.setattr(
            metadata, "_live_conflicting_run", poisoned_gate)
        with metadata._project_run_gate(
            env.project_dir, env.run_dir, "agentic", SELF_SESSION,
        ):
            pass

    def test_reentrant_start_run_queues_behind_a_held_op_lock(
        self, env,
    ):
        """End to end: while another operation holds ``.op.lock`` (the
        mid-flight journal sweep, a sibling start's RMW window), a
        re-entrant ``start_run`` into the running dir must NOT write —
        it queues on the flock and proceeds only after release. The
        bounded wait guards the must-not-happen direction (writing
        while held); the daemon thread plus join bound converts a
        regression either way into a fast hard failure, never a
        hang."""
        lock_path = env.project_dir / OP_LOCK_NAME
        fd = os.open(str(lock_path), os.O_RDWR | os.O_CREAT, 0o600)
        done = threading.Event()
        failure: list[BaseException] = []

        def worker() -> None:
            try:
                metadata.start_run(env.run_dir, "agentic")
            except BaseException as exc:  # noqa: BLE001 — surfaced below
                failure.append(exc)
            finally:
                done.set()

        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.write(fd, json.dumps({
                "pid": os.getpid(),
                "operation": "journal-reindex-sweep",
                "since": datetime.now(timezone.utc).isoformat(),
            }).encode("utf-8"))

            thread = threading.Thread(target=worker, daemon=True)
            thread.start()
            wrote_while_held = done.wait(timeout=1.5)
            assert not wrote_while_held, (
                "re-entrant start_run completed while .op.lock was "
                "held — it wrote without queueing behind the holder")
        finally:
            os.close(fd)   # releases the flock with it

        assert done.wait(timeout=15.0), (
            "start_run did not proceed after the lock was released")
        thread.join(timeout=5.0)
        assert not failure, failure
        meta = json.loads(
            (env.run_dir / metadata.RUN_METADATA_FILE).read_text(
                encoding="utf-8"))
        assert meta["status"] == "running"
        assert _op_lock_is_free(env.project_dir)

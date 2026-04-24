"""End-to-end worker tests — actually spawn a subprocess."""

from __future__ import annotations

import importlib
import sys
import time
from pathlib import Path

import pytest

from packages.studio.services import jobs as jobs_service
from packages.studio.services.jobs import Job, JobStatus


def _wait_terminal(job_id, db_path, timeout=15.0, poll=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        j = jobs_service.get(job_id, db_path=db_path)
        if j and j.is_terminal:
            return j
        time.sleep(poll)
    return jobs_service.get(job_id, db_path=db_path)


@pytest.fixture
def isolated_worker(tmp_path, monkeypatch):
    """Reload jobs + worker with STUDIO_DATA_DIR pointed at tmp_path."""
    monkeypatch.setenv("STUDIO_DATA_DIR", str(tmp_path))
    # Reload config so STUDIO_DATA_DIR picks up the env override.
    from packages.studio import config
    importlib.reload(config)
    # Reload modules that captured STUDIO_DATA_DIR at import time.
    for mod_name in ("packages.studio.services.jobs", "packages.studio.services.worker"):
        if mod_name in sys.modules:
            importlib.reload(sys.modules[mod_name])
    from packages.studio.services import jobs as jobs_reloaded
    from packages.studio.services import worker as worker_reloaded

    worker_reloaded.start()
    yield (jobs_reloaded, worker_reloaded, tmp_path / "jobs.db")
    worker_reloaded.stop(timeout=2.0)


def test_worker_runs_trivial_command_end_to_end(isolated_worker):
    jobs_reloaded, _, db = isolated_worker
    job = jobs_reloaded.Job.new(
        project_name="demo", kind="agentic", target="/tmp",
        argv=["python3", "-c", "print('hello from worker')"],
    )
    jobs_reloaded.enqueue(job)

    final = None
    for _ in range(100):
        final = jobs_reloaded.get(job.id)
        if final and final.is_terminal:
            break
        time.sleep(0.1)

    assert final is not None
    assert final.status == jobs_reloaded.JobStatus.COMPLETED
    assert final.exit_code == 0
    assert final.started_at is not None
    assert final.finished_at is not None
    assert final.log_path is not None

    log = Path(final.log_path).read_text()
    assert "hello from worker" in log


def test_worker_marks_failed_for_nonzero_exit(isolated_worker):
    jobs_reloaded, _, _ = isolated_worker
    job = jobs_reloaded.Job.new(
        project_name="demo", kind="agentic", target="/tmp",
        argv=["python3", "-c", "import sys; sys.exit(3)"],
    )
    jobs_reloaded.enqueue(job)

    final = None
    for _ in range(100):
        final = jobs_reloaded.get(job.id)
        if final and final.is_terminal:
            break
        time.sleep(0.1)

    assert final.status == jobs_reloaded.JobStatus.FAILED
    assert final.exit_code == 3


def test_worker_handles_missing_executable(isolated_worker):
    jobs_reloaded, _, _ = isolated_worker
    job = jobs_reloaded.Job.new(
        project_name="demo", kind="agentic", target="/tmp",
        argv=["/nonexistent/path/to/binary"],
    )
    jobs_reloaded.enqueue(job)

    final = None
    for _ in range(100):
        final = jobs_reloaded.get(job.id)
        if final and final.is_terminal:
            break
        time.sleep(0.1)

    assert final.status == jobs_reloaded.JobStatus.FAILED
    assert final.exit_code == 127
    assert final.error and "No such file" in final.error


def test_worker_cancel_stops_long_running_job(isolated_worker):
    jobs_reloaded, worker_reloaded, _ = isolated_worker
    job = jobs_reloaded.Job.new(
        project_name="demo", kind="fuzz", target="/tmp/bin",
        argv=["python3", "-c", "import time; time.sleep(30)"],
    )
    jobs_reloaded.enqueue(job)

    # Wait until running
    for _ in range(50):
        j = jobs_reloaded.get(job.id)
        if j and j.status == jobs_reloaded.JobStatus.RUNNING:
            break
        time.sleep(0.1)
    running = jobs_reloaded.get(job.id)
    assert running.status == jobs_reloaded.JobStatus.RUNNING

    assert worker_reloaded.cancel(job.id) is True

    # Wait until terminal
    for _ in range(100):
        j = jobs_reloaded.get(job.id)
        if j and j.is_terminal:
            break
        time.sleep(0.1)
    final = jobs_reloaded.get(job.id)
    assert final.status == jobs_reloaded.JobStatus.CANCELLED

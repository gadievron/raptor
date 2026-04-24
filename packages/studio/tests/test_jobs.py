"""Tests for jobs SQLite storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.studio.services import jobs as jobs_service
from packages.studio.services.jobs import Job, JobStatus


@pytest.fixture
def db(tmp_path: Path) -> Path:
    return tmp_path / "jobs.db"


def _make_job(**kw) -> Job:
    defaults = dict(
        project_name="demo", kind="agentic", target="/tmp/repo",
        argv=["python3", "/opt/raptor/raptor_agentic.py", "--repo", "/tmp/repo"],
    )
    defaults.update(kw)
    return Job.new(**defaults)


def test_enqueue_and_get(db: Path):
    job = _make_job()
    jobs_service.enqueue(job, db_path=db)
    loaded = jobs_service.get(job.id, db_path=db)
    assert loaded is not None
    assert loaded.id == job.id
    assert loaded.status == JobStatus.QUEUED
    assert loaded.argv == job.argv


def test_list_jobs_filters_by_project(db: Path):
    jobs_service.enqueue(_make_job(project_name="alpha"), db_path=db)
    jobs_service.enqueue(_make_job(project_name="beta"), db_path=db)
    jobs_service.enqueue(_make_job(project_name="alpha"), db_path=db)

    all_jobs = jobs_service.list_jobs(db_path=db)
    assert len(all_jobs) == 3

    alpha = jobs_service.list_jobs(project_name="alpha", db_path=db)
    assert len(alpha) == 2
    assert all(j.project_name == "alpha" for j in alpha)


def test_list_jobs_filters_by_status(db: Path):
    a = _make_job()
    b = _make_job()
    jobs_service.enqueue(a, db_path=db)
    jobs_service.enqueue(b, db_path=db)

    log = jobs_service.log_path_for(a.id, log_dir=db.parent)
    log.write_text("x")
    jobs_service.mark_running(a.id, pid=12345, log_path=log, db_path=db)

    running = jobs_service.list_jobs(status=JobStatus.RUNNING, db_path=db)
    queued = jobs_service.list_jobs(status=JobStatus.QUEUED, db_path=db)
    assert [j.id for j in running] == [a.id]
    assert [j.id for j in queued] == [b.id]


def test_next_queued_returns_oldest_queued(db: Path):
    a = _make_job()
    b = _make_job()
    jobs_service.enqueue(a, db_path=db)
    jobs_service.enqueue(b, db_path=db)

    first = jobs_service.next_queued(db_path=db)
    assert first is not None
    assert first.id == a.id


def test_mark_running_then_finished(db: Path):
    job = _make_job()
    jobs_service.enqueue(job, db_path=db)
    log = jobs_service.log_path_for(job.id, log_dir=db.parent)
    log.write_text("hi")
    jobs_service.mark_running(job.id, pid=9999, log_path=log, db_path=db)
    running = jobs_service.get(job.id, db_path=db)
    assert running.status == JobStatus.RUNNING
    assert running.pid == 9999
    assert running.log_path == str(log)

    jobs_service.mark_finished(job.id, exit_code=0, run_dir="/tmp/out/run_1", db_path=db)
    done = jobs_service.get(job.id, db_path=db)
    assert done.status == JobStatus.COMPLETED
    assert done.exit_code == 0
    assert done.run_dir == "/tmp/out/run_1"
    assert done.is_terminal


def test_mark_finished_non_zero_is_failed(db: Path):
    job = _make_job()
    jobs_service.enqueue(job, db_path=db)
    jobs_service.mark_finished(job.id, exit_code=1, db_path=db)
    loaded = jobs_service.get(job.id, db_path=db)
    assert loaded.status == JobStatus.FAILED


def test_mark_cancelled(db: Path):
    job = _make_job()
    jobs_service.enqueue(job, db_path=db)
    jobs_service.mark_cancelled(job.id, db_path=db)
    loaded = jobs_service.get(job.id, db_path=db)
    assert loaded.status == JobStatus.CANCELLED
    assert loaded.is_terminal


def test_elapsed_seconds_none_until_started(db: Path):
    job = _make_job()
    jobs_service.enqueue(job, db_path=db)
    loaded = jobs_service.get(job.id, db_path=db)
    assert loaded.elapsed_seconds is None


def test_get_returns_none_for_missing(db: Path):
    assert jobs_service.get("no-such-id", db_path=db) is None

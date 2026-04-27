"""Job queue for raptor-studio.

Stores UI-triggered raptor invocations as jobs in a local SQLite database.
The worker (services.worker) picks up queued jobs and executes them as
subprocesses, streaming stdout+stderr to log files.

Schema kept intentionally small; every field either serves the list / detail
UIs or is used by the worker to manage the subprocess lifecycle.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Optional

from packages.studio.config import STUDIO_DATA_DIR


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


# The status values that indicate the subprocess is no longer running.
TERMINAL_STATUSES = frozenset({
    JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED,
})


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _jobs_db_path() -> Path:
    return STUDIO_DATA_DIR / "jobs.db"


def _log_dir() -> Path:
    return STUDIO_DATA_DIR / "job-logs"


DDL = """
CREATE TABLE IF NOT EXISTS jobs (
    id           TEXT PRIMARY KEY,
    project_name TEXT NOT NULL,
    kind         TEXT NOT NULL,
    target       TEXT NOT NULL,
    argv_json    TEXT NOT NULL,
    status       TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    exit_code    INTEGER,
    pid          INTEGER,
    log_path     TEXT,
    run_dir      TEXT,
    error        TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
CREATE INDEX IF NOT EXISTS idx_jobs_project_created ON jobs(project_name, created_at DESC);
"""


@dataclass
class Job:
    id: str
    project_name: str
    kind: str
    target: str
    argv: list[str]
    status: JobStatus
    created_at: str
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    log_path: Optional[str] = None
    run_dir: Optional[str] = None
    error: Optional[str] = None

    @classmethod
    def new(cls, project_name: str, kind: str, target: str, argv: list[str]) -> "Job":
        return cls(
            id=str(uuid.uuid4()),
            project_name=project_name,
            kind=kind,
            target=target,
            argv=list(argv),
            status=JobStatus.QUEUED,
            created_at=_now(),
        )

    @property
    def is_terminal(self) -> bool:
        return self.status in TERMINAL_STATUSES

    @property
    def elapsed_seconds(self) -> Optional[int]:
        if not self.started_at:
            return None
        end = self.finished_at or _now()
        try:
            s = datetime.fromisoformat(self.started_at)
            e = datetime.fromisoformat(end)
            return int((e - s).total_seconds())
        except ValueError:
            return None


def _connect(db_path: Optional[Path] = None) -> sqlite3.Connection:
    path = db_path or _jobs_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.executescript(DDL)
    return conn


def _row_to_job(row: sqlite3.Row) -> Job:
    return Job(
        id=row["id"],
        project_name=row["project_name"],
        kind=row["kind"],
        target=row["target"],
        argv=json.loads(row["argv_json"]),
        status=JobStatus(row["status"]),
        created_at=row["created_at"],
        started_at=row["started_at"],
        finished_at=row["finished_at"],
        exit_code=row["exit_code"],
        pid=row["pid"],
        log_path=row["log_path"],
        run_dir=row["run_dir"],
        error=row["error"],
    )


def enqueue(job: Job, db_path: Optional[Path] = None) -> Job:
    conn = _connect(db_path)
    try:
        conn.execute(
            "INSERT INTO jobs (id, project_name, kind, target, argv_json, status, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (job.id, job.project_name, job.kind, job.target,
             json.dumps(job.argv), job.status.value, job.created_at),
        )
    finally:
        conn.close()
    return job


def get(job_id: str, db_path: Optional[Path] = None) -> Optional[Job]:
    conn = _connect(db_path)
    try:
        row = conn.execute("SELECT * FROM jobs WHERE id = ?", (job_id,)).fetchone()
    finally:
        conn.close()
    return _row_to_job(row) if row else None


def list_jobs(
    project_name: Optional[str] = None,
    status: Optional[JobStatus] = None,
    limit: int = 100,
    db_path: Optional[Path] = None,
) -> list[Job]:
    conn = _connect(db_path)
    try:
        sql = "SELECT * FROM jobs"
        where = []
        params: list = []
        if project_name:
            where.append("project_name = ?")
            params.append(project_name)
        if status:
            where.append("status = ?")
            params.append(status.value)
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        rows = conn.execute(sql, params).fetchall()
    finally:
        conn.close()
    return [_row_to_job(r) for r in rows]


def next_queued(db_path: Optional[Path] = None) -> Optional[Job]:
    conn = _connect(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM jobs WHERE status = ? ORDER BY created_at LIMIT 1",
            (JobStatus.QUEUED.value,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_job(row) if row else None


def mark_running(job_id: str, pid: int, log_path: Path, db_path: Optional[Path] = None) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE jobs SET status = ?, started_at = ?, pid = ?, log_path = ? WHERE id = ?",
            (JobStatus.RUNNING.value, _now(), pid, str(log_path), job_id),
        )
    finally:
        conn.close()


def mark_finished(
    job_id: str,
    exit_code: int,
    run_dir: Optional[str] = None,
    error: Optional[str] = None,
    db_path: Optional[Path] = None,
) -> None:
    status = JobStatus.COMPLETED if exit_code == 0 else JobStatus.FAILED
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE jobs SET status = ?, finished_at = ?, exit_code = ?, run_dir = ?, error = ? WHERE id = ?",
            (status.value, _now(), exit_code, run_dir, error, job_id),
        )
    finally:
        conn.close()


def mark_cancelled(job_id: str, db_path: Optional[Path] = None) -> None:
    conn = _connect(db_path)
    try:
        conn.execute(
            "UPDATE jobs SET status = ?, finished_at = ? WHERE id = ?",
            (JobStatus.CANCELLED.value, _now(), job_id),
        )
    finally:
        conn.close()


def log_path_for(job_id: str, log_dir: Optional[Path] = None) -> Path:
    d = log_dir or _log_dir()
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{job_id}.log"

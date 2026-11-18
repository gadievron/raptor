"""Background worker that executes queued raptor jobs.

Runs as a daemon thread inside the FastAPI process. Polls the jobs table for
queued entries, spawns raptor as a subprocess, and streams its stdout+stderr
to a per-job log file. Updates job status in SQLite across the lifecycle.

Kept deliberately minimal — for heavier workloads, replace with a real queue
(Celery, RQ, dramatiq) and swap this module out.
"""

from __future__ import annotations

import logging
import os
import signal
import subprocess
import threading
from pathlib import Path
from typing import Optional

from core.config import RaptorConfig
from packages.studio.config import RAPTOR_HOME, STUDIO_DATA_DIR
from packages.studio.services import jobs

logger = logging.getLogger("raptor-studio.worker")

# Loader / interpreter / credential-helper vars stripped from job envs on
# top of whatever RaptorConfig.get_safe_env() removes. On raptor versions
# where get_safe_env() is a blocklist these are the known gaps (PYTHONPATH
# injects into the python3 job process itself; the askpass/ssh hooks are
# exec'd by git and ssh against untrusted repos); on allowlist versions
# they are already gone and this is belt-and-braces.
_STRIPPED_HOST_ENV = (
    "PYTHONPATH", "PYTHONHOME", "PYTHONUSERBASE",
    "GIT_ASKPASS", "SSH_ASKPASS", "GIT_SSH", "GIT_SSH_COMMAND",
)

# Host variables deliberately preserved on top of RaptorConfig.get_safe_env().
# Jobs analyse untrusted repos, and inherited env is an injection surface
# (LD_PRELOAD, BASH_ENV, PAGER, ...) — so nothing here may be
# shell-evaluated or loader-consumed. Extend this list consciously; never
# fall back to os.environ wholesale.
_PRESERVED_HOST_ENV = (
    # Provider/API configuration raptor's LLM stack auto-detects
    # (see services/models_reader.py ENV_VARS).
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "MISTRAL_API_KEY",
    "OLLAMA_HOST",
    # GH Archive BigQuery credentials for /oss-forensics jobs.
    "GOOGLE_APPLICATION_CREDENTIALS",
    # Egress proxy config. A studio job is a top-level raptor invocation —
    # the equivalent of the operator launching raptor from their shell,
    # which carries these — so provider/API traffic must keep working on
    # proxied hosts. Values are URLs consumed by HTTP libraries, not
    # shell-evaluated.
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
    # Raptor's own models.json path override, so a job resolves the same
    # LLM config the UI shows.
    "RAPTOR_CONFIG",
    # Operator's custom CodeQL install; without these, studio-launched
    # /codeql jobs silently fall back to PATH lookup.
    "CODEQL_CLI",
    "CODEQL_QUERIES",
)

# Prefix families preserved wholesale. SAGE_* is the persistent-memory
# sidecar config (URL, timeouts, identity path) — plain values consumed
# by raptor's own SAGE client, never shell-evaluated.
_PRESERVED_HOST_ENV_PREFIXES = ("SAGE_",)


def _job_env() -> dict:
    """Build the environment for a raptor job subprocess.

    Starts from RAPTOR's sanitisation chokepoint (get_safe_env — a strict
    allowlist on current raptor, a blocklist on older versions), strips
    the loader/credential-helper gaps of the blocklist variant, and
    re-adds only the named provider/API and raptor path configuration
    jobs actually need.
    """
    env = RaptorConfig.get_safe_env()
    for name in _STRIPPED_HOST_ENV:
        env.pop(name, None)
    for name, value in os.environ.items():
        if name in _PRESERVED_HOST_ENV or name.startswith(_PRESERVED_HOST_ENV_PREFIXES):
            env[name] = value
    env["PYTHONUNBUFFERED"] = "1"
    return env

_stop_event = threading.Event()
_thread: Optional[threading.Thread] = None
_POLL_INTERVAL = 2.0
_active_pid: dict[str, int] = {}  # job_id -> pid (in-memory, for cancel signalling)


def _run_one_job(job: jobs.Job) -> None:
    log_path = jobs.log_path_for(job.id)
    try:
        # Open log file, start subprocess with stdout+stderr redirected.
        with log_path.open("w", buffering=1) as logfile:
            logfile.write(f"[raptor-studio] $ {' '.join(job.argv)}\n")
            logfile.write(f"[raptor-studio] cwd: {RAPTOR_HOME}\n")
            logfile.flush()

            env = _job_env()
            try:
                proc = subprocess.Popen(
                    job.argv,
                    stdout=logfile, stderr=subprocess.STDOUT,
                    cwd=str(RAPTOR_HOME) if RAPTOR_HOME.is_dir() else None,
                    env=env,
                    start_new_session=True,  # enables signalling the whole group on cancel
                )
            except FileNotFoundError as e:
                jobs.mark_finished(job.id, exit_code=127, error=str(e))
                return

            _active_pid[job.id] = proc.pid
            jobs.mark_running(job.id, pid=proc.pid, log_path=log_path)

            try:
                exit_code = proc.wait()
            finally:
                _active_pid.pop(job.id, None)

        # Try to locate the run output dir that raptor just created (best-effort).
        run_dir = _find_latest_run_dir_from_log(log_path)

        # If this job was cancelled from outside, preserve that status.
        current = jobs.get(job.id)
        if current and current.status == jobs.JobStatus.CANCELLED:
            return

        jobs.mark_finished(job.id, exit_code=exit_code, run_dir=run_dir)

    except Exception as e:  # pragma: no cover — defensive
        logger.exception("worker failed on job %s", job.id)
        try:
            jobs.mark_finished(job.id, exit_code=-1, error=str(e))
        except Exception:
            pass


def _find_latest_run_dir_from_log(log_path: Path) -> Optional[str]:
    """Best-effort extraction of raptor's output dir from the log tail.

    Raptor's scripts typically print something like
    'Output: out/scan_<repo>_<ts>/' — we scrape that from the log.
    """
    try:
        tail = log_path.read_text()[-4096:]
    except OSError:
        return None
    for marker in ("Output:", "Output directory:", "Results saved to"):
        idx = tail.find(marker)
        if idx != -1:
            rest = tail[idx + len(marker):].splitlines()[0].strip()
            if rest:
                return rest
    return None


def cancel(job_id: str) -> bool:
    """Signal a running job to stop.

    Marks the job cancelled in the DB and sends SIGTERM to the process
    group. Returns True if the process was still live when we signalled.
    """
    job = jobs.get(job_id)
    if not job or job.is_terminal:
        return False

    pid = _active_pid.get(job_id) or job.pid
    jobs.mark_cancelled(job_id)

    if not pid:
        return False
    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _loop() -> None:
    while not _stop_event.is_set():
        try:
            job = jobs.next_queued()
        except Exception:
            logger.exception("worker: failed to poll queue")
            _stop_event.wait(_POLL_INTERVAL)
            continue

        if job is None:
            _stop_event.wait(_POLL_INTERVAL)
            continue

        logger.info("worker: picking up job %s (%s)", job.id, job.kind)
        _run_one_job(job)


def start() -> None:
    """Idempotently start the worker thread."""
    global _thread
    if _thread and _thread.is_alive():
        return
    STUDIO_DATA_DIR.mkdir(parents=True, exist_ok=True)
    _stop_event.clear()
    _thread = threading.Thread(target=_loop, name="raptor-studio-worker", daemon=True)
    _thread.start()


def stop(timeout: float = 2.0) -> None:
    _stop_event.set()
    if _thread:
        _thread.join(timeout=timeout)

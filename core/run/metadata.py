"""Run metadata — .raptor-run.json lifecycle helpers.

Every run directory gets a .raptor-run.json file tracking what command
produced it, when, and whether it succeeded. Tools use start_run/complete_run/fail_run.
"""

import contextlib
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from core.json import load_json, save_json

RUN_METADATA_FILE = ".raptor-run.json"

# Status enum
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"

# Known command prefixes for inferring command type from directory names.
# Includes both legacy prefixes (raptor_, autonomous, exploitability-validation)
# and project-mode prefixes (agentic, validate, understand, fuzz, web).
_PREFIX_MAP = {
    # Scanning
    "scan": "scan",
    "codeql": "codeql",
    # Agentic (legacy: raptor_, autonomous)
    "agentic": "agentic",
    "raptor_": "agentic",
    "autonomous": "agentic",
    # Validation (legacy: exploitability-validation)
    "validate": "validate",
    "exploitability-validation": "validate",
    # Other commands
    "understand": "understand",
    "code-understanding": "understand",
    "fuzz": "fuzz",
    "web": "web",
    "crash-analysis": "crash-analysis",
    "oss-forensics": "oss-forensics",
}


def _find_claude_ancestor() -> Optional[int]:
    """Walk the process tree to find the nearest 'claude' ancestor PID.

    Returns the PID of the claude process, or None if not found.
    Works from any depth: Bash tool calls, hooks, Python subprocesses.
    """
    pid = os.getpid()
    for _ in range(20):
        try:
            pid = os.getppid() if pid == os.getpid() else _read_ppid(pid)
        except (OSError, ValueError):
            return None
        if pid <= 1:
            return None
        try:
            comm = Path(f"/proc/{pid}/comm").read_text().strip()
        except OSError:
            return None
        if comm == "claude":
            return pid
    return None


def _read_ppid(pid: int) -> int:
    """Read PPID from /proc/<pid>/stat (Linux-only)."""
    stat = Path(f"/proc/{pid}/stat").read_text()
    # Format: pid (comm) state ppid ...
    # comm can contain spaces/parens, so find the last ')' first
    close_paren = stat.rfind(")")
    fields = stat[close_paren + 2:].split()
    return int(fields[1])  # ppid is field index 1 after state


def _get_session_pid() -> Optional[int]:
    """Get the PID of the Claude Code session process.

    Walks the ancestor tree to find the 'claude' process rather than
    using getppid(), because the immediate parent varies by context
    (Bash tool shell, hook sh wrapper, Python subprocess).
    Falls back to CLAUDECODE env var check + getppid() on non-Linux.
    """
    ancestor = _find_claude_ancestor()
    if ancestor is not None:
        return ancestor
    if not os.environ.get("CLAUDECODE"):
        return None
    return os.getppid()


def _pid_alive(pid: int) -> bool:
    """Check if a process is alive. Returns False for invalid PIDs."""
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # alive but owned by another user


def start_run(output_dir: Path, command: str, extra: Dict[str, Any] = None,
              target: str = None) -> Path:
    """Write initial .raptor-run.json with status=running.

    Call this at the start of a command. Returns the output_dir (for chaining).
    Creates the directory if it doesn't exist. In project mode, creates a
    checklist.json symlink pointing to the project-level checklist.

    Records the session PID so sweep can check if the session is still alive.
    Also marks any abandoned runs from the same session and command type as
    failed (handles the Esc-then-retry scenario).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    session_pid = _get_session_pid()

    # Clean up abandoned runs: same session, same command type, still "running"
    if session_pid is not None:
        _cleanup_abandoned(output_dir.parent, command, session_pid)

    metadata = {
        "version": 1,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": STATUS_RUNNING,
        "extra": extra or {},
    }
    if session_pid is not None:
        metadata["session_pid"] = session_pid
        metadata["tool_pid"] = os.getppid()
    if target:
        metadata["target_path"] = str(target)
    # Mark this run as the active sandbox-summary recording target before
    # any further setup work — guarantees that any sandbox calls made by
    # _setup_checklist_symlink (or anything else added later between save_json
    # and return) get recorded into this run's summary.
    # Lazy import to avoid circular core.sandbox load on metadata import.
    from core.sandbox.summary import set_active_run_dir
    set_active_run_dir(output_dir)
    save_json(output_dir / RUN_METADATA_FILE, metadata)
    _setup_checklist_symlink(output_dir)
    return output_dir


def _cleanup_abandoned(project_dir: Path, command: str, session_pid: int) -> None:
    """Mark abandoned runs from the same session and command type as failed.

    An abandoned run is one that has status=running, same session_pid (same
    Claude Code session), and same command type. This happens when the user
    presses Esc and retries the same command.
    """
    try:
        if not project_dir.is_dir():
            return
        children = list(project_dir.iterdir())
    except OSError:
        # Parent dir may be a system-managed directory the current user
        # can't read (e.g., /tmp containing systemd-private-* siblings,
        # NFS with restricted ACLs). The cleanup is a best-effort tidy
        # of *our* past runs; if we can't enumerate, skip and let the
        # caller proceed.
        return
    for d in children:
        try:
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            meta_path = d / RUN_METADATA_FILE
            if not meta_path.exists():
                continue
            meta = load_json(meta_path)
        except OSError:
            # Per-child stat may fail even after iterdir succeeded.
            continue
        if not meta:
            continue
        if (meta.get("status") == STATUS_RUNNING
                and meta.get("command") == command
                and meta.get("session_pid") == session_pid):
            fail_run(d, "abandoned — replaced by new run in same session",
                     record_timing=False)


def _setup_checklist_symlink(run_dir: Path) -> None:
    """Create a checklist.json symlink in the run dir pointing to the project-level checklist.

    Only acts in project mode (active project detected via .active symlink).
    In standalone mode, does nothing.

    If no project-level checklist exists yet, promotes the newest run-level
    checklist from sibling run dirs.
    """

    # Determine project output dir from .active symlink only
    project_dir = None
    try:
        from core.startup import PROJECTS_DIR, get_active_name
        name = get_active_name()
        if name:
            from core.json import load_json as _load
            data = _load(PROJECTS_DIR / f"{name}.json")
            if data:
                candidate = Path(data.get("output_dir", ""))
                if candidate.is_dir():
                    project_dir = candidate
    except Exception:
        pass

    if not project_dir:
        return  # Standalone mode

    # Don't create symlink if a real checklist already exists in the run dir
    checklist_in_run = run_dir / "checklist.json"
    if checklist_in_run.exists() and not checklist_in_run.is_symlink():
        return

    # Don't create symlink if it already exists
    if checklist_in_run.is_symlink():
        return

    # Promote: if no project-level checklist, find the newest run-level one
    project_checklist = project_dir / "checklist.json"
    if not project_checklist.exists():
        _promote_checklist(project_dir)

    # Create relative symlink: run_dir/checklist.json → ../checklist.json
    try:
        checklist_in_run.symlink_to("../checklist.json")
    except OSError:
        pass  # Silently skip if symlink creation fails


def _promote_checklist(project_dir: Path) -> None:
    """Copy the newest run-level checklist to the project level.

    Scans sibling run dirs for checklist.json files. Takes the newest
    and copies it to project_dir/checklist.json, merging checked_by
    from older checklists.
    """
    from core.json import load_json, save_json

    try:
        children = list(project_dir.iterdir())
    except OSError:
        return

    def _safe_mtime(d: Path) -> float:
        try:
            return d.stat().st_mtime
        except OSError:
            return 0.0

    checklists = []
    for d in sorted(children, key=_safe_mtime, reverse=True):
        try:
            if not d.is_dir() or d.name.startswith((".", "_")):
                continue
            cl = d / "checklist.json"
            if not cl.exists() or cl.is_symlink():
                continue
        except OSError:
            continue
        data = load_json(cl)
        if data:
            checklists.append(data)

    if not checklists:
        return

    # Start with newest, merge checked_by from older ones
    promoted = checklists[0]
    if len(checklists) > 1:
        from core.inventory.builder import _carry_forward_coverage
        for older in checklists[1:]:
            _carry_forward_coverage(older, promoted)

    save_json(project_dir / "checklist.json", promoted)


def _finalize_sandbox_summary(output_dir: Path) -> None:
    """Write sandbox-summary.json (if any denials recorded) and clear the
    active-run state. Called from every terminal-state transition so the
    summary lands regardless of how the run ended.

    Broad except: lifecycle hooks must never raise out of complete_run /
    fail_run / cancel_run on account of summary-write failures. Today
    summarize_and_write catches its own OSErrors and returns None, but a
    future change introducing a different exception path shouldn't break
    the lifecycle. The active-run state is always cleared in finally.
    """
    # Lazy import to keep core.sandbox out of metadata import time.
    from core.sandbox.summary import (
        summarize_and_write, set_active_run_dir, SUMMARY_FILE,
    )
    import logging
    log = logging.getLogger(__name__)
    try:
        result = summarize_and_write(output_dir)
        # Discoverability: if denials were captured, tell operators
        # where the report is + how many entries. Silent when no denials
        # (don't add chatter to clean runs).
        if result is not None:
            log.info(
                "sandbox: %d denials this run → %s",
                result.get("total_denials", 0),
                output_dir / SUMMARY_FILE,
            )
    except Exception:  # noqa: BLE001 — never fail lifecycle on summary error
        # Debug-only log so a developer can find swallowed exceptions
        # when investigating "why is my summary missing?". INFO would be
        # too noisy if the failure is recurrent.
        log.debug(
            "_finalize_sandbox_summary: summarize_and_write failed",
            exc_info=True,
        )
    finally:
        # Always clear active-run state, even if summary write failed —
        # otherwise subsequent runs would record into a stale path.
        set_active_run_dir(None)


# Sandbox summary is finalized BEFORE the status update in every terminal-
# state transition. If the process crashes between the two:
#  - finalize-then-status-update path: status stays "running", summary on
#    disk. A later cleanup-of-stale-runs marks the status appropriately;
#    summary is already there. No data lost.
#  - status-update-then-finalize path (the alternative): status flips to
#    "completed" but no summary; reader assumes "no denials" because no
#    file. Misleading.
# Finalizing first preserves the data; status update is just the signal.

def complete_run(output_dir: Path, extra: Dict[str, Any] = None) -> None:
    """Update .raptor-run.json to status=completed."""
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_COMPLETED, extra)


def fail_run(output_dir: Path, error: str = None, extra: Dict[str, Any] = None,
             record_timing: bool = True) -> None:
    """Update .raptor-run.json to status=failed."""
    extra = extra or {}
    if error:
        extra["error"] = error
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_FAILED, extra, record_timing=record_timing)


def cancel_run(output_dir: Path, extra: Dict[str, Any] = None) -> None:
    """Update .raptor-run.json to status=cancelled."""
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_CANCELLED, extra)


@contextlib.contextmanager
def tracked_run(output_dir: Path, command: str, extra: Dict[str, Any] = None):
    """Context manager for run lifecycle. Writes metadata automatically.

    Usage:
        with tracked_run(out_dir, "agentic") as run_dir:
            # do work...
        # .raptor-run.json: completed on success, failed on exception, cancelled on Ctrl-C
    """
    run_dir = start_run(output_dir, command, extra)
    try:
        yield run_dir
        complete_run(run_dir)
    except KeyboardInterrupt:
        cancel_run(run_dir)
        raise
    except Exception as e:
        fail_run(run_dir, error=str(e))
        raise


def load_run_metadata(run_dir: Path) -> Optional[Dict[str, Any]]:
    """Load .raptor-run.json from a run directory. Returns None if missing."""
    return load_json(run_dir / RUN_METADATA_FILE)


def is_run_directory(path: Path) -> bool:
    """Check if a directory looks like a RAPTOR run output.

    True if it has .raptor-run.json, or matches known naming patterns,
    or contains typical output files.
    """
    if not path.is_dir():
        return False

    # Has metadata file
    if (path / RUN_METADATA_FILE).exists():
        return True

    # Matches known prefix patterns
    name = path.name
    if any(name.startswith(prefix) for prefix in _PREFIX_MAP):
        return True

    # Contains typical output files
    typical_files = {"findings.json", "checklist.json", "scan_metrics.json",
                     "orchestrated_report.json", "validation-report.md"}
    if any((path / f).exists() for f in typical_files):
        return True

    return False


def infer_command_type(run_dir: Path) -> str:
    """Infer the command type from a run directory.

    Checks .raptor-run.json first, falls back to directory name prefix.
    """
    # Check metadata file
    metadata = load_run_metadata(run_dir)
    if metadata and metadata.get("command"):
        return metadata["command"]

    # Infer from directory name
    name = run_dir.name
    for prefix, cmd_type in _PREFIX_MAP.items():
        if name.startswith(prefix):
            return cmd_type

    return "unknown"


def generate_run_metadata(run_dir: Path) -> None:
    """Generate .raptor-run.json for a directory that doesn't have one.

    Used when adopting existing directories into a project. Infers
    command type from directory name and timestamp from directory mtime.
    """
    if (run_dir / RUN_METADATA_FILE).exists():
        return

    command = infer_command_type(run_dir)

    # Try to get timestamp from directory name (e.g. scan-20260406-100000)
    timestamp = parse_timestamp_from_name(run_dir.name)
    if not timestamp:
        # Fall back to directory modification time
        mtime = run_dir.stat().st_mtime
        timestamp = datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()

    metadata = {
        "version": 1,
        "command": command,
        "timestamp": timestamp,
        "status": STATUS_COMPLETED,  # Assume completed if it exists
        "extra": {"adopted": True},
    }

    save_json(run_dir / RUN_METADATA_FILE, metadata)


def _update_status(output_dir: Path, status: str, extra: Dict[str, Any] = None,
                   record_timing: bool = True) -> None:
    """Update the status field in .raptor-run.json.

    When record_timing is True (default), also records end_timestamp and
    duration_seconds. Set to False for sweep/cleanup where the run ended
    at an unknown earlier time.

    Raises FileNotFoundError if metadata file doesn't exist (call start_run first).
    """
    path = Path(output_dir) / RUN_METADATA_FILE
    metadata = load_json(path)
    if metadata is None:
        raise FileNotFoundError(f"No {RUN_METADATA_FILE} in {output_dir} — call start_run() first")
    metadata["status"] = status

    if record_timing:
        now = datetime.now(timezone.utc)
        metadata["end_timestamp"] = now.isoformat()
        start_ts = metadata.get("timestamp")
        if start_ts:
            try:
                start_dt = datetime.fromisoformat(start_ts)
                metadata["duration_seconds"] = round((now - start_dt).total_seconds(), 1)
            except (ValueError, TypeError):
                pass

    if extra:
        existing_extra = metadata.get("extra", {})
        existing_extra.update(extra)
        metadata["extra"] = existing_extra
    save_json(path, metadata)


def parse_timestamp_from_name(name: str) -> Optional[str]:
    """Try to extract an ISO timestamp from a directory name.

    Matches patterns like:
    - scan-20260406-100000
    - scan_vulns_20260406_100000
    - exploitability-validation-20260406-100000
    """
    # Look for YYYYMMDD_HHMMSS or YYYYMMDD-HHMMSS
    match = re.search(r'(\d{4})(\d{2})(\d{2})[_-](\d{2})(\d{2})(\d{2})', name)
    if match:
        y, mo, d, h, mi, s = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    # Look for YYYYMMDD only
    match = re.search(r'(\d{4})(\d{2})(\d{2})', name)
    if match:
        y, mo, d = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    return None

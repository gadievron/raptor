"""Run metadata — .raptor-run.json lifecycle helpers.

Every run directory gets a .raptor-run.json file tracking what command
produced it, when, and whether it succeeded. Tools use start_run/complete_run/fail_run.
"""

import contextlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.json import load_json, save_json

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

RUN_METADATA_FILE = ".raptor-run.json"

# Status enum
STATUS_RUNNING = "running"
STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_CANCELLED = "cancelled"
# Interrupted: the run was stopped by an external supervisor (SIGTERM
# grace drain, harness background-shell cap) with its artifacts intact.
# Terminal for the double-finalisation guard, but explicitly resumable
# via resume_run() — and deliberately NOT reaped by
# core.run.tmp_reaper.reap_stale_runs (failed/cancelled only).
STATUS_INTERRUPTED = "interrupted"

# `_cleanup_abandoned` freshness threshold. A sibling run in
# status=running that was created within this many seconds is treated
# as a concurrent in-flight run, not as an Esc-then-retry abandon.
# 30s is comfortably longer than any spawn-to-first-checkpoint
# window (sandbox setup + tool init typically completes in a few
# seconds) but tighter than a real abandon (Esc-cancelled runs sit
# in 'running' state until the session terminates, often hours).
_ABANDON_FRESHNESS_S = 30.0

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
    # Dynamic instrumentation
    "frida": "frida",
    # Other commands
    "understand": "understand",
    "code-understanding": "understand",
    "fuzz": "fuzz",
    "web": "web",
    "crash-analysis": "crash-analysis",
    "oss-forensics": "oss-forensics",
}


def _find_claude_ancestor() -> int | None:
    """Walk the process tree to find the nearest 'claude' ancestor PID.

    Returns the PID of the claude process, or None if not found.
    Works from any depth: Bash tool calls, hooks, Python subprocesses.
    Uses /proc on Linux, ps(1) on macOS.
    """
    import sys
    pid = os.getpid()
    for _ in range(20):
        try:
            pid = os.getppid() if pid == os.getpid() else _read_ppid(pid)
        except (OSError, ValueError, IndexError):
            return None
        if pid <= 1:
            return None
        try:
            if sys.platform == "linux":
                comm = Path(f"/proc/{pid}/comm").read_text(
                    encoding="utf-8"
                ).strip()
            else:
                comm = _read_comm_ps(pid)
                if comm is None:
                    return None
        except OSError:
            return None
        if comm == "claude":
            return pid
    return None


def _read_comm_ps(pid: int) -> str | None:
    """Read process name via ps(1) — portable fallback for non-Linux."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["ps", "-o", "comm=", "-p", str(pid)],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        return out.strip().rsplit("/", 1)[-1]
    except (subprocess.SubprocessError, OSError):
        return None


def _read_ppid(pid: int) -> int:
    """Read PPID — /proc on Linux, ps(1) elsewhere.

    Race-aware error wrapping. If a PID disappears mid-walk,
    raises ProcessLookupError so callers handle "ancestor died" via
    one well-known exception type.
    """
    import sys
    if sys.platform != "linux":
        return _read_ppid_ps(pid)
    try:
        stat = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise ProcessLookupError(
            f"_read_ppid: /proc/{pid}/stat vanished — process exited"
        ) from exc
    except PermissionError:
        raise
    except OSError as exc:
        raise ProcessLookupError(
            f"_read_ppid: /proc/{pid}/stat unreadable: {exc}"
        ) from exc
    # Format: pid (comm) state ppid ...
    close_paren = stat.rfind(")")
    fields = stat[close_paren + 2:].split()
    return int(fields[1])


def _read_ppid_ps(pid: int) -> int:
    """Read PPID via ps(1) — portable fallback."""
    import subprocess
    try:
        out = subprocess.check_output(
            ["ps", "-o", "ppid=", "-p", str(pid)],
            text=True, timeout=5, stderr=subprocess.DEVNULL,
        )
        return int(out.strip())
    except (subprocess.SubprocessError, OSError, ValueError) as exc:
        raise ProcessLookupError(
            f"_read_ppid_ps: ps failed for pid {pid}: {exc}"
        ) from exc


def _get_session_pid() -> int | None:
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
    """Check if a process is alive AND looks like the original.

    Returns False for invalid PIDs.

    PID-reuse hazard: a session_pid recorded yesterday (Claude Code
    session A, PID 12345). Session A exits; the kernel reuses PID
    12345 for an unrelated process (a cron job, an editor, any
    long-lived daemon). Plain `os.kill(pid, 0)` returns True for the
    wrong process. `_cleanup_abandoned` then treats the long-dead
    Claude Code session as still alive and skips legitimate cleanup
    of its abandoned runs.

    Cross-check with `/proc/<pid>/comm` on Linux: if the running
    process at that PID isn't named `claude` (or a `claude*` variant
    — `claude-code`, `claude.sh` wrapper, etc.), it's not the
    session that recorded the run. Treat as dead so cleanup can
    proceed.

    Falls back to plain `os.kill(pid, 0)` on non-Linux (no /proc) —
    accepts the residual PID-reuse risk on macOS/BSD where the
    canonical /proc isn't available.
    """
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # alive but owned by another user

    # Process exists at that PID. On Linux, verify it's still a
    # claude-shaped process — `comm` is the binary basename truncated
    # to 16 chars (TASK_COMM_LEN), so we substring-match `claude`.
    proc_comm = Path(f"/proc/{pid}/comm")
    if not proc_comm.exists():
        # Non-Linux or `/proc` not mounted — best-effort accept.
        return True
    try:
        comm = proc_comm.read_text(encoding="utf-8", errors="replace").strip().lower()
    except OSError:
        return True
    return "claude" in comm


def _tool_pid_alive(pid: Any) -> bool:
    """Liveness check for a run's recorded ``tool_pid`` (the worker
    process that called ``start_run`` — a Bash-tool shell, a Python
    orchestrator, etc.).

    Unlike :func:`_pid_alive` there is NO ``comm == claude`` cross-check:
    the tool process is deliberately NOT a claude binary. Plain
    ``kill(pid, 0)`` accepts a residual PID-reuse risk, but the failure
    direction is safe — a reused PID keeps a genuinely abandoned run in
    ``running`` state until its owning session dies (the dead-session
    branch then sweeps it), whereas a false "dead" would fail a live run.

    Missing / malformed pids return False so legacy metadata (written
    before ``tool_pid`` was recorded) falls back to the old behaviour.
    """
    if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # alive but owned by another user
    return True


@contextlib.contextmanager
def _metadata_lock(meta_path: Path):
    """Cross-process exclusive lock guarding a ``.raptor-run.json``
    read-modify-write window.

    Same idiom as ``core.coverage.store.coverage_store_lock``: flock a
    sibling ``.lock`` file (not the JSON itself, which ``save_json``
    atomically replaces), hold it across the whole load → mutate → save
    window, degrade to a no-op without fcntl (non-POSIX). Without it,
    concurrent ``_update_status`` writers (a run's own completion racing
    a sweep's ``fail_run``, or parallel workers updating ``extra``)
    last-writer-wins and one update is silently dropped.

    The ``.lock`` file is deliberately left behind (one zero-byte
    sibling per run dir): unlinking after unlock races — another
    process may already hold an fd to the old inode while a third
    creates a fresh file at the path, splitting lockers across two
    inodes and silently breaking mutual exclusion.
    """
    if not _HAS_FCNTL:
        yield
        return
    path = Path(meta_path)
    lock_path = path.with_suffix(path.suffix + ".lock")
    try:
        fd = os.open(str(lock_path), os.O_WRONLY | os.O_CREAT, 0o600)
    except OSError:
        # Lock file uncreatable (read-only dir mid-teardown, ENOSPC) —
        # proceed unserialised rather than failing the lifecycle.
        yield
        return
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def start_run(output_dir: Path, command: str,
              extra: dict[str, Any] | None = None,
              target: str | None = None,
              target_identity: dict[str, Any] | None = None) -> Path:
    """Write initial .raptor-run.json with status=running.

    Call this at the start of a command. Returns the output_dir (for chaining).
    Creates the directory if it doesn't exist. In project mode, creates a
    checklist.json symlink pointing to the project-level checklist.

    Records the session PID so sweep can check if the session is still alive.
    Also marks any abandoned runs from the same session and command type as
    failed (handles the Esc-then-retry scenario).
    """
    from core.run.safe_io import safe_run_mkdir

    output_dir = Path(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    safe_run_mkdir(output_dir)

    session_pid = _get_session_pid()

    # Clean up abandoned runs: same session, same command type, still "running"
    if session_pid is not None:
        _cleanup_abandoned(output_dir.parent, command, session_pid)

    # Sweep temp artifacts orphaned by earlier hard-killed runs — their
    # atexit/exit-path cleanups never fire on SIGKILL/OOM/SIGTERM —
    # aged-out per-process audit logs (opt-in via
    # RAPTOR_LOG_REAP_MAX_AGE_D; audit data is never deleted by
    # default), and aged-out failed/cancelled sibling run dirs
    # (completed runs are results and are never age-reaped).
    from core.run.tmp_reaper import (
        reap_stale_logs,
        reap_stale_runs,
        reap_stale_tmp,
    )

    reap_stale_tmp()
    reap_stale_logs()
    reap_stale_runs(output_dir.parent)

    # Seal the provenance manifest NOW, before any analysis runs. The
    # source-control snapshot in particular must be taken here — the tree
    # can change mid-run or after, and the only honest record of what
    # produced this run is the state at its start. complete_run merges in
    # end-of-run facts (models that fired, engine versions).
    from core.run.provenance import build_start_manifest

    metadata = {
        "version": 2,
        "command": command,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status": STATUS_RUNNING,
        "manifest": build_start_manifest(target=target, target_identity=target_identity),
        "extra": extra or {},
    }
    if session_pid is not None:
        metadata["session_pid"] = session_pid
        metadata["tool_pid"] = os.getppid()
    if target:
        metadata["target_path"] = str(target)
    # Order: persist metadata FIRST, then mark as active.
    #
    # Pre-fix `set_active_run_dir(output_dir)` ran BEFORE `save_json`.
    # If `save_json` crashed (disk full, EIO, permission flip), the
    # "active run dir" pointer was already set to a directory with
    # no metadata file. Subsequent sandbox-summary writes (and any
    # other consumer that resolves "the active run") would target
    # a directory the rest of the system can't recognise as a real
    # run — `is_run_directory()` returns False, recovery / sweep
    # logic doesn't see it.
    #
    # Persist first; mark active only on success. The original
    # justification (sandbox calls inside `_setup_checklist_symlink`
    # need the active dir set) still holds for those — they run
    # AFTER the active-dir set, which now happens AFTER the
    # metadata write, so the timing window for that case is
    # unchanged.
    #
    # Lazy import to avoid circular core.sandbox load on metadata import.
    from core.sandbox.summary import set_active_run_dir
    save_json(output_dir / RUN_METADATA_FILE, metadata)
    set_active_run_dir(output_dir)
    _setup_checklist_symlink(output_dir)
    return output_dir


def _cleanup_abandoned(project_dir: Path, command: str, session_pid: int) -> None:
    """Mark abandoned sibling runs as failed.

    Two abandonment shapes, both status=running and past the freshness
    gate:

    - Same session_pid AND same command type AND the run's recorded
      worker (``tool_pid``) is dead — the Esc-then-retry case (user
      cancelled and reissued the same command in one session). The
      worker-liveness gate keeps long-lived parallel runs of the same
      command in the same session from being false-failed.
    - Owning session DEAD — the recorded session_pid no longer maps to
      a live claude process (session SIGKILL'd, machine rebooted, or
      PID recycled by something else). No live owner means no lifecycle
      hook will ever finalize the run: without this branch such runs
      sat in status=running forever, regardless of command type. The
      current session's own runs are excluded (its in-flight runs of
      OTHER command types are healthy).

    Recent siblings (created within ``_ABANDON_FRESHNESS_S`` seconds)
    are LEFT ALONE even on the (session_pid, command) match. Pre-fix
    a user issuing two commands of the same type in close succession
    (or two parallel `/scan`s from the same Claude Code session in
    different terminals) saw the new run mark the in-flight earlier
    one as failed — exactly the wrong behaviour. The Esc-cancel case
    the function is meant to handle leaves stale runs measured in
    minutes, not seconds, so the freshness gate distinguishes
    cleanly.
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

    now = datetime.now(timezone.utc)
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
        if meta.get("status") != STATUS_RUNNING:
            continue
        run_session = meta.get("session_pid")
        # Same-session retry additionally requires the run's own worker
        # (``tool_pid``, recorded at start_run) to be DEAD. The freshness
        # gate alone is not enough: a legitimate parallel run of the same
        # command in the same session that has been going for more than
        # _ABANDON_FRESHNESS_S seconds would otherwise be failed here,
        # and the terminal-status guard in _update_status would then
        # refuse its real completion — misfiling a live run's results.
        # An Esc-cancelled run's tool process IS dead, so the case this
        # branch exists for still cleans up. Runs predating tool_pid
        # recording have no pid and keep the old (freshness-only) gate.
        same_session_retry = (
            meta.get("command") == command
            and run_session == session_pid
            and not _tool_pid_alive(meta.get("tool_pid"))
        )
        session_dead = (
            isinstance(run_session, int)
            and run_session != session_pid
            and not _pid_alive(run_session)
        )
        if same_session_retry or session_dead:
            # Freshness gate — skip recent siblings (probable
            # concurrent in-flight run, NOT an abandon; for the
            # dead-session branch it also absorbs the window where
            # a just-spawned run's owning session is still booting).
            ts_str = meta.get("timestamp")
            if isinstance(ts_str, str):
                try:
                    started = datetime.fromisoformat(ts_str)
                    if started.tzinfo is None:
                        started = started.replace(tzinfo=timezone.utc)
                    age_s = (now - started).total_seconds()
                    if age_s < _ABANDON_FRESHNESS_S:
                        continue
                except ValueError:
                    # Malformed timestamp — fall through to fail_run
                    # (the run is questionable either way).
                    pass
            reason = (
                "abandoned — replaced by new run in same session"
                if same_session_retry
                else "abandoned — owning session terminated"
            )
            fail_run(d, reason, record_timing=False)


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
            if isinstance(data, dict):
                candidate_str = data.get("output_dir") or ""
                candidate = Path(candidate_str) if candidate_str else None
                if candidate and candidate.is_dir():
                    project_dir = candidate
    except (FileNotFoundError, ImportError, json.JSONDecodeError, KeyError, PermissionError) as exc:
        # Narrowed from bare Exception. Pre-fix a corrupt project
        # JSON, a renamed field, or a PermissionError on PROJECTS_DIR
        # all silently degraded to standalone mode — runs that
        # should have been filed under an active project went into
        # bare out/, and operators only noticed when /project status
        # didn't include the run. Surface the cause.
        from core.logging import get_logger as _get_logger
        _get_logger().warning(
            "run.metadata: active-project lookup failed (%s); "
            "treating as standalone",
            exc,
        )

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
    #
    # TOCTOU window note: between the existence check above and the
    # symlink_to call below, a parallel start_run() (same project,
    # same wall-clock instant) can race in and create EITHER a real
    # file or a symlink at this path. `symlink_to` then raises
    # FileExistsError, caught by the except below.
    #
    # Pre-fix `except OSError: pass` swallowed that silently. Two
    # downstream consequences:
    #   * Operator debugging "why is my run dir missing the
    #     checklist symlink" had no log signal — they had to read
    #     the source to find this branch.
    #   * EACCES, ENOSPC, EROFS (real failure modes that aren't
    #     a race) were also silently swallowed, masking real
    #     project-state corruption.
    #
    # Log at debug for the race case (FileExistsError), warning for
    # real OS failures so operators can grep for them.
    try:
        checklist_in_run.symlink_to("../checklist.json")
    except FileExistsError:
        # Lost the race — the other process's checklist (real or
        # symlinked) is now in place. Either is correct end state;
        # debug-log so the race is visible if anyone looks.
        from core.logging import get_logger
        get_logger(__name__).debug(
            "checklist symlink already created by parallel start_run "
            "in %s — leaving it in place", run_dir,
        )
    except OSError as exc:
        from core.logging import get_logger
        get_logger(__name__).warning(
            "checklist symlink creation failed in %s (%s) — "
            "downstream consumers will see no checklist for this run",
            run_dir, exc,
        )


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

    # Sort key: (mtime, name) so identical mtimes break deterministically
    # by directory name. Pre-fix the sort was on `_safe_mtime` alone;
    # filesystems with second-resolution timestamps (or two start_run()
    # calls in the same wall-clock second under unique_run_suffix's
    # 4-digit ns tail) produced ties whose ordering then depended on
    # `iterdir()`'s undefined traversal order. The "newest" checklist
    # promoted to the project level then varied across re-promotion
    # passes for the SAME on-disk state — operators saw checked_by
    # state mysteriously disappear / reappear because a different
    # checklist became "newest" each time. Run-dir names embed a
    # PID + monotonic-ns tail (see core/run/output.unique_run_suffix),
    # so name-tie-break gives a chronologically meaningful disambiguation.
    checklists = []
    for d in sorted(children, key=lambda d: (_safe_mtime(d), d.name), reverse=True):
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
    import logging

    from core.sandbox.summary import (
        SUMMARY_FILE,
        get_active_run_dir,
        set_active_run_dir,
        summarize_and_write,
    )
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
    except Exception:
        # Debug-only log so a developer can find swallowed exceptions
        # when investigating "why is my summary missing?". INFO would be
        # too noisy if the failure is recurrent.
        log.debug(
            "_finalize_sandbox_summary: summarize_and_write failed",
            exc_info=True,
        )
    finally:
        # Clear active-run state ONLY if the active dir is the one we
        # just finalised. Pre-fix this unconditionally cleared, which
        # corrupted concurrent-run accounting: if run A's _finalize
        # fired while run B was already the active dir (A and B
        # overlapped because A's lifecycle ended slightly later than
        # its work, or sweep ran A's finaliser concurrently with B's
        # work), every B-side denial after A's finalise was dropped
        # silently. Compare paths via .resolve() so the same dir
        # reached via two paths still matches.
        try:
            active = get_active_run_dir()
            if active is not None and Path(active).resolve() == Path(output_dir).resolve():
                set_active_run_dir(None)
        except OSError:
            # Path resolution failed (deleted dir, permission error)
            # — clear conservatively so the active-pointer doesn't
            # stay pinned to an unreachable target.
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

def complete_run(output_dir: Path, extra: dict[str, Any] | None = None,
                 manifest: dict[str, Any] | None = None) -> None:
    """Update .raptor-run.json to status=completed.

    ``manifest`` merges end-of-run provenance into the manifest sealed at
    start_run. Top-level keys overwrite; the start-sealed source_control /
    environment snapshots are preserved unless explicitly overwritten.

    Standard end-of-run provenance the lifecycle can derive itself — engine
    versions (``detect_engines``) and ``deterministically_reproducible`` (from
    the command) — is filled automatically for EVERY completion path, so a
    caller only needs to pass the facts unique to it (the models that fired).
    Callers still win on conflict: an explicitly-passed key is never clobbered.
    """
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_COMPLETED, extra, manifest=manifest)
    # Materialise the LLM read-coverage record from the plugin's .reads-manifest
    # FIRST, so the snapshot below imports it alongside the scanner records.
    _convert_reads_manifest(output_dir)
    # Stamp findings with provenance_refs back to this run's manifest. Must run
    # AFTER _update_status (manifest sealed) and BEFORE _snapshot_run_coverage
    # (coverage importer pulls findings into the store; we want them stamped
    # by then). Best-effort: a stamping failure must not fail the lifecycle.
    _stamp_findings_provenance(output_dir)
    # Snapshot AFTER the status/manifest write so coverage provenance can read
    # the sealed manifest (engine versions / resolved models).
    _snapshot_run_coverage(output_dir)


def _stamp_findings_provenance(output_dir: Path) -> None:
    """Best-effort: stamp every finding in this run's ``findings.json`` (and
    ``sca/findings.json``) with a ``provenance_refs`` field pointing back to
    the run's manifest, so downstream consumers (``/project correlate``, the
    citation view, audit reports) can trace each finding to the run that
    produced it.

    Idempotent (re-runs do nothing). Never raises — lifecycle hooks must not
    fail on a stamping error. See ``core/run/findings.py``.
    """
    import logging
    try:
        from core.run.findings import stamp_findings_in_run
        stamp_findings_in_run(Path(output_dir))
    except Exception:
        logging.getLogger(__name__).debug(
            "_stamp_findings_provenance failed for %s", output_dir, exc_info=True
        )


def _convert_reads_manifest(output_dir: Path) -> None:
    """Turn the coverage plugin's ``.reads-manifest`` (the files the LLM read
    this run, captured by the PostToolUse-on-Read hook) into a
    ``coverage-read.json`` record so LLM read-extent reaches the store.

    Labelled ``read`` (not ``llm``): a whole-file *read* is shallow coverage —
    it is NOT a function-level review. The store distinguishes read from
    reviewed by depth, so a file the LLM merely read still surfaces in the
    LLM-review gap (the gap /audit fills). The plugin captures the reads but
    nothing converted them — this wires that conversion at run completion.
    Best-effort: a missing/empty manifest is a no-op, and a failure must never
    break the lifecycle.
    """
    import logging
    try:
        from core.coverage.record import build_from_manifest, write_record
        record = build_from_manifest(Path(output_dir), "read")
        if record:
            write_record(Path(output_dir), record, tool_name="read")
    except Exception:
        logging.getLogger(__name__).debug(
            "_convert_reads_manifest failed for %s", output_dir, exc_info=True
        )


def _snapshot_run_coverage(output_dir: Path) -> None:
    """Best-effort: fold a just-completed run's coverage into the project's
    durable ``coverage.json`` so it survives out-of-band deletion of the run
    dir (manual ``rm``, tmpfs) — not only ``/project clean``.

    Scoped to THIS run's records + findings (bounded cost); project-level
    ``checked_by`` / annotations live in the project checklist and are captured
    by the on-demand ``--store`` union, surviving deletion regardless. No-op
    for a standalone ``out/`` run (no project store). The coverage.json
    read-modify-write is taken under :func:`coverage_store_lock` so parallel
    run completions (and a concurrent clean) can't last-writer-wins each other.
    Never raises — lifecycle hooks must not fail on a snapshot error.
    """
    import logging
    log = logging.getLogger(__name__)
    try:
        run_dir = Path(output_dir)
        proj = run_dir.parent
        checklist_path = proj / "checklist.json"
        if not checklist_path.exists():
            return                       # standalone run — no durable project store
        from core.coverage.importer import (
            _inventory_paths,
            import_journal,
            import_run_dir,
            import_run_findings,
        )
        from core.coverage.store import CoverageStore, coverage_store_lock
        from core.json import load_json

        checklist = load_json(checklist_path)
        if not checklist:
            return
        cov_path = proj / "coverage.json"
        with coverage_store_lock(cov_path):
            store = CoverageStore(cov_path)
            store.set_content_id(checklist)
            import_run_dir(store, run_dir, checklist)
            import_run_findings(store, run_dir, _inventory_paths(checklist))
            # Import LLM review existence from the project-level
            # journal index. Replaces the pre-migration
            # ``import_checked_by(store, checklist)`` path — the
            # journal is now authoritative for LLM review state and
            # the coverage store projects it into (file, line, tool)
            # intervals so ``store.who_checked_function`` keeps
            # returning ``audit`` / ``agentic`` labels unchanged.
            import_journal(store, proj, checklist)
            store.save()
    except Exception:
        log.debug("_snapshot_run_coverage failed for %s", output_dir, exc_info=True)


def fail_run(output_dir: Path, error: str | None = None,
             extra: dict[str, Any] | None = None,
             record_timing: bool = True) -> None:
    """Update .raptor-run.json to status=failed."""
    extra = extra or {}
    if error:
        extra["error"] = error
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_FAILED, extra, record_timing=record_timing)


def cancel_run(output_dir: Path, extra: dict[str, Any] | None = None) -> None:
    """Update .raptor-run.json to status=cancelled."""
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_CANCELLED, extra)


def interrupt_run(output_dir: Path, reason: str | None = None,
                  extra: dict[str, Any] | None = None) -> None:
    """Update .raptor-run.json to status=interrupted.

    For runs stopped by an external supervisor (SIGTERM drain, harness
    shell cap) whose artifacts are intact and which a later
    :func:`resume_run` may re-enter. Unlike ``fail_run`` the run is
    not an error: journal/ledger state on disk is coherent up to the
    interruption point.
    """
    extra = dict(extra or {})
    if reason:
        extra["interrupt_reason"] = reason
    _finalize_sandbox_summary(output_dir)
    _update_status(output_dir, STATUS_INTERRUPTED, extra)


#: Statuses :func:`resume_run` accepts as re-enterable. ``completed``
#: is deliberately absent — a completed run's results are final; new
#: work belongs in a new run (cross-run verdict reuse imports the
#: prior verdicts there at $0).
RESUMABLE_STATUSES = frozenset({
    STATUS_INTERRUPTED, STATUS_FAILED, STATUS_CANCELLED, STATUS_RUNNING,
})


def resume_run(output_dir: Path, note: str | None = None) -> int:
    """Re-enter an interrupted/failed run AS THE SAME RUN.

    Flips status back to ``running`` (the one sanctioned
    terminal→running transition — ``_update_status`` refuses it for
    everyone else), records a segment row in ``extra.resumes`` and
    refreshes ``session_pid``/``tool_pid`` so the abandon sweeps track
    the resuming session, not the dead one.

    A ``running`` status is also accepted — a SIGKILLed run never got
    a terminal transition and sits in ``running`` until a sweep finds
    it; resuming it is exactly the recovery this function exists for.

    Returns the new segment number (2 for the first resume).
    Raises FileNotFoundError when there is no run metadata, and
    ValueError when the status is not resumable (notably
    ``completed``).
    """
    path = Path(output_dir) / RUN_METADATA_FILE
    with _metadata_lock(path):
        metadata = load_json(path)
        if metadata is None:
            raise FileNotFoundError(
                f"No {RUN_METADATA_FILE} in {output_dir} — not a run directory"
            )
        if not isinstance(metadata, dict):
            # ValueError (not TypeError): malformed on-disk data — the
            # same convention _update_status uses for this exact case.
            raise ValueError(  # noqa: TRY004
                f"Malformed {RUN_METADATA_FILE} in {output_dir} — "
                "expected JSON object")
        current = metadata.get("status")
        if current not in RESUMABLE_STATUSES:
            raise ValueError(
                f"run status {current!r} is not resumable "
                f"(resumable: {', '.join(sorted(RESUMABLE_STATUSES))})"
            )
        extra = metadata.get("extra") or {}
        resumes = extra.get("resumes")
        if not isinstance(resumes, list):
            resumes = []
        segment = len(resumes) + 2
        row: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "prior_status": current,
            "segment": segment,
        }
        if note:
            row["note"] = note
        resumes.append(row)
        extra["resumes"] = resumes
        metadata["extra"] = extra
        metadata["status"] = STATUS_RUNNING
        # The prior segment's end_timestamp/duration describe segment 1
        # only; drop them so the eventual terminal transition records
        # the full multi-segment envelope from the original start.
        metadata.pop("end_timestamp", None)
        metadata.pop("duration_seconds", None)
        session_pid = _get_session_pid()
        if session_pid is not None:
            metadata["session_pid"] = session_pid
            metadata["tool_pid"] = os.getppid()
        save_json(path, metadata)
    # Re-mark as the active run so sandbox summaries and coverage
    # tracking attach to the resumed segment.
    from core.sandbox.summary import set_active_run_dir
    set_active_run_dir(Path(output_dir))
    return segment


@contextlib.contextmanager
def tracked_run(output_dir: Path, command: str,
                extra: dict[str, Any] | None = None,
                target: str | None = None):
    """Context manager for run lifecycle. Writes metadata automatically.

    Usage:
        with tracked_run(out_dir, "agentic", target="/repo") as run_dir:
            # do work...
        # .raptor-run.json: completed on success, failed on exception, cancelled on Ctrl-C

    `target` is forwarded to `start_run`. Pre-fix `tracked_run`
    didn't accept it — callers using the context-manager style
    couldn't record the scan target into the metadata file (the
    `target_path` field that downstream consumers — project-listing,
    coverage rollups, multi-target dedup — read from
    `.raptor-run.json`). Now mirrored from start_run's signature.
    """
    run_dir = start_run(output_dir, command, extra, target=target)
    try:
        yield run_dir
        complete_run(run_dir)
    except KeyboardInterrupt:
        cancel_run(run_dir)
        raise
    except Exception as e:
        fail_run(run_dir, error=str(e))
        raise


def load_run_metadata(run_dir: Path) -> dict[str, Any] | None:
    """Load .raptor-run.json from a run directory. Returns None if missing."""
    return load_json(run_dir / RUN_METADATA_FILE)


def corroborate_target_path(run_dir: Path, candidate) -> str | None:
    """Check a recovered target path against the run's sealed metadata.

    Tools that lose the operator-supplied ``--target`` recover it from
    run artefacts (e.g. checklist.json's ``target_path``) — but those
    artefacts are written into the run dir by analysis stages and can
    drift or be tampered with. The ``target_path`` sealed into
    ``.raptor-run.json`` at :func:`start_run` is the authoritative
    record of what this run was pointed at.

    Returns ``None`` when the candidate is consistent with the sealed
    path, or when there is nothing to corroborate against (no metadata
    file, no ``target_path`` field — older runs). Returns a
    human-readable mismatch description otherwise; callers should
    refuse the recovered path and tell the operator to pass the target
    explicitly.
    """
    if not candidate:
        return None
    meta = load_run_metadata(Path(run_dir))
    sealed = (meta or {}).get("target_path")
    if not sealed or not isinstance(sealed, str):
        return None
    try:
        if Path(sealed).resolve() == Path(candidate).resolve():
            return None
    except OSError:
        return None
    return (
        f"recovered target path {candidate!s} does not match the "
        f"target_path sealed in {RUN_METADATA_FILE} ({sealed})"
    )


def is_run_directory(path: Path, *, strict: bool = True) -> bool:
    """Check if a directory looks like a RAPTOR run output.

    Default (``strict=True``): requires the canonical
    ``.raptor-run.json`` marker file. This is the only signal
    `start_run` actually plants and that the rest of the lifecycle
    relies on. Pre-fix the function ALSO accepted any directory whose
    name matched a known command-prefix OR that contained a "typical
    output file" (findings.json, checklist.json, ...) — the latter
    in particular over-matched: a user dir of past validation
    artifacts, a vendored sample, or a manually-copied subset all
    looked like real runs to anything iterating on `is_run_directory`
    (sweep / cleanup / project-listing logic).

    ``strict=False``: legacy heuristic preserved for callers that
    deliberately want the loose match (e.g., diagnostic tooling
    inspecting pre-metadata historical runs from before
    `.raptor-run.json` was a thing). Caller passes the flag
    explicitly so the loose semantics are visible at the call site.
    """
    if not path.is_dir():
        return False

    # Canonical marker — always sufficient.
    if (path / RUN_METADATA_FILE).exists():
        return True

    if strict:
        return False

    # Lenient heuristics — opted into via strict=False.
    name = path.name
    if any(name.startswith(prefix) for prefix in _PREFIX_MAP):
        return True

    typical_files = {"findings.json", "checklist.json", "scan_metrics.json",
                     "orchestrated_report.json", "validation-report.md"}
    return any((path / f).exists() for f in typical_files)


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

    # Adopted/legacy dirs never had provenance sealed at run time, and it
    # cannot be reconstructed (today's git/model/tool state is unrelated to
    # the run that produced these artifacts). Stamp the manifest as
    # explicitly unavailable so cite/reporting degrade honestly rather than
    # backfilling current values.
    from core.run.provenance import UNAVAILABLE_MANIFEST

    metadata = {
        "version": 2,
        "command": command,
        "timestamp": timestamp,
        "status": STATUS_COMPLETED,  # Assume completed if it exists
        "manifest": dict(UNAVAILABLE_MANIFEST),
        "extra": {"adopted": True},
    }

    save_json(run_dir / RUN_METADATA_FILE, metadata)


_TERMINAL_STATUSES = frozenset({
    STATUS_COMPLETED, STATUS_FAILED, STATUS_CANCELLED, STATUS_INTERRUPTED,
})


def _update_status(output_dir: Path, status: str,
                   extra: dict[str, Any] | None = None,
                   record_timing: bool = True,
                   manifest: dict[str, Any] | None = None) -> None:
    """Update the status field in .raptor-run.json.

    When record_timing is True (default), also records end_timestamp and
    duration_seconds. Set to False for sweep/cleanup where the run ended
    at an unknown earlier time.

    Terminal-status guard: refuses to overwrite an already-terminal
    state (completed / failed / cancelled). Pre-fix the function
    silently flipped any status to any other status, so:
      * `fail_run` called after `complete_run` (e.g. by exception
        handlers in caller's `finally` after the lifecycle already
        completed) downgraded a successful run to failed, masking
        the actual outcome.
      * `complete_run` called after `fail_run` (cleanup loop racing
        a real failure handler) upgraded a failed run to completed
        — operator sees green, the failure is invisible.
    Logs at warning level so the racing-caller bug is investigable
    rather than hidden.

    Raises FileNotFoundError if metadata file doesn't exist (call start_run first).

    The whole read-modify-write runs under :func:`_metadata_lock` so
    concurrent writers (parallel workers, a sweep racing a completion)
    serialise instead of last-writer-wins dropping each other's updates.
    """
    path = Path(output_dir) / RUN_METADATA_FILE
    with _metadata_lock(path):
        metadata = load_json(path)
        if metadata is None:
            raise FileNotFoundError(f"No {RUN_METADATA_FILE} in {output_dir} — call start_run() first")
        if not isinstance(metadata, dict):
            # ValueError (not TypeError): malformed on-disk data, and the
            # exception type callers already handle.
            raise ValueError(  # noqa: TRY004
                f"Malformed {RUN_METADATA_FILE} in {output_dir} — expected JSON object")
        current = metadata.get("status")
        if current in _TERMINAL_STATUSES and current != status:
            logger.warning(
                "Refusing to overwrite terminal status %r → %r in %s "
                "(probable double-finalisation; investigate caller)",
                current, status, output_dir,
            )
            return
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
            existing_extra = metadata.get("extra") or {}
            existing_extra.update(extra)
            metadata["extra"] = existing_extra

        if manifest:
            # Merge caller-supplied end-of-run provenance into the start-sealed
            # manifest. Shallow top-level merge: source_control / environment
            # (sealed at start) stay put; models land here.
            existing_manifest = metadata.get("manifest") or {}
            existing_manifest.update(manifest)
            metadata["manifest"] = existing_manifest

        if status == STATUS_COMPLETED:
            _apply_standard_provenance(metadata, Path(output_dir))

        save_json(path, metadata)


def _apply_standard_provenance(metadata: dict[str, Any], output_dir: Path) -> None:
    """Fill the manifest with the standard end-of-run provenance the lifecycle
    derives itself — engine versions + ``deterministically_reproducible`` — so
    EVERY completion path enriches uniformly without per-command wiring.

    Caller-supplied keys win (``setdefault``): the lifecycle only fills gaps,
    never clobbers a value a command passed via ``complete_run(manifest=...)``.
    Skipped when there's no real manifest to enrich — a run that predates
    manifest capture carries the ``provenance: unavailable`` stamp, and a run
    whose ``start_run`` never sealed one has no ``manifest`` key at all.
    """
    existing = metadata.get("manifest")
    if not existing or existing.get("provenance") == "unavailable":
        return
    from core.run.provenance import standard_completion_provenance
    standard = standard_completion_provenance(output_dir, metadata.get("command"))
    for key, value in standard.items():
        existing.setdefault(key, value)


def parse_timestamp_from_name(name: str) -> str | None:
    """Try to extract an ISO timestamp from a directory name.

    Matches patterns like:
    - scan-20260406-100000
    - scan_vulns_20260406_100000
    - exploitability-validation-20260406-100000
    """
    # `re.ASCII` so `\d` matches only ASCII digits. Pre-fix `\d` was
    # Unicode-aware by default, admitting Devanagari / Arabic-Indic
    # / fullwidth digit characters. A directory named with mixed
    # ASCII + Unicode digits (rare but possible if an operator
    # copies a path through a tool that re-encodes glyphs, or a
    # CI-system-generated name templates with locale-aware
    # formatting) would parse via `int(y)` — which DOES accept
    # Unicode digits and produces the corresponding integer value.
    # The directory name then "looks like" a timestamp the parser
    # accepts, even though grep / human-readable filtering treats
    # the chars as different. Anchoring to ASCII keeps the
    # timestamp-parsed-from-name <-> timestamp-rendered-to-name
    # mapping deterministic.
    # Look for YYYYMMDD_HHMMSS or YYYYMMDD-HHMMSS
    match = re.search(
        r'(\d{4})(\d{2})(\d{2})[_-](\d{2})(\d{2})(\d{2})',
        name, re.ASCII,
    )
    if match:
        y, mo, d, h, mi, s = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), int(h), int(mi), int(s), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    # Look for YYYYMMDD only
    match = re.search(r'(\d{4})(\d{2})(\d{2})', name, re.ASCII)
    if match:
        y, mo, d = match.groups()
        try:
            dt = datetime(int(y), int(mo), int(d), tzinfo=timezone.utc)
            return dt.isoformat()
        except ValueError:
            pass

    return None

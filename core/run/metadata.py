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

from core.json import append_jsonl, load_json, save_json

try:
    import fcntl
    _HAS_FCNTL = True
except ImportError:                                    # pragma: no cover
    _HAS_FCNTL = False

logger = logging.getLogger(__name__)

RUN_METADATA_FILE = ".raptor-run.json"


class RunOwnershipError(ValueError):
    """A lifecycle finaliser declared a command that does not match the
    run's recorded owner.

    Raised when ``complete_run`` / ``fail_run`` / ``cancel_run`` /
    ``interrupt_run`` is called with ``expected_command`` and the run
    directory's ``.raptor-run.json`` records a DIFFERENT command. Only
    the flow that started a run owns its terminal transition — a
    sub-step that writes into another command's run directory (the
    observed case: the in-session ``/understand --map`` mapping phase
    running with ``--out`` pointed at an ``/audit``-owned dir) must not
    finalise it. Pre-fix, that mapping step stamped the audit run
    ``completed`` minutes in, so the later SIGTERM drain hit the
    double-finalisation refusal and ``raptor-audit resume`` refused a
    run that was in fact interrupted mid-flight.

    PID-based enforcement is deliberately NOT used here: the offending
    finaliser runs in the SAME session (same ``session_pid``) as the
    legitimate one, and ``tool_pid`` is a fresh shell per stub
    invocation even for the legitimate flow — the discriminator that
    actually separates owner from trespasser is the command name.
    """


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
    "openant": "openant",
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
        msg = f"_read_ppid: /proc/{pid}/stat vanished — process exited"
        raise ProcessLookupError(msg) from exc
    except PermissionError:
        raise
    except OSError as exc:
        msg = f"_read_ppid: /proc/{pid}/stat unreadable: {exc}"
        raise ProcessLookupError(msg) from exc
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
        msg = f"_read_ppid_ps: ps failed for pid {pid}: {exc}"
        raise ProcessLookupError(msg) from exc


def _get_session_pid() -> int | None:
    """Get the PID of the Claude Code session process.

    Delegates to the ONE shared session resolver
    (``core.project.sessions.resolve_session_pid``: validated
    ``RAPTOR_SESSION_PID`` env credential first — correct beneath
    nested ``claude -p`` subagents and across PID namespaces — then
    the claude-ancestor tree walk). Binding readers, run-metadata
    recording, the contention gate, and the abandon sweeps must all
    agree on one identity; two resolvers meant a run recorded under a
    subagent pid that the sweeps then judged dead the moment the
    subagent exited.

    The CLAUDECODE env + getppid() fallback survives ONLY here — for
    run-metadata recording in claude-less contexts (bare-shell libexec
    flows). It is never used for project-binding resolution.
    """
    from core.project.sessions import resolve_session_pid
    pid = resolve_session_pid()
    if pid is not None:
        return pid
    if not os.environ.get("CLAUDECODE"):
        return None
    return os.getppid()


def _session_stamp(pid: int) -> dict[str, str]:
    """Identity stamp for *pid*, recorded beside ``session_pid`` in run
    metadata so the liveness verifiers can tell "this exact process"
    from "some process that recycled the PID" — including another real
    claude session, which every comm check accepts by construction.
    Keys absent when unreadable (legacy semantics apply on read)."""
    from core.project import sessions as _sessions
    stamp: dict[str, str] = {}
    start = _sessions.proc_starttime(pid)
    if start is not None:
        stamp["session_start"] = start
    boot = _sessions.boot_id()
    if boot is not None:
        stamp["session_boot_id"] = boot
    ns = _sessions.pidns_id()
    if ns is not None:
        stamp["session_pidns"] = ns
    return stamp


def _session_alive_for_meta(meta: dict) -> bool:
    """Is the session that owns this run metadata still alive?

    Stamped metadata (``session_start`` + ``session_boot_id``) gets the
    full identity check: a live claude process at the recorded pid with
    a MISMATCHING stamp is a recycled pid — the owner is dead. Foreign
    stamps (other boot / machine / pid namespace) are unverifiable here
    and read as ALIVE — the fail-open direction: sweeps skip rather
    than fail a run they cannot judge, and the gate preserves
    contention. Unstamped (pre-series) metadata keeps the legacy
    comm-checked ``_pid_alive`` — also fail-open.
    """
    pid = meta.get("session_pid")
    if isinstance(pid, str) and pid.isascii() and pid.isdigit():
        pid = int(pid)  # stringified pid: read like the hooks do
    if not isinstance(pid, int) or isinstance(pid, bool):
        return False
    start = meta.get("session_start")
    boot = meta.get("session_boot_id")
    if start and boot:
        from core.project import sessions as _sessions
        fields = {"starttime": str(start), "boot_id": str(boot)}
        pidns = meta.get("session_pidns")
        if pidns:
            fields["pidns"] = str(pidns)
        if _sessions._foreign_entry(fields):
            return True  # unverifiable — fail open
        return _sessions._identity_matches(pid, fields)
    return _pid_alive(pid)


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


def _contention_project_dir(output_dir: Path) -> Path | None:
    """The directory run-start contention keys on, or ``None``.

    Only managed project output dirs contend — standalone timestamped
    runs under ``out/`` never did and still don't. Lazy import: the
    check resolves through the project registry.
    """
    parent = Path(output_dir).parent
    try:
        from core.project.project import is_project_output_dir
        if is_project_output_dir(parent):
            return parent
    except Exception:  # noqa: BLE001 — contention is a QoL gate, never
        pass           # a reason a run can't start
    return None


def _gate_session_alive(pid: int) -> bool:
    """Liveness probe for the run-start contention gate ONLY.

    :func:`_pid_alive` treats an unsignallable pid (EPERM) as alive —
    conservative and correct for cleanup (skip rather than sweep), but
    a DoS primitive for the GATE: planted sibling metadata with
    ``session_pid=1`` reads as a live session forever, refusing every
    start (and queueing ``--wait`` indefinitely). Here EPERM falls
    through to the ``/proc/<pid>/comm`` cross-check, which is world-
    readable on Linux — another operator's real claude session still
    counts as live (contention preserved cross-user), while init or a
    root daemon does not. Without a readable comm (non-Linux), only a
    signallable pid is accepted: unverifiable never blocks a start.
    """
    if pid <= 0:
        return False
    signallable = True
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        signallable = False
    proc_comm = Path(f"/proc/{pid}/comm")
    try:
        comm = proc_comm.read_text(
            encoding="utf-8", errors="replace").strip().lower()
    except OSError:
        return signallable
    return "claude" in comm


def _live_conflicting_run(project_dir: Path, self_dir: Path,
                          self_session_pid: int | None) -> dict | None:
    """Find a sibling run that makes a new start contention.

    A sibling contends when its metadata says ``status=running`` AND
    its recorded ``session_pid`` is a live claude session belonging to
    a DIFFERENT session than ours. Everything else is explicitly not
    contention:

    * dead recorded pid — a crashed run; detectable, must never block
      forever (this is why run-in-progress lives in metadata rather
      than a flock: the stub start/complete flow spans processes, so
      no single process could hold a lock for the run's duration);
    * same session — parallel runs from one session stay legal (the
      `_cleanup_abandoned` freshness doctrine already supports them);
    * no recorded pid (legacy metadata) — unverifiable; never block on
      what can't be checked.
    """
    self_name = Path(self_dir).name
    try:
        children = list(Path(project_dir).iterdir())
    except OSError:
        return None
    for d in children:
        try:
            if (not d.is_dir() or d.name.startswith((".", "_"))
                    or d.name == self_name):
                continue
            meta_path = d / RUN_METADATA_FILE
            if not meta_path.exists():
                continue
            meta = load_json(meta_path)
        except OSError:
            continue
        if not isinstance(meta, dict) or meta.get("status") != STATUS_RUNNING:
            continue
        owner = meta.get("session_pid")
        if isinstance(owner, str) and owner.isascii() and owner.isdigit():
            owner = int(owner)  # stringified pid: read like the hooks
        if not isinstance(owner, int) or isinstance(owner, bool):
            continue
        if self_session_pid is not None and owner == self_session_pid:
            continue
        # Stamped metadata gets the identity check (a recycled claude
        # pid must not hold contention forever); unstamped falls back
        # to the gate's EPERM-aware comm probe.
        if meta.get("session_start") and meta.get("session_boot_id"):
            if not _session_alive_for_meta(meta):
                continue
        elif not _gate_session_alive(owner):
            continue
        # Sibling metadata is FILE CONTENT another workspace user can
        # plant — terminal-sanitise every field that reaches the
        # contention message (pid is already validated as an int).
        from core.security.log_sanitisation import sanitise_for_terminal
        return {
            "pid": owner,
            "operation": sanitise_for_terminal(
                str(meta.get("command") or "run"), max_len=64),
            "since": sanitise_for_terminal(
                str(meta.get("timestamp") or "unknown"), max_len=64),
            "run_dir": sanitise_for_terminal(d.name, max_len=128),
        }
    return None


@contextlib.contextmanager
def _project_run_gate(project_dir: Path, output_dir: Path, command: str,
                      session_pid: int | None, wait: bool = False):
    """Run-start contention gate for managed project dirs.

    Holds the project op lock (``.op.lock``) across the whole
    [contention check → metadata write] window so two simultaneous
    starts can't both pass the check; the flock guards only that
    read-modify-write, NOT the run itself. Run-in-progress is the run
    metadata (``status=running`` + live ``session_pid``) — see
    ``_live_conflicting_run`` for why.

    On contention: raises ``ProjectRunContention`` IMMEDIATELY (no
    grace — a live run holds the project for minutes-to-hours, so a
    silent retry window would just add latency to the refusal) with
    the holder named. ``wait=True`` queues instead: poll until the
    live run finishes or dies.
    """
    import time as _time

    from core.project.oplock import ProjectRunContention, project_op_lock

    # Re-entrant stamp: raptor.py's lifecycle wrapper start_run()s the
    # run dir, then the child (raptor_agentic.py) start_run()s the SAME
    # dir to enrich metadata. The second call is not a new run start —
    # gating it against siblings could kill a run whose parent already
    # passed the gate.
    with contextlib.suppress(OSError):
        own = load_json(Path(output_dir) / RUN_METADATA_FILE)
        if isinstance(own, dict) and own.get("status") == STATUS_RUNNING:
            yield
            return

    waiting_printed = False
    while True:
        with contextlib.ExitStack() as stack:
            # Blocking flock: op-lock holders (mutations, other starts'
            # RMW windows) are short-lived, unlike the run itself.
            stack.enter_context(project_op_lock(
                project_dir, f"run-start:{command}", wait=True))
            holder = _live_conflicting_run(project_dir, output_dir,
                                           session_pid)
            if holder is None:
                yield
                return
            if not wait:
                msg = (
                    f"a run is already in progress on this project: "
                    f"{holder['operation']} (session pid {holder['pid']}, "
                    f"since {holder['since']}, run {holder['run_dir']}) — "
                    f"let it finish or pass --wait to queue"
                )
                raise ProjectRunContention(
                    msg,
                    holder,
                )
        if not waiting_printed:
            import sys as _sys
            print(f"  waiting for in-progress {holder['operation']} run "
                  f"(session pid {holder['pid']}) to finish...",
                  file=_sys.stderr)
            waiting_printed = True
        _time.sleep(2.0)


def start_run(output_dir: Path, command: str,
              extra: dict[str, Any] | None = None,
              target: str | None = None,
              target_identity: dict[str, Any] | None = None,
              wait_for_project: bool = False) -> Path:
    """Write initial .raptor-run.json with status=running.

    Call this at the start of a command. Returns the output_dir (for chaining).
    Creates the directory if it doesn't exist. In project mode, creates a
    checklist.json symlink pointing to the project-level checklist.

    Records the session PID so sweep can check if the session is still alive.
    Also marks any abandoned runs from the same session and command type as
    failed (handles the Esc-then-retry scenario).

    In a managed project dir, a live run owned by ANOTHER session is
    contention: raises ``core.project.oplock.ProjectRunContention``
    immediately (``wait_for_project=True`` queues instead). Crashed
    runs (status=running, dead recorded pid) never block.
    """
    from core.run.safe_io import safe_run_mkdir

    output_dir = Path(output_dir)
    output_dir.parent.mkdir(parents=True, exist_ok=True)

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

    with contextlib.ExitStack() as _gate:
        # Contention gate BEFORE the run dir is created, so a refused
        # start leaves nothing behind (the raptor.py wrapper pre-creates
        # the dir on its own path and rmdir()s it on refusal).
        project_dir = _contention_project_dir(output_dir)
        if project_dir is not None:
            _gate.enter_context(_project_run_gate(
                project_dir, output_dir, command, session_pid,
                wait=wait_for_project))
        safe_run_mkdir(output_dir)

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
            metadata.update(_session_stamp(session_pid))
        if target:
            metadata["target_path"] = str(target)

        # Session ownership — WRITE-ONCE while running (same doctrine
        # as the pin below): a re-entrant start on a dir some session
        # already owns and is still running must not re-own it — that
        # would silently kill the first session's hook attribution and
        # contention identity. resume_run is the sanctioned re-owning
        # path (it refreshes the full stamp).
        _prior_meta = load_json(output_dir / RUN_METADATA_FILE,
                                max_bytes=1024 * 1024)
        if (isinstance(_prior_meta, dict)
                and _prior_meta.get("status") == STATUS_RUNNING
                and _prior_meta.get("session_pid") is not None
                and _session_alive_for_meta(_prior_meta)):
            for _k in ("session_pid", "tool_pid", "session_start",
                       "session_boot_id", "session_pidns"):
                if _k in _prior_meta:
                    metadata[_k] = _prior_meta[_k]
                else:
                    metadata.pop(_k, None)

        # Project pin — WRITE-ONCE. A start_run on a dir
        # whose metadata is already status=running (the documented
        # re-entrant flows: the raptor.py wrapper followed by
        # raptor_agentic's own start; /understand→/validate sharing an
        # --out) preserves the first start's pin: re-resolving here is
        # exactly the mid-run ambient re-resolution pinning exists to
        # kill. A conflicting explicit --project is a hard error.
        from core.run.pin import (
            ProjectArgvError,
            _frozen_pins,
            freeze_run_pin,
            get_process_project,
            resolve_pin_for_start,
        )
        # Prior pin: the PROCESS FREEZE CACHE first (the on-disk marker
        # sits in the sandbox write grant handed to prompt-injectable
        # children, so a re-entrant start must never re-derive
        # write-once state from a file a hostile child may have
        # rewritten), then disk for cross-process re-entrant flows.
        # A dir that EVER carried a pin keeps it regardless of status:
        # /understand → /validate reusing one --out is one pinned dir,
        # and re-resolving after the first command completed raced
        # mid-gap project switches.
        frozen = _frozen_pins.get(str(output_dir.resolve()))
        prior = _prior_meta
        prior_pin: tuple[str | None, str] | None = None
        if frozen is not None:
            prior_pin = (frozen.project, frozen.source)
        else:
            if isinstance(prior, dict) and "project" in prior:
                _pp = prior.get("project")
                if _pp is not None and not isinstance(_pp, str):
                    # A pin is a string or null by construction —
                    # anything else is corruption or tampering, and
                    # silently coercing it would strip the pin
                    # cross-process.
                    logger.warning(
                        "run pin in %s has non-string project %r — "
                        "treating as pinned-projectless; the marker "
                        "may have been tampered with", output_dir, _pp)
                    _pp = None
                prior_pin = (_pp,
                             str(prior.get("project_source") or "none"))
            # Out-of-grant witness check: the disk marker sits inside
            # the sandbox write grant; the session ledger's pin record
            # (written at the FIRST start, outside the grant) is the
            # arbiter for cross-process re-entrant flows. It is
            # consulted even when the marker carries NO pin — a child
            # that deletes/corrupts the marker must not convert a
            # re-entrant start into a fresh ambient re-pin.
            _witness_found = False
            try:
                from core.project.sessions import ledger_pin_witness
                found, witnessed, wit_source = ledger_pin_witness(
                    output_dir)
                _witness_found = found
                if found and (prior_pin is None
                              or witnessed != prior_pin[0]):
                    logger.warning(
                        "run pin in %s (%r) disagrees with the session "
                        "ledger witness (%r) — using the witness; the "
                        "marker may have been tampered with",
                        output_dir,
                        prior_pin[0] if prior_pin else "<missing>",
                        witnessed)
                    prior_pin = (witnessed, wit_source or "session")
            except Exception:  # noqa: BLE001 — witness is best-effort
                logger.debug("pin witness check failed", exc_info=True)
            if (prior_pin is not None and not _witness_found):
                # No witness and no freeze: the disk pin is
                # UNCORROBORATED (the witness lives in the STARTING
                # session's ledger, so a legitimate reuse across a
                # claude relaunch arrives here too — the dead
                # session's ledger is pruned). It stands when it
                # AGREES with start-time resolution; on DISAGREEMENT
                # neither side may elect silently — a planted marker
                # in a reused --out dir must not become the first pin
                # and seed the first witness, and a legitimate
                # restart-reuse must not lose its pin to whatever the
                # session ambient happens to be. The operator
                # disambiguates.
                _fresh_project, _fresh_source = resolve_pin_for_start()
                if _fresh_project != prior_pin[0]:
                    if get_process_project() is not None:
                        # An explicit --project IS the operator's
                        # disambiguation: re-pin to it. (Without this,
                        # the error's own "--project <fresh>" remedy
                        # re-derived the same disagreement here and
                        # looped on the same hard error.)
                        logger.warning(
                            "re-pinning %s from uncorroborated %r to "
                            "%r per explicit --project", output_dir,
                            prior_pin[0], _fresh_project)
                        prior_pin = (_fresh_project, _fresh_source)
                    else:
                        _keep = prior_pin[0] if prior_pin[0] else "-"
                        _fresh = (_fresh_project if _fresh_project
                                  else "-")
                        msg = (
                            f"the run dir {output_dir} carries an "
                            f"uncorroborated pin to "
                            f"{prior_pin[0] or 'no project'!r} (no "
                            f"ledger witness — reused across a "
                            f"relaunch, or a pre-existing marker), "
                            f"while this start resolves to "
                            f"{_fresh_project or 'no project'!r}. "
                            f"Pass --project {_keep} to keep the "
                            f"dir's pin, or --project {_fresh} to "
                            f"re-pin it."
                        )
                        raise ProjectArgvError(msg)
        if prior_pin is not None:
            pin_project, pin_source = prior_pin
            override = get_process_project()
            if override is not None:
                wanted = None if override == "-" else override
                if wanted != pin_project:
                    msg = (
                        f"--project {override!r} conflicts with the "
                        f"run's existing pin {pin_project!r} in "
                        f"{output_dir} — a run dir is pinned to one "
                        "project for its whole lifetime"
                    )
                    raise ProjectArgvError(msg)
        else:
            pin_project, pin_source = resolve_pin_for_start()
        metadata["project"] = pin_project
        metadata["project_source"] = pin_source
        freeze_run_pin(output_dir, pin_project, pin_source)
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
    # Session run ledger: the record drives exact
    # coverage-hook attribution and sibling-discovery tier 0.
    # Best-effort by contract — never lifecycle-critical.
    if session_pid is not None:
        from core.project.sessions import ledger_record_start
        ledger_record_start(output_dir, pid=session_pid,
                            pin_project=pin_project, record_pin=True,
                            pin_source=pin_source)
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
        if not isinstance(meta, dict) or not meta:
            # Corrupt or non-object metadata (torn write, hostile or
            # malformed run dir): not sweepable — never crash the sweep.
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
            and not _session_alive_for_meta(meta)
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

    # THE RUN PIN decides which project this is (start_run sealed it
    # just before calling here). Pre-fix this read the AMBIENT layers
    # (get_active_name), which never see a --project override: a run
    # pinned to X in a session bound to Y got no symlink — or worse,
    # triggered _promote_checklist (a durable write) in Y.
    project_dir = None
    try:
        from core.run.pin import pin_project_dir
        candidate = pin_project_dir(run_dir)
        if candidate is not None and candidate.is_dir():
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


def _finalize_sandbox_triage(output_dir: Path) -> str | None:
    """Best-effort: classify this run's sandbox telemetry
    (sandbox-summary.json / proxy-events.jsonl) into a clean / notable /
    suspicious verdict and write sandbox-triage.json. Returns the
    verdict string (or None: no telemetry / triage failed) so the
    terminal-state transitions can surface it in .raptor-run.json.

    Must run AFTER _finalize_sandbox_summary — triage reads
    sandbox-summary.json, which that call just wrote. Rules-based, no LLM
    call, no network: cheap enough to run unconditionally on every
    terminal-state transition rather than requiring an operator to invoke
    ``raptor-sandbox-triage`` by hand. See core/sandbox/triage.py's module
    docstring for the signal taxonomy and known limitations.

    Broad except, mirrors _finalize_sandbox_summary: lifecycle hooks must
    never raise out of complete_run / fail_run / cancel_run on account of
    a triage failure.
    """
    from core.sandbox.triage import triage_run, TRIAGE_FILE
    import logging
    log = logging.getLogger(__name__)
    try:
        # Current lifecycle runs fail closed on provenance: the run dir is
        # target-writable until this point, so unstamped artefacts must not
        # be allowed to drive a verdict. Manual/post-hoc triage keeps legacy
        # support for genuinely old runs.
        result = triage_run(output_dir, allow_legacy=False)
        # Discoverability: only log when there's something to see — a
        # clean run (the common case) shouldn't add chatter. Mirrors the
        # "if result is not None" gate in _finalize_sandbox_summary.
        if result is not None and result["verdict"] != "clean":
            log.warning(
                "sandbox triage: verdict=%s (%d signal(s)) → %s",
                result["verdict"], len(result["signals"]),
                output_dir / TRIAGE_FILE,
            )
        return None if result is None else result["verdict"]
    except Exception:  # noqa: BLE001 — never fail lifecycle on triage error
        log.debug(
            "_finalize_sandbox_triage: triage_run failed",
            exc_info=True,
        )
        return None


# Sandbox summary + triage are finalized BEFORE the status update in every
# terminal-state transition. If the process crashes between them:
#  - finalize-then-status-update path: status stays "running", summary/triage
#    on disk. A later cleanup-of-stale-runs marks the status appropriately;
#    the artifacts are already there. No data lost.
#  - status-update-then-finalize path (the alternative): status flips to
#    "completed" but no summary/triage; reader assumes "no denials" because
#    no file. Misleading.
# Finalizing first preserves the data; status update is just the signal.
# Triage runs strictly after summary within each finalize call — it reads
# sandbox-summary.json, which the summary finalize step just wrote.

def ensure_run_command(output_dir: Path,
                       expected_command: str | None) -> None:
    """Refuse a terminal transition on a run another command owns.

    ``expected_command`` is the command the FINALISER believes it is
    finishing. ``None`` (caller made no claim) checks nothing — the
    legacy surface stays valid. When a claim is made and the run's
    recorded ``command`` differs, raises :class:`RunOwnershipError`
    BEFORE any finalisation side effect (sandbox summary/triage
    flush, journal merge, status flip) touches the foreign run.

    Missing or malformed metadata is not an ownership violation —
    those cases keep their existing handling in ``_update_status``
    (FileNotFoundError / ValueError there).
    """
    if expected_command is None:
        return
    metadata = load_json(Path(output_dir) / RUN_METADATA_FILE)
    if not isinstance(metadata, dict):
        return
    owner = metadata.get("command")
    if owner and owner != expected_command:
        msg = (
            f"run {output_dir} is owned by command {owner!r} — refusing "
            f"the terminal transition claimed by {expected_command!r}. "
            f"Only the flow that started a run may finalise it; a "
            f"sub-step writing into another command's run directory "
            f"(e.g. /understand --map with --out pointed at an /audit "
            f"dir) must leave the owner's lifecycle alone."
        )
        raise RunOwnershipError(msg)


def complete_run(output_dir: Path, extra: dict[str, Any] | None = None,
                 manifest: dict[str, Any] | None = None,
                 expected_command: str | None = None) -> None:
    """Update .raptor-run.json to status=completed.

    ``manifest`` merges end-of-run provenance into the manifest sealed at
    start_run. Top-level keys overwrite; the start-sealed source_control /
    environment snapshots are preserved unless explicitly overwritten.

    Standard end-of-run provenance the lifecycle can derive itself — engine
    versions (``detect_engines``) and ``deterministically_reproducible`` (from
    the command) — is filled automatically for EVERY completion path, so a
    caller only needs to pass the facts unique to it (the models that fired).
    Callers still win on conflict: an explicitly-passed key is never clobbered.

    ``expected_command`` (optional) asserts ownership: see
    :func:`ensure_run_command`. Checked before the sandbox summary /
    triage finalisers so a refused completion leaves no side effects
    in the foreign run directory.
    """
    ensure_run_command(output_dir, expected_command)
    _finalize_sandbox_summary(output_dir)
    _triage_verdict = _finalize_sandbox_triage(output_dir)
    if _triage_verdict is not None:
        # Surface the verdict in .raptor-run.json so cross-run views
        # (/project status, /review) can flag non-clean runs without
        # opening every sandbox-triage.json. Callers win on conflict,
        # matching the extra-merge contract above.
        extra = dict(extra or {})
        extra.setdefault("sandbox_triage", _triage_verdict)
    _update_status(output_dir, STATUS_COMPLETED, extra, manifest=manifest)
    # Merge this run's review journal into the project-level index BEFORE
    # the coverage snapshot — ``import_journal`` reads the index, not
    # per-run journal files. Living here (the completion chokepoint)
    # covers every ``complete_run`` caller, including the Python
    # pipelines that never go through the libexec lifecycle shim.
    _merge_run_journal(output_dir)
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


def _journal_project_dir(out_dir: Path) -> Path | None:
    """Project-level directory a run's journal should merge into.

    THE RUN PIN decides: a run pinned to project P merges into P's
    index wherever the run dir physically sits; a standalone
    (pin-null) run merges nowhere. The pre-fix ambient
    ``get_active_name()`` read at COMPLETION time meant a mid-flight
    ``/project use B`` (with B's dir an ancestor of the run) merged
    the run's verdicts into B's index, which cross-run reuse then
    silently trusted. The write requires an authoritative pin;
    pre-series (pin-less) run dirs keep the legacy parent-marker probe
    so their projections don't regress at landing.
    """
    try:
        out_res = Path(out_dir).resolve()
    except OSError:
        return None
    try:
        from core.run.pin import (
            legacy_probe_allowed,
            pin_project_dir,
            pinned_write_target_ok,
            resolve_run_pin,
        )
        pin = resolve_run_pin(out_res)
        if not _pin_witness_ok(out_res, pin):
            return None
        if pin.authoritative:
            proj_dir = pin_project_dir(out_res, for_write=True)
            if proj_dir is not None and not pinned_write_target_ok(out_res):
                return None
            return proj_dir.resolve() if proj_dir is not None else None
        if not legacy_probe_allowed(pin):
            # Corrupt or deleted marker: tamper evidence, not a legacy
            # dir — never fall through to topology inference.
            return None
    except Exception:  # noqa: BLE001 — resolver failure: no fallthrough
        return None
    parent = out_res.parent
    if _is_out_root(parent):
        # A stray checklist.json at the out-root must not turn it
        # into a pseudo project store for every marker-less run
        # beneath it (the pin walk stops at the out-root; this direct
        # parent probe needs the same boundary).
        return None
    if (parent / "checklist.json").exists() or (
        parent / "coverage.json"
    ).exists():
        return parent
    return None


def _is_out_root(directory: Path) -> bool:
    """Is *directory* the configured out-root? (Runs live UNDER it —
    it is never itself a project dir.)"""
    try:
        from core.config import RaptorConfig
        return directory.resolve() == Path(
            RaptorConfig.get_out_dir()).resolve()
    except Exception:  # noqa: BLE001 — out-root unknown
        return False


def _pin_witness_ok(run_dir, pin) -> bool:
    """Verify a resolved pin against the session ledger's out-of-grant
    witness before a privileged project-store write. True when no
    witness exists (unverifiable — pre-witness runs, sessionless
    contexts keep their existing posture) or when it AGREES with the
    resolved pin; False on disagreement (the disk marker sits inside
    the sandbox write grant and was rewritten or deleted under us).
    A frozen pin needs no witness — it was sealed by the owner.
    """
    try:
        from core.run.pin import _frozen_pins
        if str(Path(run_dir).resolve()) in _frozen_pins:
            return True
        from core.project.sessions import ledger_pin_witness
        found, witnessed, _wit_source = ledger_pin_witness(run_dir)
        if not found:
            return True
        resolved = pin.project if pin.authoritative else None
        if witnessed != resolved:
            logger.warning(
                "pin: SUPPRESSED project-store write for %s — the run "
                "marker resolves %r but the session ledger witnessed "
                "%r at start. The marker may have been tampered with.",
                run_dir, resolved, witnessed)
            return False
        return True
    except Exception:  # noqa: BLE001 — witness is an aid, never a crash
        logger.debug("pin witness check failed", exc_info=True)
        return True


def project_run_projections(output_dir: Path,
                            project_dir: Path | None = None) -> None:
    """Re-run the project-facing completion projections for one run.

    The journal-index merge, reads-manifest conversion, and coverage
    snapshot normally fire exactly once, at ``complete_run`` — a run
    ADOPTED into a project after the fact (retro-created project,
    ``raptor project add``/``adopt``) already had its completion and
    missed them, so its verdicts stay invisible to cross-run reuse,
    ``/review``, and ``/project coverage``. Same best-effort semantics
    as the completion chokepoint: each step no-ops or logs at debug,
    never raises. Idempotent — the index merge is latest-ts keyed and
    the coverage import is interval-union.
    """
    _merge_run_journal(output_dir, project_dir=project_dir)
    _convert_reads_manifest(output_dir)
    _snapshot_run_coverage(output_dir, project_dir=project_dir)


def _merge_run_journal(output_dir: Path,
                       project_dir: Path | None = None) -> None:
    """Best-effort: merge this run's review journals (run root + one-
    level tool subdirs, see ``merge_run_into_index``) into the
    project-level index so sibling runs, resume, and the coverage-
    store import see its verdicts.

    Lives at the completion chokepoint so EVERY ``complete_run`` /
    ``interrupt_run`` caller gets it — including the Python pipelines
    that never go through the libexec lifecycle shim. No-op for a
    standalone run (no project dir resolves — see
    :func:`_journal_project_dir`). Never raises — lifecycle hooks
    must not fail on a merge error.
    """
    try:
        run_dir = Path(output_dir)
        # An explicit project_dir comes from a trusted caller that
        # KNOWS the governing project (the adoption path, whose
        # registry is authoritative for it and which target-validated
        # the run before moving it) — ambient re-resolution through
        # the default registry would miss custom-registry projects.
        proj = project_dir if project_dir is not None \
            else _journal_project_dir(run_dir)
        if proj is None:
            return
        from core.coverage.journal import merge_run_into_index
        merged = merge_run_into_index(proj, run_dir)
        if merged:
            logger.info(
                "journal: %d entries merged into project index", merged,
            )
    except Exception:
        logger.debug(
            "_merge_run_journal failed for %s", output_dir, exc_info=True
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


def _snapshot_run_coverage(output_dir: Path,
                           project_dir: Path | None = None) -> None:
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
        # THE RUN PIN decides which project store receives the
        # snapshot. Pre-fix `proj = run_dir.parent` + a
        # checklist-marker probe: a standalone run whose parent
        # happened to carry a checklist merged coverage into a
        # pseudo-store there, and an --out run under a FOREIGN
        # project's dir merged into that project. Pin-less legacy runs
        # keep the parent-marker shape so their projections don't
        # regress at landing.
        # Explicit project_dir = trusted adoption-path caller (see
        # _merge_run_journal) — skip ambient pin re-resolution.
        proj = project_dir
        if proj is None:
            try:
                from core.run.pin import (
                    legacy_probe_allowed,
                    pin_project_dir,
                    pinned_write_target_ok,
                    resolve_run_pin,
                )
                pin = resolve_run_pin(run_dir)
                from core.run.metadata import _pin_witness_ok
                if not _pin_witness_ok(run_dir, pin):
                    return               # marker disagrees with witness
                if pin.authoritative:
                    proj = pin_project_dir(run_dir, for_write=True)
                    if proj is None:
                        return           # standalone by pin — no store
                    if not pinned_write_target_ok(run_dir):
                        return           # one-target gate: foreign target
                elif not legacy_probe_allowed(pin):
                    return               # corrupt/deleted marker: tamper
            except Exception:  # noqa: BLE001 — no privileged fallthrough
                return
        if proj is None:
            if _is_out_root(run_dir.parent):
                return  # same out-root boundary as _journal_project_dir
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
            _append_coverage_progress(proj, run_dir, store, checklist)
    except Exception:
        log.debug("_snapshot_run_coverage failed for %s", output_dir, exc_info=True)


def _append_coverage_progress(proj: Path, run_dir: Path, store,
                              checklist: dict[str, Any]) -> None:
    """Append one line to the project's ``coverage-progress.jsonl``.

    The accumulation promise ("each run reviews only remaining gaps")
    was never measured — no artifact recorded whether the reviewed
    count actually moves run over run. One JSON line per completed
    run, computed from the just-saved store, gives the cross-run
    trend for free. Called under ``coverage_store_lock``, so the
    append cannot interleave with a parallel completion. Best-effort.
    """
    import logging
    try:
        from core.coverage.store_summary import store_view
        view = store_view(store, checklist)
        row = {
            "run": run_dir.name,
            "ts": datetime.now(timezone.utc).isoformat(),
            "items": view.get("total_functions", 0),
            "examined": view.get("functions_covered", 0),
            "llm_reviewable": view.get("llm_reviewable", 0),
            "llm_reviewed": view.get("functions_reviewed", 0),
        }
        append_jsonl(proj / "coverage-progress.jsonl", row)
    except Exception:
        logging.getLogger(__name__).debug(
            "coverage progress append failed for %s", run_dir, exc_info=True,
        )


def fail_run(output_dir: Path, error: str | None = None,
             extra: dict[str, Any] | None = None,
             record_timing: bool = True,
             expected_command: str | None = None) -> None:
    """Update .raptor-run.json to status=failed.

    ``expected_command`` (optional) asserts ownership — see
    :func:`ensure_run_command`. Sweep/cleanup callers that legitimately
    fail runs they did not start (dead-session abandons, lifecycle
    hooks) simply make no claim.
    """
    ensure_run_command(output_dir, expected_command)
    extra = extra or {}
    if error:
        extra["error"] = error
    _finalize_sandbox_summary(output_dir)
    _triage_verdict = _finalize_sandbox_triage(output_dir)
    if _triage_verdict is not None:
        extra.setdefault("sandbox_triage", _triage_verdict)
    _update_status(output_dir, STATUS_FAILED, extra, record_timing=record_timing)
    # The LLM's reads happened regardless of how the run ended — convert
    # the manifest so the read coverage survives. Pre-fix only
    # complete_run converted, so every failed/cancelled/interrupted
    # run's reads were silently lost (the raw manifest lingers but no
    # importer reads raw manifests). The manifest is left in place, and
    # a later resume→complete re-converts it with any new reads —
    # write_record overwrites, so this is idempotent, never additive.
    _convert_reads_manifest(output_dir)


def cancel_run(output_dir: Path, extra: dict[str, Any] | None = None,
               expected_command: str | None = None) -> None:
    """Update .raptor-run.json to status=cancelled.

    ``expected_command`` (optional) asserts ownership — see
    :func:`ensure_run_command`.
    """
    ensure_run_command(output_dir, expected_command)
    _finalize_sandbox_summary(output_dir)
    _triage_verdict = _finalize_sandbox_triage(output_dir)
    if _triage_verdict is not None:
        extra = dict(extra or {})
        extra.setdefault("sandbox_triage", _triage_verdict)
    _update_status(output_dir, STATUS_CANCELLED, extra)
    _convert_reads_manifest(output_dir)  # see fail_run


def interrupt_run(output_dir: Path, reason: str | None = None,
                  extra: dict[str, Any] | None = None,
                  expected_command: str | None = None) -> None:
    """Update .raptor-run.json to status=interrupted.

    For runs stopped by an external supervisor (SIGTERM drain, harness
    shell cap) whose artifacts are intact and which a later
    :func:`resume_run` may re-enter. Unlike ``fail_run`` the run is
    not an error: journal/ledger state on disk is coherent up to the
    interruption point.

    ``expected_command`` (optional) asserts ownership — see
    :func:`ensure_run_command`.
    """
    ensure_run_command(output_dir, expected_command)
    extra = dict(extra or {})
    if reason:
        extra["interrupt_reason"] = reason
    _finalize_sandbox_summary(output_dir)
    _triage_verdict = _finalize_sandbox_triage(output_dir)
    if _triage_verdict is not None:
        extra.setdefault("sandbox_triage", _triage_verdict)
    _update_status(output_dir, STATUS_INTERRUPTED, extra)
    _convert_reads_manifest(output_dir)  # see fail_run
    # An interrupted run's journal verdicts are real reviews — merge them
    # into the project index so sibling runs (and the eventual resume)
    # see them.
    _merge_run_journal(output_dir)


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
            msg = f"No {RUN_METADATA_FILE} in {output_dir} — not a run directory"
            raise FileNotFoundError(msg)
        if not isinstance(metadata, dict):
            # ValueError (not TypeError): malformed on-disk data — the
            # same convention _update_status uses for this exact case.
            msg = (
                f"Malformed {RUN_METADATA_FILE} in {output_dir} — "
                "expected JSON object"
            )
            raise ValueError(msg)  # noqa: TRY004
        current = metadata.get("status")
        if current not in RESUMABLE_STATUSES:
            msg = (
                f"run status {current!r} is not resumable "
                f"(resumable: {', '.join(sorted(RESUMABLE_STATUSES))})"
            )
            raise ValueError(msg)
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
        prior_session_pid = metadata.get("session_pid")
        session_pid = _get_session_pid()
        if session_pid is not None:
            metadata["session_pid"] = session_pid
            metadata["tool_pid"] = os.getppid()
            # Refresh the FULL identity stamp with the pid — a resumed
            # run owned by a different session must never carry the old
            # session's stamp (the verifiers would judge the live
            # resumed run abandoned: stamp != live process at new pid).
            for key in ("session_start", "session_boot_id",
                        "session_pidns"):
                metadata.pop(key, None)
            metadata.update(_session_stamp(session_pid))
        save_json(path, metadata)
    # Re-mark as the active run so sandbox summaries and coverage
    # tracking attach to the resumed segment.
    from core.sandbox.summary import set_active_run_dir
    set_active_run_dir(Path(output_dir))
    # Ledger: the RESUMING session gains a running
    # record (else every read in the resumed segment is unattributable)
    # and the original owner's line is CAS-marked interrupted so its
    # session's hook stops attributing to a run it no longer owns.
    if session_pid is not None:
        # Seal the pin for THIS process — segment 2+ must enjoy the
        # same marker-rewrite immunity as the original owner. The
        # marker is verified against the out-of-grant witness FIRST:
        # a hostile child rewriting project (and status → resumable)
        # during segment 1 must not be laundered into a trusted
        # frozen pin here. Witness lookup: the RESUMING session's
        # ledger first, then the ORIGINAL owner's (a cross-session
        # resume otherwise found no witness and trusted the marker —
        # the prior pid comes from the same child-writable metadata,
        # but a FORGED pid merely yields no witness, i.e. today's
        # posture). Neither found = the documented sessionless
        # residual. Any restore is a fresh LOCKED read-modify-write —
        # the earlier snapshot is stale by now, and an unlocked save
        # would clobber concurrent status writers wholesale.
        _restored_pin = None
        try:
            from core.project.sessions import ledger_pin_witness
            from core.run.pin import freeze_run_pin, resolve_run_pin
            _pin = resolve_run_pin(output_dir)
            _marker_project = (_pin.project if _pin.authoritative
                               else None)
            _found, _witnessed, _wsource = ledger_pin_witness(output_dir)
            _fallback = False
            if not _found and isinstance(prior_session_pid, int) \
                    and not isinstance(prior_session_pid, bool):
                # The prior pid comes from CHILD-WRITABLE metadata:
                # the lookup verifies the pid's registered identity,
                # and its witness is used VETO-ONLY below — a steered
                # lookup can at most suppress, never choose a project.
                _found, _witnessed, _wsource = ledger_pin_witness(
                    output_dir, pid=prior_session_pid)
                _fallback = True
            if _found and _witnessed != _marker_project:
                if _fallback:
                    logger.warning(
                        "resume: run pin in %s (%r) disagrees with the "
                        "PRIOR owner's ledger witness (%r) — freezing "
                        "projectless (fallback witnesses veto, never "
                        "elect); the marker may have been tampered "
                        "with", output_dir, _marker_project, _witnessed)
                    _witnessed, _wsource = None, "none"
                else:
                    logger.warning(
                        "resume: run pin in %s (%r) disagrees with the "
                        "session ledger witness (%r) — restoring the "
                        "witness; the marker may have been tampered "
                        "with", output_dir, _marker_project, _witnessed)
                _wsource = _wsource or "session"
                with _metadata_lock(path):
                    _fresh = load_json(path)
                    if isinstance(_fresh, dict):
                        _fresh["project"] = _witnessed
                        _fresh["project_source"] = _wsource
                        save_json(path, _fresh)
                freeze_run_pin(output_dir, _witnessed, _wsource)
                _restored_pin = (_witnessed, _wsource)
            elif _pin.authoritative:
                freeze_run_pin(output_dir, _pin.project, _pin.source)
                _restored_pin = (_pin.project, _pin.source)
        except Exception:  # noqa: BLE001 — seal is best-effort
            logger.debug("resume pin seal failed", exc_info=True)
        from core.project.sessions import ledger_record_resume
        prior = (prior_session_pid
                 if isinstance(prior_session_pid, int)
                 and not isinstance(prior_session_pid, bool) else None)
        # Thread the verified pin so the RESUMING session's ledger
        # carries a witness for segment 2+ — without it, this
        # session's later completions had nothing to verify against.
        ledger_record_resume(Path(output_dir),
                             prior_session_pid=prior, pid=session_pid,
                             pin_project=(_restored_pin[0]
                                          if _restored_pin else None),
                             pin_source=(_restored_pin[1]
                                         if _restored_pin else None),
                             record_pin=_restored_pin is not None)
    return segment


def reopen_run(output_dir: Path, note: str | None = None) -> None:
    """Flip a spuriously ``completed`` run back to ``interrupted``.

    The one sanctioned completed→interrupted transition, for
    contradiction recovery: a step that did not own the run stamped it
    completed (e.g. a mapping-phase ``raptor-run-lifecycle complete``
    on an /audit dir), leaving the real workflow's completion refused
    by the terminal-status guard and resume refusing the "completed"
    run. Callers (``raptor-audit resume --reopen``) are responsible
    for verifying the contradiction — this helper only requires that
    the current status IS ``completed`` and records the reopen with a
    timestamped note so the status history stays auditable.

    Raises FileNotFoundError when there is no metadata file and
    ValueError when the current status is not ``completed``.
    """
    path = Path(output_dir) / RUN_METADATA_FILE
    with _metadata_lock(path):
        metadata = load_json(path)
        if metadata is None:
            msg = f"No {RUN_METADATA_FILE} in {output_dir}"
            raise FileNotFoundError(msg)
        if not isinstance(metadata, dict):
            msg = (
                f"Malformed {RUN_METADATA_FILE} in {output_dir} — "
                "expected JSON object"
            )
            raise ValueError(msg)  # noqa: TRY004 — malformed on-disk data
        current = metadata.get("status")
        if current != STATUS_COMPLETED:
            msg = f"reopen_run: expected status 'completed', got {current!r}"
            raise ValueError(msg)
        extra = metadata.get("extra") or {}
        reopens = extra.get("reopens")
        if not isinstance(reopens, list):
            reopens = []
        row: dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "prior_status": current,
        }
        if note:
            row["note"] = note
        reopens.append(row)
        extra["reopens"] = reopens
        metadata["extra"] = extra
        metadata["status"] = STATUS_INTERRUPTED
        save_json(path, metadata)
    logger.warning(
        "reopen_run: %s flipped completed → interrupted (%s)",
        output_dir, note or "no note",
    )


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


def write_run_pin(run_dir: Path, project: str | None, source: str) -> None:
    """Rewrite a run dir's project pin — the SANCTIONED rewrites only:
    adoption into a project (``adopted``), removal from one (``none``),
    and merge-synthesised dirs (``merged``). A run in flight is never
    re-pinned; these all operate on non-live dirs by construction.

    Upserts into existing metadata (all other keys preserved) and
    updates the process pin freeze cache so in-process consumers —
    the projections that fire right after adoption — see the rewrite
    rather than the pre-move resolution.
    """
    from core.run.pin import freeze_run_pin
    rewrite_sources = ("adopted", "none", "merged")
    if source not in rewrite_sources:
        msg = (f"invalid pin rewrite source {source!r} "
               f"(one of {rewrite_sources})")
        raise ValueError(msg)
    path = Path(run_dir) / RUN_METADATA_FILE
    # Same lock every other read-modify-write on this file takes:
    # racing a completing run's _update_status must not lose either
    # write (a resurrected status=running reads as abandoned and gets
    # sweep-failed; a dropped pin orphans the run).
    with _metadata_lock(path):
        meta = load_json(path)
        if not isinstance(meta, dict):
            meta = {}
        if (meta.get("status") == STATUS_RUNNING
                and _session_alive_for_meta(meta)):
            msg = (f"refusing to re-pin {run_dir}: the run is live "
                   f"(owned by session {meta.get('session_pid')}) — "
                   "a run in flight is never re-pinned")
            raise ValueError(msg)
        meta["project"] = project
        meta["project_source"] = source
        save_json(path, meta)
    freeze_run_pin(run_dir, project, source)


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
            msg = f"No {RUN_METADATA_FILE} in {output_dir} — call start_run() first"
            raise FileNotFoundError(msg)
        if not isinstance(metadata, dict):
            # ValueError (not TypeError): malformed on-disk data, and the
            # exception type callers already handle.
            msg = f"Malformed {RUN_METADATA_FILE} in {output_dir} — expected JSON object"
            raise ValueError(msg)  # noqa: TRY004
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

    # CAS-mark the run's ledger record with its TRUE terminal status —
    # in the OWNING session's ledger (metadata session_pid: a sweep in
    # session B finalising session A's abandoned run must mark A's
    # record, and after a resume the owner IS the resuming session).
    if status in _TERMINAL_STATUSES:
        owner = metadata.get("session_pid")
        if isinstance(owner, int) and not isinstance(owner, bool):
            from core.project.sessions import ledger_record_finish
            ledger_record_finish(output_dir, status, pid=owner)


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

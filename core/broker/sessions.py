"""Remote session management for long-running tasks.

Unix:
    Wraps commands in tmux (preferred) or screen so they survive SSH
    disconnects.  Falls back to nohup if neither is available.

Windows:
    Uses PowerShell ``Start-Process`` to launch a detached child
    process with output redirected to log files.  A wrapper script
    writes the exit code to a sentinel file on completion.

Both platforms:
    - ``poll()`` checks for a sentinel file without blocking
    - ``collect()`` downloads results after completion
    - ``kill_session()`` terminates the remote process
    - ``cleanup_workspace()`` removes the remote workspace
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from core.broker.capabilities import OperatingSystem
from core.broker.transport import CommandResult, Transport, TransportError

logger = logging.getLogger(__name__)


class SessionBackend(Enum):
    TMUX = "tmux"
    SCREEN = "screen"
    NOHUP = "nohup"
    POWERSHELL = "powershell"


@dataclass(frozen=True)
class RemoteTaskState:
    """Snapshot of a remote task's state."""
    task_id: str
    running: bool
    exit_code: Optional[int] = None
    pid: Optional[int] = None
    tail_stdout: str = ""
    tail_stderr: str = ""


_SENTINEL_NAME = ".raptor-exit-code"
_PID_NAME = ".raptor-pid"
_STDOUT_LOG = "stdout.log"
_STDERR_LOG = "stderr.log"


def detect_session_backend(
    transport: Transport,
    remote_os: OperatingSystem = OperatingSystem.LINUX,
) -> SessionBackend:
    """Detect which session manager is available on the remote."""
    if remote_os == OperatingSystem.WINDOWS:
        return SessionBackend.POWERSHELL

    which_cmd = "which" if remote_os != OperatingSystem.ANDROID else "command -v"

    for backend, binary in [
        (SessionBackend.TMUX, "tmux"),
        (SessionBackend.SCREEN, "screen"),
    ]:
        result = transport.run(f"{which_cmd} {binary}", timeout=10)
        if result.ok:
            logger.info("session backend: %s", backend.value)
            return backend

    logger.info("session backend: nohup (no tmux/screen)")
    return SessionBackend.NOHUP


def start_detached(
    transport: Transport,
    task_id: str,
    command: str,
    workspace: str,
    backend: SessionBackend,
) -> None:
    """Start *command* in a detached session on the remote.

    The command's stdout/stderr are tee'd (Unix) or redirected
    (Windows) to log files.  On exit, the return code is written to
    a sentinel file so ``poll()`` can detect completion.
    """
    if backend == SessionBackend.POWERSHELL:
        _start_detached_windows(transport, task_id, command, workspace)
    else:
        _start_detached_unix(transport, task_id, command, workspace, backend)


def _start_detached_unix(
    transport: Transport,
    task_id: str,
    command: str,
    workspace: str,
    backend: SessionBackend,
) -> None:
    session_name = f"raptor-{task_id}"
    q_sentinel = _sh_quote(f"{workspace}/{_SENTINEL_NAME}")
    q_stdout = _sh_quote(f"{workspace}/{_STDOUT_LOG}")
    q_stderr = _sh_quote(f"{workspace}/{_STDERR_LOG}")
    q_workspace = _sh_quote(workspace)

    wrapped = (
        f"{{ {command} ; }} "
        f"> >(tee {q_stdout}) "
        f"2> >(tee {q_stderr} >&2) ; "
        f"echo $? > {q_sentinel}"
    )

    if backend == SessionBackend.TMUX:
        start_cmd = (
            f"tmux new-session -d -s {session_name} "
            f"'cd {q_workspace} && {wrapped}'"
        )
    elif backend == SessionBackend.SCREEN:
        start_cmd = (
            f"screen -dmS {session_name} bash -c "
            f"'cd {q_workspace} && {wrapped}'"
        )
    else:
        start_cmd = (
            f"cd {q_workspace} && nohup bash -c '{wrapped}' &"
        )

    result = transport.run(start_cmd, timeout=30)
    if not result.ok:
        raise TransportError(
            f"failed to start detached session: {result.stderr}"
        )

    _write_pid_unix(transport, workspace, session_name, backend)

    logger.info(
        "[%s] started detached (%s) in %s",
        task_id, backend.value, workspace,
    )


def _start_detached_windows(
    transport: Transport,
    task_id: str,
    command: str,
    workspace: str,
) -> None:
    """Start a detached process on Windows via PowerShell.

    Creates a wrapper script that runs the command, captures its exit
    code, and writes it to the sentinel file.  The wrapper runs as a
    background process that survives WinRM session teardown.
    """
    sentinel = f"{workspace}\\{_SENTINEL_NAME}"
    pid_file = f"{workspace}\\{_PID_NAME}"
    stdout_log = f"{workspace}\\{_STDOUT_LOG}"
    stderr_log = f"{workspace}\\{_STDERR_LOG}"
    wrapper = f"{workspace}\\raptor-wrapper.ps1"

    _ps_escape = _ps_escape_str

    wrapper_content = (
        f"Set-Location '{_ps_escape(workspace)}'\n"
        f"try {{\n"
        f"  {command} > '{_ps_escape(stdout_log)}' 2> '{_ps_escape(stderr_log)}'\n"
        f"  $LASTEXITCODE | Out-File -FilePath '{_ps_escape(sentinel)}' -Encoding ASCII\n"
        f"}} catch {{\n"
        f"  1 | Out-File -FilePath '{_ps_escape(sentinel)}' -Encoding ASCII\n"
        f"  $_.Exception.Message | Out-File -FilePath '{_ps_escape(stderr_log)}' -Append\n"
        f"}}\n"
    )

    write_script = (
        f"Set-Content -Path '{_ps_escape(wrapper)}' "
        f"-Value @'\n{wrapper_content}\n'@"
    )
    result = transport.run(write_script, timeout=15)
    if not result.ok:
        raise TransportError(
            f"failed to write wrapper script: {result.stderr}"
        )

    start_cmd = (
        f"$proc = Start-Process -FilePath 'powershell.exe' "
        f"-ArgumentList '-ExecutionPolicy','Bypass','-File','{_ps_escape(wrapper)}' "
        f"-WindowStyle Hidden -PassThru; "
        f"$proc.Id | Out-File -FilePath '{_ps_escape(pid_file)}' -Encoding ASCII"
    )
    result = transport.run(start_cmd, timeout=30)
    if not result.ok:
        raise TransportError(
            f"failed to start detached process: {result.stderr}"
        )

    logger.info(
        "[%s] started detached (powershell) in %s",
        task_id, workspace,
    )


def _write_pid_unix(
    transport: Transport,
    workspace: str,
    session_name: str,
    backend: SessionBackend,
) -> None:
    q_pid_file = _sh_quote(f"{workspace}/{_PID_NAME}")

    if backend == SessionBackend.TMUX:
        result = transport.run(
            f"tmux list-panes -t {session_name} -F '#{{pane_pid}}'",
            timeout=10,
        )
        pid_str = _validated_pid(result.stdout) if result.ok else None
        if pid_str:
            transport.run(f"echo {pid_str} > {q_pid_file}", timeout=5)
    elif backend == SessionBackend.SCREEN:
        result = transport.run(
            f"screen -ls {session_name} | grep -oP '\\d+(?=\\.{session_name})'",
            timeout=10,
        )
        pid_str = _validated_pid(result.stdout) if result.ok else None
        if pid_str:
            transport.run(f"echo {pid_str} > {q_pid_file}", timeout=5)


# ── polling ──────────────────────────────────────────────────────────

def poll(
    transport: Transport,
    task_id: str,
    workspace: str,
    *,
    tail_lines: int = 20,
    is_windows: bool = False,
) -> RemoteTaskState:
    """Check whether a detached task has completed.

    Non-blocking: runs a few quick commands over the existing
    transport connection and returns immediately.
    """
    if is_windows:
        return _poll_windows(transport, task_id, workspace, tail_lines)
    return _poll_unix(transport, task_id, workspace, tail_lines)


def _poll_unix(
    transport: Transport,
    task_id: str,
    workspace: str,
    tail_lines: int,
) -> RemoteTaskState:
    q_sentinel = _sh_quote(f"{workspace}/{_SENTINEL_NAME}")
    q_pid_file = _sh_quote(f"{workspace}/{_PID_NAME}")

    exit_result = transport.run(f"cat {q_sentinel} 2>/dev/null", timeout=10)
    if exit_result.ok and exit_result.stdout.strip():
        try:
            exit_code = int(exit_result.stdout.strip())
        except ValueError:
            exit_code = 1
        return RemoteTaskState(
            task_id=task_id,
            running=False,
            exit_code=exit_code,
            tail_stdout=_tail_unix(transport, f"{workspace}/{_STDOUT_LOG}", tail_lines),
            tail_stderr=_tail_unix(transport, f"{workspace}/{_STDERR_LOG}", tail_lines),
        )

    pid = None
    pid_result = transport.run(f"cat {q_pid_file} 2>/dev/null", timeout=10)
    if pid_result.ok and pid_result.stdout.strip():
        try:
            pid = int(pid_result.stdout.strip())
        except ValueError:
            pass

    return RemoteTaskState(
        task_id=task_id,
        running=True,
        pid=pid,
        tail_stdout=_tail_unix(transport, f"{workspace}/{_STDOUT_LOG}", tail_lines),
        tail_stderr=_tail_unix(transport, f"{workspace}/{_STDERR_LOG}", tail_lines),
    )


def _poll_windows(
    transport: Transport,
    task_id: str,
    workspace: str,
    tail_lines: int,
) -> RemoteTaskState:
    sentinel = f"{workspace}\\{_SENTINEL_NAME}"
    pid_file = f"{workspace}\\{_PID_NAME}"

    exit_result = transport.run(
        f"if (Test-Path '{sentinel}') {{ Get-Content '{sentinel}' }}",
        timeout=10,
    )
    if exit_result.ok and exit_result.stdout.strip():
        try:
            exit_code = int(exit_result.stdout.strip())
        except ValueError:
            exit_code = 1
        return RemoteTaskState(
            task_id=task_id,
            running=False,
            exit_code=exit_code,
            tail_stdout=_tail_windows(transport, f"{workspace}\\{_STDOUT_LOG}", tail_lines),
            tail_stderr=_tail_windows(transport, f"{workspace}\\{_STDERR_LOG}", tail_lines),
        )

    pid = None
    pid_result = transport.run(
        f"if (Test-Path '{pid_file}') {{ Get-Content '{pid_file}' }}",
        timeout=10,
    )
    if pid_result.ok and pid_result.stdout.strip():
        try:
            pid = int(pid_result.stdout.strip())
        except ValueError:
            pass

    running = True
    if pid:
        alive = transport.run(
            f"Get-Process -Id {pid} -ErrorAction SilentlyContinue | "
            f"Select-Object -ExpandProperty Id",
            timeout=10,
        )
        if not alive.ok or not alive.stdout.strip():
            running = False

    return RemoteTaskState(
        task_id=task_id,
        running=running,
        pid=pid,
        tail_stdout=_tail_windows(transport, f"{workspace}\\{_STDOUT_LOG}", tail_lines),
        tail_stderr=_tail_windows(transport, f"{workspace}\\{_STDERR_LOG}", tail_lines),
    )


def _tail_unix(transport: Transport, path: str, lines: int) -> str:
    result = transport.run(
        f"tail -n {lines} {_sh_quote(path)} 2>/dev/null", timeout=10,
    )
    return result.stdout if result.ok else ""


def _tail_windows(transport: Transport, path: str, lines: int) -> str:
    result = transport.run(
        f"if (Test-Path '{path}') {{ Get-Content '{path}' -Tail {lines} }}",
        timeout=10,
    )
    return result.stdout if result.ok else ""


# ── kill ─────────────────────────────────────────────────────────────

def kill_session(
    transport: Transport,
    task_id: str,
    workspace: str,
    backend: SessionBackend,
) -> bool:
    """Kill a running detached session.  Returns True if killed."""
    if backend == SessionBackend.POWERSHELL:
        return _kill_windows(transport, workspace)

    session_name = f"raptor-{task_id}"

    if backend == SessionBackend.TMUX:
        result = transport.run(f"tmux kill-session -t {session_name}", timeout=10)
        return result.ok
    elif backend == SessionBackend.SCREEN:
        result = transport.run(f"screen -S {session_name} -X quit", timeout=10)
        return result.ok
    else:
        return _kill_by_pid(transport, workspace, unix=True)


def _kill_windows(transport: Transport, workspace: str) -> bool:
    pid_file = f"{workspace}\\{_PID_NAME}"
    pid_result = transport.run(
        f"if (Test-Path '{pid_file}') {{ Get-Content '{pid_file}' }}",
        timeout=10,
    )
    pid_str = _validated_pid(pid_result.stdout) if pid_result.ok else None
    if pid_str:
        transport.run(
            f"Stop-Process -Id {pid_str} -Force "
            f"-ErrorAction SilentlyContinue",
            timeout=10,
        )
        return True
    return False


def _kill_by_pid(transport: Transport, workspace: str, *, unix: bool) -> bool:
    pid_file = f"{workspace}/{_PID_NAME}" if unix else f"{workspace}\\{_PID_NAME}"
    q_path = _sh_quote(pid_file) if unix else pid_file
    cat_cmd = f"cat {q_path} 2>/dev/null" if unix else f"Get-Content '{pid_file}'"
    pid_result = transport.run(cat_cmd, timeout=10)
    pid_str = _validated_pid(pid_result.stdout) if pid_result.ok else None
    if pid_str:
        transport.run(f"kill {pid_str}", timeout=10)
        return True
    return False


# ── cleanup ──────────────────────────────────────────────────────────

def cleanup_workspace(
    transport: Transport,
    workspace: str,
    *,
    is_windows: bool = False,
) -> None:
    """Remove the remote workspace.  Platform-aware."""
    if is_windows:
        transport.run(
            f"Remove-Item -Recurse -Force -Path '{_ps_escape_str(workspace)}' "
            f"-ErrorAction SilentlyContinue",
            timeout=30,
        )
    else:
        transport.run(f"rm -rf {_sh_quote(workspace)}", timeout=30)


_PID_RE = re.compile(r"^\d{1,10}$")


def _validated_pid(raw: str) -> str | None:
    """Return the PID string only if it looks like a decimal integer."""
    cleaned = raw.strip()
    if _PID_RE.match(cleaned):
        return cleaned
    return None


def _sh_quote(s: str) -> str:
    """POSIX shell-safe quoting."""
    if not s:
        return "''"
    return "'" + s.replace("'", "'\"'\"'") + "'"


def _ps_escape_str(s: str) -> str:
    """Escape for PowerShell single-quoted strings."""
    return s.replace("'", "''")

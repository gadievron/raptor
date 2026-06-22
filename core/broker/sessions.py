"""Remote session management for long-running tasks.

Wraps commands in tmux (preferred) or screen so they survive SSH
disconnects.  The head node can reconnect later to poll status,
stream output, or collect results.

Design:
    - Each task gets a tmux session named ``raptor-<task_id>``
    - The command writes its exit code to a sentinel file on completion
    - ``poll()`` checks for the sentinel without blocking
    - ``attach()`` reconnects the operator's terminal to the live session
    - ``collect()`` downloads results after completion

tmux is preferred because it's scriptable and on every modern Linux.
Falls back to screen if tmux is absent.  If neither is available,
falls back to nohup (no reattach, but still survives disconnect).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

from core.broker.transport import CommandResult, Transport, TransportError

logger = logging.getLogger(__name__)


class SessionBackend(Enum):
    TMUX = "tmux"
    SCREEN = "screen"
    NOHUP = "nohup"


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


def detect_session_backend(transport: Transport) -> SessionBackend:
    """Detect which session manager is available on the remote."""
    for backend, binary in [
        (SessionBackend.TMUX, "tmux"),
        (SessionBackend.SCREEN, "screen"),
    ]:
        result = transport.run(f"which {binary}", timeout=10)
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

    The command's stdout/stderr are tee'd to log files.  On exit,
    the return code is written to a sentinel file so ``poll()`` can
    detect completion without keeping the SSH channel open.
    """
    session_name = f"raptor-{task_id}"
    sentinel = f"{workspace}/{_SENTINEL_NAME}"
    pid_file = f"{workspace}/{_PID_NAME}"
    stdout_log = f"{workspace}/{_STDOUT_LOG}"
    stderr_log = f"{workspace}/{_STDERR_LOG}"

    wrapped = (
        f"{{ {command} ; }} "
        f"> >(tee {stdout_log}) "
        f"2> >(tee {stderr_log} >&2) ; "
        f"echo $? > {sentinel}"
    )

    if backend == SessionBackend.TMUX:
        start_cmd = (
            f"tmux new-session -d -s {session_name} "
            f"'cd {workspace} && {wrapped}'"
        )
    elif backend == SessionBackend.SCREEN:
        start_cmd = (
            f"screen -dmS {session_name} bash -c "
            f"'cd {workspace} && {wrapped}'"
        )
    else:
        start_cmd = (
            f"cd {workspace} && nohup bash -c '{wrapped}' &"
        )

    result = transport.run(start_cmd, timeout=30)
    if not result.ok:
        raise TransportError(
            f"failed to start detached session: {result.stderr}"
        )

    _write_pid(transport, workspace, session_name, backend)

    logger.info(
        "[%s] started detached (%s) in %s on remote",
        task_id, backend.value, workspace,
    )


def _write_pid(
    transport: Transport,
    workspace: str,
    session_name: str,
    backend: SessionBackend,
) -> None:
    """Best-effort: write the PID of the session's child process."""
    pid_file = f"{workspace}/{_PID_NAME}"

    if backend == SessionBackend.TMUX:
        result = transport.run(
            f"tmux list-panes -t {session_name} -F '#{{pane_pid}}'",
            timeout=10,
        )
        if result.ok and result.stdout.strip():
            transport.run(
                f"echo {result.stdout.strip()} > {pid_file}", timeout=5,
            )
    elif backend == SessionBackend.SCREEN:
        result = transport.run(
            f"screen -ls {session_name} | grep -oP '\\d+(?=\\.{session_name})'",
            timeout=10,
        )
        if result.ok and result.stdout.strip():
            transport.run(
                f"echo {result.stdout.strip()} > {pid_file}", timeout=5,
            )


def poll(
    transport: Transport,
    task_id: str,
    workspace: str,
    *,
    tail_lines: int = 20,
) -> RemoteTaskState:
    """Check whether a detached task has completed.

    Non-blocking: runs a few quick commands over the existing
    transport connection and returns immediately.
    """
    sentinel = f"{workspace}/{_SENTINEL_NAME}"
    pid_file = f"{workspace}/{_PID_NAME}"

    exit_result = transport.run(f"cat {sentinel} 2>/dev/null", timeout=10)
    if exit_result.ok and exit_result.stdout.strip():
        exit_code = int(exit_result.stdout.strip())
        stdout_tail = _tail(transport, f"{workspace}/{_STDOUT_LOG}", tail_lines)
        stderr_tail = _tail(transport, f"{workspace}/{_STDERR_LOG}", tail_lines)
        return RemoteTaskState(
            task_id=task_id,
            running=False,
            exit_code=exit_code,
            tail_stdout=stdout_tail,
            tail_stderr=stderr_tail,
        )

    pid = None
    pid_result = transport.run(f"cat {pid_file} 2>/dev/null", timeout=10)
    if pid_result.ok and pid_result.stdout.strip():
        pid = int(pid_result.stdout.strip())

    stdout_tail = _tail(transport, f"{workspace}/{_STDOUT_LOG}", tail_lines)
    stderr_tail = _tail(transport, f"{workspace}/{_STDERR_LOG}", tail_lines)

    return RemoteTaskState(
        task_id=task_id,
        running=True,
        pid=pid,
        tail_stdout=stdout_tail,
        tail_stderr=stderr_tail,
    )


def _tail(transport: Transport, path: str, lines: int) -> str:
    result = transport.run(f"tail -n {lines} {path} 2>/dev/null", timeout=10)
    return result.stdout if result.ok else ""


def kill_session(
    transport: Transport,
    task_id: str,
    workspace: str,
    backend: SessionBackend,
) -> bool:
    """Kill a running detached session.  Returns True if killed."""
    session_name = f"raptor-{task_id}"

    if backend == SessionBackend.TMUX:
        result = transport.run(f"tmux kill-session -t {session_name}", timeout=10)
        return result.ok
    elif backend == SessionBackend.SCREEN:
        result = transport.run(f"screen -S {session_name} -X quit", timeout=10)
        return result.ok
    else:
        pid_file = f"{workspace}/{_PID_NAME}"
        pid_result = transport.run(f"cat {pid_file} 2>/dev/null", timeout=10)
        if pid_result.ok and pid_result.stdout.strip():
            transport.run(f"kill {pid_result.stdout.strip()}", timeout=10)
            return True
    return False


def cleanup_workspace(
    transport: Transport,
    workspace: str,
    *,
    is_windows: bool = False,
) -> None:
    """Remove the remote workspace.  Platform-aware."""
    if is_windows:
        transport.run(
            f'Remove-Item -Recurse -Force -Path "{workspace}"',
            timeout=30,
        )
    else:
        transport.run(f"rm -rf {workspace}", timeout=30)

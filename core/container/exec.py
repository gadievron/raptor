"""Command execution inside an already-running container.

``docker exec`` mechanics with the same posture guarantees the launch
path establishes: no ``--privileged``, no ``-u`` override (the command
runs as whatever user the image set), no TTY, wall-clock bounded, and
an ownership gate — callers name the label their launcher stamped, and
a container without it is refused, so an agent-driven consumer can
never exec into arbitrary host containers.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from core.container.proc import run_cli

_OWNER_CHECK_TIMEOUT = 5.0
STDOUT_CAP_BYTES = 8 * 1024
STDERR_CAP_BYTES = 4 * 1024
DEFAULT_TIMEOUT_SECONDS = 30.0
MAX_TIMEOUT_SECONDS = 300.0


def container_has_label(container_id: str, key: str, value: str) -> bool:
    """True iff the container carries exactly ``key=value``."""
    outcome = run_cli(
        [
            "docker",
            "inspect",
            "--format",
            f'{{{{index .Config.Labels "{key}"}}}}',
            container_id,
        ],
        timeout=_OWNER_CHECK_TIMEOUT,
    )
    return (
        outcome.returncode == 0
        and (outcome.stdout or "").strip() == value
    )


def classify_exec_exit(exit_code: int, stderr: str) -> str:
    """Classify ``docker exec`` failures.

    Different failure surface from ``docker run``: no image pull, no
    manifest issues. Common cases for in-container probes:

    * 127 — command not found (binary missing in container)
    * 126 — permission denied (binary not executable)
    * 137 — SIGKILL (often OOM)
    * stderr 'no space left' — disk_full (rare during exec, possible
      with `tar` / `cp` / writes to overlay)
    * stderr 'i/o' / 'connection' — transport (rare during exec)
    """
    if exit_code == 0:
        return "ok"
    sl = stderr.lower()
    if "no space left on device" in sl:
        return "disk_full"
    if exit_code == 137 or "out of memory" in sl or "killed" in sl[:80]:
        return "oom_killed"
    if (
        exit_code == 127
        or "command not found" in sl
        or "executable file not found" in sl
    ):
        return "command_not_found"
    if exit_code == 126 or "permission denied" in sl:
        return "permission_denied"
    if any(p in sl for p in ("i/o error", "input/output error", "connection reset")):
        return "transport"
    return "unknown"


@dataclass
class ExecOutcome:
    """Result of :func:`exec_in_container` — data, never an exception."""

    ok: bool  # True iff exit_code == 0
    container_id: str
    command: str
    exit_code: int = -1
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    reason: str = ""  # populated when ok == False
    # ok / disk_full / oom_killed / command_not_found /
    # permission_denied / transport / unknown
    reason_class: str = "ok"


def exec_in_container(
    *,
    container_id: str,
    command: str,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    workdir: str = "",
    required_label: tuple[str, str] | None = None,
) -> ExecOutcome:
    """Execute ``command`` in ``container_id`` via ``docker exec``.

    ``command`` runs through ``sh -c`` so callers can use shell syntax
    (pipes, redirects, env vars). Output is capped
    (:data:`STDOUT_CAP_BYTES` / :data:`STDERR_CAP_BYTES`) and the
    subprocess is killed after ``timeout_seconds`` (clamped to
    [1, :data:`MAX_TIMEOUT_SECONDS`]). When ``required_label`` is
    given, a container not carrying it is refused.
    """
    if not container_id:
        return ExecOutcome(
            ok=False,
            container_id="",
            command=command,
            reason="container_id is empty",
        )
    if required_label is not None and not container_has_label(
        container_id, *required_label
    ):
        return ExecOutcome(
            ok=False,
            container_id=container_id,
            command=command,
            reason=(
                f"container is not owned by this launcher "
                f"(missing label {required_label[0]})"
            ),
        )
    if not command or not command.strip():
        return ExecOutcome(
            ok=False,
            container_id=container_id,
            command=command,
            reason="command is empty",
        )
    # Clamp timeout. A runaway exec should not stall the caller.
    timeout_clamped = min(max(float(timeout_seconds), 1.0), MAX_TIMEOUT_SECONDS)

    argv: list[str] = ["docker", "exec"]
    if workdir:
        argv.extend(["--workdir", workdir])
    # No -u override, no --privileged, no -t. Keep it minimal.
    argv.extend([container_id, "sh", "-c", command])

    start = time.monotonic()
    outcome = run_cli(argv, timeout=timeout_clamped)
    duration = time.monotonic() - start

    if outcome.timed_out:
        return ExecOutcome(
            ok=False,
            container_id=container_id,
            command=command,
            exit_code=-1,
            stdout=outcome.stdout[-STDOUT_CAP_BYTES:],
            stderr=outcome.stderr[-STDERR_CAP_BYTES:],
            duration_s=duration,
            reason=f"timeout after {timeout_clamped}s",
            reason_class="transport",
        )
    if outcome.returncode is None and outcome.stderr.startswith("command_not_found:"):
        return ExecOutcome(
            ok=False,
            container_id=container_id,
            command=command,
            reason="docker CLI not found on PATH",
            reason_class="unknown",
        )

    stdout = (outcome.stdout or "")[-STDOUT_CAP_BYTES:]
    stderr = (outcome.stderr or "")[-STDERR_CAP_BYTES:]
    ok = outcome.returncode == 0
    # returncode is int | None; normalize to -1 so downstream fields
    # stay int-typed (matches the timeout path).
    exit_code = outcome.returncode if outcome.returncode is not None else -1
    reason = "" if ok else f"exit_code={exit_code}"
    reason_class = classify_exec_exit(exit_code, stderr)
    return ExecOutcome(
        ok=ok,
        container_id=container_id,
        command=command,
        exit_code=exit_code,
        stdout=stdout,
        stderr=stderr,
        duration_s=duration,
        reason=reason,
        reason_class=reason_class,
    )

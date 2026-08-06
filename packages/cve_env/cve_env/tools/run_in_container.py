"""Run a command inside an already-launched container.

Some CVEs are reproducible in containers but fail ``verify`` because
``verify`` only speaks HTTP: Redis (RESP), sudo Baron Samedit (local
setuid PoC), polkit PwnKit (in-container exploit run). The agent can do
those probes itself via this tool.

Security invariants:

* The tool uses ``docker exec`` on a container that the agent has
  already launched via ``docker_run`` (which enforces ``--cap-drop
  ALL``, ``--security-opt=no-new-privileges:true``, localhost-only
  port bind). ``docker exec`` alone cannot loosen that posture.
* No ``--privileged`` override. No ``-u root`` override (command runs
  as whatever user the image set; agent cannot escalate). No TTY.
* Timeout-bounded; kills the subprocess on expiry so a hung exec
  cannot stall the bench.

Returns a structured dict with exit_code, stdout (capped), stderr
(capped), duration. The agent interprets the result in its next
verify step.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from cve_env.utils.run import run_with_timeout

_OWNER_CHECK_TIMEOUT = 5.0
_STDOUT_CAP_BYTES = 8 * 1024
_STDERR_CAP_BYTES = 4 * 1024
_DEFAULT_TIMEOUT_SECONDS = 30.0
_MAX_TIMEOUT_SECONDS = 300.0


def _is_owned_container(container_id: str) -> bool:
    """Return True only if the container carries the ``cve-env.owner=cve-env`` label.

    Prevents the LLM agent from ``docker exec``-ing into arbitrary host
    containers that it did not launch via ``docker_run`` / ``docker_compose_up``.
    """
    outcome = run_with_timeout(
        [
            "docker",
            "inspect",
            "--format",
            '{{index .Config.Labels "cve-env.owner"}}',
            container_id,
        ],
        timeout=_OWNER_CHECK_TIMEOUT,
    )
    return (
        outcome.returncode == 0
        and (outcome.stdout or "").strip() == "cve-env"
    )


def _classify_exec_exit(exit_code: int, stderr: str) -> str:
    """Classify ``docker exec`` failures.

    Different failure surface from ``docker run``: no image pull, no
    manifest issues. Common cases for verify probes:

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
class ExecResult:
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


def run_in_container(
    *,
    container_id: str,
    command: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    workdir: str = "",
) -> ExecResult:
    """Execute ``command`` in ``container_id`` via ``docker exec``.

    ``command`` is run through ``sh -c`` so the agent can use shell
    syntax (pipes, redirects, env vars). Output is capped to
    ``_STDOUT_CAP_BYTES`` / ``_STDERR_CAP_BYTES`` and the subprocess
    is killed after ``timeout_seconds``.
    """
    if not container_id:
        return ExecResult(
            ok=False,
            container_id="",
            command=command,
            reason="container_id is empty",
        )
    if not _is_owned_container(container_id):
        return ExecResult(
            ok=False,
            container_id=container_id,
            command=command,
            reason="container is not owned by cve-env (missing label)",
        )
    if not command or not command.strip():
        return ExecResult(
            ok=False,
            container_id=container_id,
            command=command,
            reason="command is empty",
        )
    # Clamp timeout upward. A runaway exec should not stall the bench.
    timeout_clamped = min(max(float(timeout_seconds), 1.0), _MAX_TIMEOUT_SECONDS)

    argv: list[str] = ["docker", "exec"]
    if workdir:
        argv.extend(["--workdir", workdir])
    # No -u override, no --privileged, no -t. Keep it minimal.
    argv.extend([container_id, "sh", "-c", command])

    # run_with_timeout auto-decodes output, so the timeout branch reduces to a
    # check on outcome.timed_out, and the missing-binary branch checks for the
    # canonical "command_not_found:" prefix the helper writes to stderr.
    start = time.monotonic()
    outcome = run_with_timeout(argv, timeout=timeout_clamped)
    duration = time.monotonic() - start

    if outcome.timed_out:
        return ExecResult(
            ok=False,
            container_id=container_id,
            command=command,
            exit_code=-1,
            stdout=outcome.stdout[-_STDOUT_CAP_BYTES:],
            stderr=outcome.stderr[-_STDERR_CAP_BYTES:],
            duration_s=duration,
            reason=f"timeout after {timeout_clamped}s",
            reason_class="transport",
        )
    if outcome.returncode is None and outcome.stderr.startswith("command_not_found:"):
        return ExecResult(
            ok=False,
            container_id=container_id,
            command=command,
            reason="docker CLI not found on PATH",
            reason_class="unknown",
        )

    stdout = (outcome.stdout or "")[-_STDOUT_CAP_BYTES:]
    stderr = (outcome.stderr or "")[-_STDERR_CAP_BYTES:]
    ok = outcome.returncode == 0
    # RunOutcome.returncode is int | None (None when subprocess never
    # started OR on timeout). Normalize to -1 here so downstream fields
    # are int-typed — matches the existing convention at line 134
    # (timeout path) and the test at test_run_in_container.py:58.
    exit_code = outcome.returncode if outcome.returncode is not None else -1
    reason = "" if ok else f"exit_code={exit_code}"
    reason_class = _classify_exec_exit(exit_code, stderr)
    return ExecResult(
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


def run_in_container_payload(
    *,
    container_id: str,
    command: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    workdir: str = "",
) -> dict[str, Any]:
    """Agent-tool-ready dict shape."""
    r = run_in_container(
        container_id=container_id,
        command=command,
        timeout_seconds=timeout_seconds,
        workdir=workdir,
    )
    return {
        "ok": r.ok,
        "container_id": r.container_id,
        "command": r.command,
        "exit_code": r.exit_code,
        "stdout": r.stdout,
        "stderr": r.stderr,
        "duration_s": r.duration_s,
        "reason": r.reason,
        "reason_class": r.reason_class,
    }

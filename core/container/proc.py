"""Bounded CLI runner + allowlisted child env for container tooling.

One subprocess boundary for every ``docker`` / ``docker compose`` /
registry-CLI invocation. Two properties every caller relies on:

1. **Never raises on the failure paths a container host actually
   produces.** Timeout, missing binary, and transport-level spawn
   errors all fold into :class:`RunOutcome` — callers branch on data,
   not on exception plumbing.

2. **Bounded even against unreapable children.** On POSIX,
   ``subprocess.run``'s TimeoutExpired path does an UNBOUNDED
   ``process.wait()`` after SIGKILL — which blocks forever on a child
   wedged in uninterruptible D-state (dead VM socket / wedged
   virtiofs; the classic Colima hang). The runner executes
   ``subprocess.run`` in a daemon thread joined for
   ``timeout + _REAP_GRACE_S`` and abandons it when wedged, so the
   caller's wall-clock promise holds no matter what the daemon does.

The child environment is the core allowlist
(:meth:`core.config.RaptorConfig.get_safe_env`) plus the docker CLI
daemon vars (:data:`DOCKER_CHILD_ENV_VARS`) — docker children must
reach the right daemon and its auth/TLS config, but must not inherit
proxy vars (the daemon does the pulls) or the operator shell's
LD_PRELOAD-class vars.
"""

from __future__ import annotations

import os
import queue
import subprocess
import threading
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

# Extra wall, beyond ``timeout``, granted to ``subprocess.run``'s own
# post-SIGKILL cleanup before the runner abandons the thread.
_REAP_GRACE_S: float = 10.0

# Docker CLI children need these to reach the right daemon and its
# auth/TLS configuration. HOME is already on the core allowlist, so
# ~/.docker/config.json credentials resolve without extra handling.
# Kept OUT of the core allowlist itself: most RAPTOR children must not
# see the docker-daemon configuration at all.
DOCKER_CHILD_ENV_VARS: tuple[str, ...] = (
    "DOCKER_HOST",
    "DOCKER_CONFIG",
    "DOCKER_CERT_PATH",
    "DOCKER_TLS_VERIFY",
    "DOCKER_CONTEXT",
)

# Proxy vars for the docker commands that speak to registries from the
# CLIENT process. The default env strips proxies deliberately — for
# run/build/pull the DAEMON does the transfers under its own proxy
# config — but ``docker manifest inspect`` (and kin) contact the
# registry directly from the CLI, so on proxy-only hosts they fail as
# transport errors unless the ambient proxy env is passed through.
# Callers opt in per invocation via ``keep_env=PROXY_ENV_VARS``.
PROXY_ENV_VARS: frozenset[str] = frozenset({
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "no_proxy",
})


def docker_child_env(*, keep: frozenset[str] = frozenset()) -> dict[str, str]:
    """Allowlisted env for a container-tooling child process.

    ``RaptorConfig.get_safe_env()`` plus :data:`DOCKER_CHILD_ENV_VARS`,
    plus any ``keep`` vars the call site opts back in (use sparingly and
    document why at each call site).
    """
    from core.config import RaptorConfig

    env = dict(RaptorConfig.get_safe_env())
    for k in (*DOCKER_CHILD_ENV_VARS, *keep):
        if k in os.environ:
            env[k] = os.environ[k]
    return env


@dataclass(frozen=True)
class RunOutcome:
    """Result of running a CLI subprocess with a wall-clock bound.

    On timeout: ``returncode=None``, ``timed_out=True``, stdout/stderr
    contain whatever the process emitted before the timeout fired.
    On normal exit (any returncode): ``timed_out=False``.
    ``returncode is None and not timed_out`` means the subprocess never
    started — ``stderr`` carries a ``command_not_found:`` or
    ``os_error:`` prefix to distinguish which.
    """

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool


def _decode(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def run_cli(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    keep_env: frozenset[str] = frozenset(),
) -> RunOutcome:
    """Run ``cmd`` with a wall-clock timeout. Never raises TimeoutExpired.

    Captures stdout/stderr as text (lenient UTF-8 — container output
    routinely carries stray latin-1 bytes). When ``env`` is None
    (default), :func:`docker_child_env` with ``keep=keep_env`` is
    passed; a caller-supplied ``env`` dict is used verbatim (caller's
    responsibility).
    """
    effective_env = docker_child_env(keep=keep_env) if env is None else env
    # Keep the call spelled ``subprocess.run`` (callers' existing mocks at
    # subprocess.run still intercept), but run it in a daemon thread joined
    # for only ``timeout + _REAP_GRACE_S``. If it is still alive after that,
    # its internal post-SIGKILL ``process.wait()`` is wedged on a D-state
    # child — abandon the thread (the orphan is reaped at process exit) and
    # report timed_out so the caller's wall-clock promise holds.
    result_q: queue.Queue[dict[str, Any]] = queue.Queue()

    def _target() -> None:
        try:
            result_q.put({"result": subprocess.run(
                cmd,
                timeout=timeout,
                cwd=cwd,
                env=effective_env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )})
        except subprocess.TimeoutExpired as exc:
            result_q.put({"timeout": exc})
        except FileNotFoundError as exc:
            result_q.put({"fnf": exc})
        except OSError as exc:
            result_q.put({"oserr": exc})
        except Exception as exc:  # noqa: BLE001 — surface as OSError-class
            result_q.put({"oserr": exc})

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    # Daemon thread abandoned on timeout — holds FDs until process exit.
    # In long runs, monitor FD count.
    worker.join(timeout + _REAP_GRACE_S)
    if worker.is_alive():
        return RunOutcome(
            returncode=None,
            stdout="",
            stderr=(
                f"timeout: subprocess unreapable after "
                f"{timeout + _REAP_GRACE_S:.0f}s (child wedged in D-state — "
                "abandoned to keep the wall-clock bound)"
            ),
            timed_out=True,
        )
    # worker finished ⇒ result_q has exactly one item (put precedes death).
    box = result_q.get_nowait()
    if "timeout" in box:
        exc = box["timeout"]
        return RunOutcome(
            returncode=None,
            stdout=_decode(exc.stdout),
            stderr=_decode(exc.stderr),
            timed_out=True,
        )
    if "fnf" in box:
        # cmd[0] not on PATH (or cwd is invalid). Subprocess never started.
        return RunOutcome(
            returncode=None,
            stdout="",
            stderr=f"command_not_found: {box['fnf']}",
            timed_out=False,
        )
    if "oserr" in box:
        # Transport-layer spawn failures (EAGAIN, EMFILE) tolerated as data.
        return RunOutcome(
            returncode=None,
            stdout="",
            stderr=f"os_error: {box['oserr']}",
            timed_out=False,
        )
    result = box["result"]
    return RunOutcome(
        returncode=result.returncode,
        stdout=result.stdout,
        stderr=result.stderr,
        timed_out=False,
    )

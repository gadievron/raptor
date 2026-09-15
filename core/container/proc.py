"""Bounded CLI runner + allowlisted child env for container tooling.

One subprocess boundary for every ``docker`` / ``docker compose`` /
registry-CLI invocation. Two properties every caller relies on:

1. **Never raises on the failure paths a container host actually
   produces.** Timeout, missing binary, and transport-level spawn
   errors all fold into :class:`RunOutcome` — callers branch on data,
   not on exception plumbing.

2. **Bounded even against unreapable children.** On POSIX, the
   post-SIGKILL ``process.wait()`` after a timeout is UNBOUNDED —
   it blocks forever on a child
   wedged in uninterruptible D-state (dead VM socket / wedged
   virtiofs; the classic Colima hang). The runner does its
   spawn/drain/wait in a daemon thread joined for
   ``timeout + _REAP_GRACE_S`` and abandons it when wedged, so the
   caller's wall-clock promise holds no matter what the daemon does.

3. **Bounded output, at the read boundary.** Child stdout/stderr are
   drained into per-stream tail buffers capped at
   ``max_output_bytes`` — hostile workload output (a container
   command spamming gigabytes) never accumulates wholesale in host
   memory before caller-side slicing.

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

# Extra wall, beyond ``timeout``, granted to the runner thread's own
# post-SIGKILL cleanup before the runner abandons it.
_REAP_GRACE_S: float = 10.0

# Per-stream capture cap (keep the TAIL — error diagnostics cluster at
# the end, and every caller-side slice is already tail-oriented).
# Trade-off, documented both ways: too LOW truncates legitimate large
# outputs — ``docker compose config`` resolved models, ``docker logs``
# reads that callers slice up to 1 MiB — corrupting their heads; too
# HIGH re-opens the memory DoS this cap exists for (a hostile container
# command like ``yes`` can emit gigabytes inside one 30 s exec window,
# and pre-cap the whole stream was buffered in host memory before any
# caller-side slice ran). 16 MiB clears every legitimate caller by an
# order of magnitude while keeping hostile output at a constant bound.
_OUTPUT_CAP_BYTES: int = 16 * 1024 * 1024

# Pipe-drain read granularity.
_DRAIN_CHUNK_BYTES: int = 65536

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

    ``truncated=True`` means at least one stream overflowed the
    ``max_output_bytes`` drain buffer and only its tail survived —
    capped output is otherwise indistinguishable from complete output,
    and a consumer that PARSES stdout (rather than slicing it for
    diagnostics) must refuse a truncated outcome instead of parsing a
    head-dropped document as if it were whole. Defaulted so existing
    constructor call sites and test mocks keep their shape.
    """

    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    truncated: bool = False


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
    max_output_bytes: int = _OUTPUT_CAP_BYTES,
) -> RunOutcome:
    """Run ``cmd`` with a wall-clock timeout. Never raises TimeoutExpired.

    Captures stdout/stderr as text (lenient UTF-8 — container output
    routinely carries stray latin-1 bytes), each stream capped at
    ``max_output_bytes`` AT THE READ BOUNDARY (tail kept): the child's
    output is drained into a bounded buffer as it arrives, so a hostile
    command emitting gigabytes never materialises wholesale in host
    memory. Truncation is never silent — an overflowed stream sets
    ``RunOutcome.truncated`` so parsing consumers can refuse the
    partial document. When ``env`` is None
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
    #
    # Output travels through pipes WE own instead of ``capture_output``
    # (which buffers the child's entire output in memory before any
    # caller-side slice can run): the child writes into the pipes,
    # drainer threads keep a bounded tail of each stream, and hostile
    # output size costs the drain buffers only. When ``subprocess.run``
    # is mocked, nothing writes to the pipes and the mock's own
    # ``stdout``/``stderr`` attributes are used, so the test seam keeps
    # its exact pre-pipe shape.
    result_q: queue.Queue[dict[str, Any]] = queue.Queue()

    def _drain(fd: int, sink: dict[str, bytes],
               overflowed: dict[str, bool], key: str) -> None:
        buf = bytearray()
        try:
            while True:
                chunk = os.read(fd, _DRAIN_CHUNK_BYTES)
                if not chunk:
                    break
                buf.extend(chunk)
                if len(buf) > max_output_bytes:
                    del buf[: len(buf) - max_output_bytes]
                    overflowed[key] = True
        except OSError:  # pragma: no cover — racy close
            pass
        finally:
            try:
                os.close(fd)
            except OSError:  # pragma: no cover — racy close
                pass
        sink[key] = bytes(buf)

    def _target() -> None:
        try:
            read_out, write_out = os.pipe()
            read_err, write_err = os.pipe()
        except OSError as exc:  # pragma: no cover — fd exhaustion
            result_q.put({"oserr": exc})
            return
        sink: dict[str, bytes] = {}
        overflowed: dict[str, bool] = {}
        drainers = [
            threading.Thread(target=_drain,
                             args=(read_out, sink, overflowed, "stdout"),
                             daemon=True),
            threading.Thread(target=_drain,
                             args=(read_err, sink, overflowed, "stderr"),
                             daemon=True),
        ]
        for t in drainers:
            t.start()

        def _finish_pipes() -> None:
            # Close OUR write ends (the child got dup'd copies) so the
            # drainers see EOF once the child — and any fd-inheriting
            # grandchild — is gone; the join then has communicate()'s
            # exact lifetime, and the outer daemon-join bounds a
            # grandchild that holds a pipe open.
            for fd in (write_out, write_err):
                try:
                    os.close(fd)
                except OSError:  # pragma: no cover — racy close
                    pass
            for t in drainers:
                t.join()

        try:
            result = subprocess.run(
                cmd,
                timeout=timeout,
                cwd=cwd,
                env=effective_env,
                stdout=write_out,
                stderr=write_err,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            _finish_pipes()
            if exc.output is None and exc.stderr is None:
                # fd-routed output: the exception carries none — attach
                # the drained partials (mocked TimeoutExpired keeps its
                # own payload).
                exc = subprocess.TimeoutExpired(
                    cmd, timeout,
                    output=_decode(sink.get("stdout")),
                    stderr=_decode(sink.get("stderr")),
                )
            result_q.put({"timeout": exc, "truncated": bool(overflowed)})
        except FileNotFoundError as exc:
            _finish_pipes()
            result_q.put({"fnf": exc})
        except OSError as exc:
            _finish_pipes()
            result_q.put({"oserr": exc})
        except Exception as exc:  # noqa: BLE001 — surface as OSError-class
            _finish_pipes()
            result_q.put({"oserr": exc})
        else:
            _finish_pipes()
            stdout = getattr(result, "stdout", None)
            stderr = getattr(result, "stderr", None)
            # ``overflowed`` only ever gains keys from the drainers, and a
            # mocked ``subprocess.run`` writes nothing to the pipes — so a
            # mock supplying its own stdout/stderr never reads as truncated.
            result_q.put({
                "result": subprocess.CompletedProcess(
                    cmd,
                    getattr(result, "returncode", None),
                    stdout=(stdout if stdout is not None
                            else _decode(sink.get("stdout"))),
                    stderr=(stderr if stderr is not None
                            else _decode(sink.get("stderr"))),
                ),
                "truncated": bool(overflowed),
            })

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
                f"{timeout + _REAP_GRACE_S:.0f}s (child wedged in D-state, "
                "or a descendant still holds the output pipes open — "
                "runner abandoned to keep the wall-clock bound)"
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
            truncated=box.get("truncated", False),
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
        truncated=box.get("truncated", False),
    )

"""Subprocess timeout helper.

Consolidates the duplicated ``subprocess.run(...) + except
TimeoutExpired`` blocks scattered across ``tools/source_build.py`` (via
``_run_git``), ``tools/docker_build.py``, ``tools/docker_compose_up.py``,
``tools/image_resolve.py``, ``tools/verify.py``,
``tools/run_in_container.py``, ``tools/github_fetch.py``.

This helper unifies the boundary: caller always gets a ``RunOutcome``
dataclass and decides what to do based on:

- ``timed_out=True`` → wall-clock timeout fired
- ``returncode is None and not timed_out`` → subprocess never started
  (cmd[0] not on PATH, or transport-level OSError); inspect ``stderr``
  for ``command_not_found:`` / ``os_error:`` prefixes to distinguish

The helper catches three exception classes (``TimeoutExpired``,
``FileNotFoundError``, ``OSError``) that pre-migration sites caught
variously. Callers handle site-specific cleanup (``shutil.rmtree``,
``warnings.append``, ``logger.warning``) on the timeout / transport-error
branch instead of inside an ``except`` block.
"""

from __future__ import annotations

import subprocess
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cve_env.utils.safe_env import safe_subprocess_env

# Extra wall, beyond ``timeout``, that we allow the underlying
# ``subprocess.run`` to finish its OWN cleanup. On POSIX,
# ``subprocess.run``'s TimeoutExpired path does an UNBOUNDED ``process.wait()``
# after SIGKILL — which blocks FOREVER on a child wedged in uninterruptible
# D-state (dead VM socket / wedged virtiofs). That is the ``docker_build →
# external wall`` hang mechanism. We run ``subprocess.run`` in a daemon thread
# and join only for ``timeout + _REAP_GRACE_S``; if it is still wedged we
# abandon it and return ``timed_out=True`` so the tool handler returns and
# clears ``_in_flight``.
_REAP_GRACE_S: float = 10.0


@dataclass(frozen=True)
class RunOutcome:
    """Result of running a subprocess with a timeout.

    On timeout: returncode=None, timed_out=True, stdout/stderr contain
    whatever the process emitted before the timeout fired.
    On normal exit (any returncode): timed_out=False, returncode is set.
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


def run_with_timeout(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    keep_env: frozenset[str] = frozenset(),
) -> RunOutcome:
    """Run `cmd` with a wall-clock timeout. Never raises TimeoutExpired.

    Returns RunOutcome(timed_out=True, returncode=None, ...) if the timeout
    fires; otherwise returns RunOutcome(timed_out=False, returncode=N, ...)
    where N is the actual exit code (zero or nonzero — caller decides).

    Captures stdout/stderr as text. Caller-supplied env replaces the entire
    environment when provided; pass `os.environ.copy() | {...}` to merge.

    When ``env`` is None (default), the helper passes
    ``safe_subprocess_env(keep=keep_env)`` so dangerous parent-shell vars
    (HTTPS_PROXY / LD_PRELOAD / GIT_SSH_COMMAND / PYTHONPATH / ...) do NOT
    leak into git/docker/gh subprocesses. Use ``keep_env={"HTTPS_PROXY"}``
    to opt back in for a specific dangerous var. If a caller passes their
    own ``env`` dict, it is used verbatim (caller's responsibility).
    """
    effective_env = safe_subprocess_env(keep=keep_env) if env is None else env
    # Keep the call to ``subprocess.run`` (so callers' existing mocks at
    # ``subprocess.run`` still intercept), but run it in a daemon thread joined
    # for only ``timeout + _REAP_GRACE_S``. If ``subprocess.run`` is still alive
    # after that, its internal post-SIGKILL ``process.wait()`` is wedged on a
    # D-state child (dead VM socket) — we abandon the daemon thread (the orphaned
    # child is reaped when this per-CVE process exits) and return
    # ``timed_out=True`` so the tool handler returns and clears ``_in_flight``,
    # instead of riding to the external wall.
    box: dict[str, Any] = {}

    def _target() -> None:
        try:
            box["result"] = subprocess.run(
                cmd,
                timeout=timeout,
                cwd=cwd,
                env=effective_env,
                capture_output=True,
                text=True,
                # Decode container/subprocess stdout LENIENTLY: real-world output
                # carries non-UTF-8 bytes (e.g. a 0xa9 latin-1 copyright byte).
                # Without errors="replace", text=True decodes strictly and raises
                # UnicodeDecodeError (a ValueError) — NOT caught below — crashing
                # this daemon thread.
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            box["timeout"] = exc
        except FileNotFoundError as exc:
            box["fnf"] = exc
        except OSError as exc:
            box["oserr"] = exc

    worker = threading.Thread(target=_target, daemon=True)
    worker.start()
    worker.join(timeout + _REAP_GRACE_S)
    if worker.is_alive():
        # subprocess.run wedged in its own unbounded post-kill wait() — abandon.
        return RunOutcome(
            returncode=None,
            stdout="",
            stderr=(
                f"timeout: subprocess unreapable after {timeout + _REAP_GRACE_S:.0f}s "
                "(child wedged in D-state — abandoned to avoid the 1440s wall)"
            ),
            timed_out=True,
        )
    # worker finished ⇒ box is fully populated (assignment precedes thread death).
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
        # tools/docker_compose_up._compose_invocation and
        # tools/github_fetch.resolve_github_token caught bare ``OSError`` on top
        # of TimeoutExpired/FileNotFoundError to tolerate transport-layer spawn
        # failures (EAGAIN, EMFILE). Catching here keeps callers simple.
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

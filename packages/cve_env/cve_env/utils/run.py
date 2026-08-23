"""Subprocess timeout helper — delegates to ``core.container.proc``.

Pre-integration this module carried its own daemon-thread-bounded
``subprocess.run`` wrapper (consolidating the duplicated timeout blocks
across ``tools/source_build.py``, ``tools/docker_build.py``,
``tools/docker_compose_up.py``, ``tools/image_resolve.py``,
``tools/verify.py``, ``tools/run_in_container.py``,
``tools/github_fetch.py``). The integration moved the mechanism to
:mod:`core.container.proc` unchanged — same :class:`RunOutcome`
contract (``timed_out=True`` on wall-clock expiry; ``returncode is
None and not timed_out`` with a ``command_not_found:`` / ``os_error:``
stderr prefix when the subprocess never started), same D-state
abandon-the-reaper bound, same allowlisted default env.

This shim preserves the package-local import surface
(``from cve_env.utils.run import run_with_timeout, RunOutcome``).
"""

from __future__ import annotations


from core.container.proc import RunOutcome, run_cli
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

__all__ = ["RunOutcome", "run_with_timeout"]


def run_with_timeout(
    cmd: list[str],
    *,
    timeout: float,
    cwd: str | Path | None = None,
    env: dict[str, str] | None = None,
    keep_env: frozenset[str] = frozenset(),
) -> RunOutcome:
    """Run `cmd` with a wall-clock timeout. Never raises TimeoutExpired.

    See :func:`core.container.proc.run_cli` for the full contract. When
    ``env`` is None the allowlisted container-tooling env (with
    ``keep=keep_env`` opt-ins) is used; a caller-supplied ``env`` dict
    is used verbatim.
    """
    return run_cli(cmd, timeout=timeout, cwd=cwd, env=env, keep_env=keep_env)

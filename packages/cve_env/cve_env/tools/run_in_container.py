"""Run a command inside an already-launched container (planner layer).

Some CVEs are reproducible in containers but fail ``verify`` because
``verify`` only speaks HTTP: Redis (RESP), sudo Baron Samedit (local
setuid PoC), polkit PwnKit (in-container exploit run). The agent can do
those probes itself via this tool.

The exec mechanics — posture guarantees (no ``--privileged``, no
``-u`` override, no TTY, wall-clock bound, output caps) and the
ownership gate — live in :mod:`core.container.exec`; this module binds
the ``cve-env.owner=cve-env`` label and keeps the agent-tool result
shape.
"""

from __future__ import annotations

from typing import Any

from core.container.exec import (
    DEFAULT_TIMEOUT_SECONDS as _DEFAULT_TIMEOUT_SECONDS,
)
from core.container.exec import (
    ExecOutcome,
    container_has_label,
    exec_in_container,
)

_OWNER_LABEL = ("cve-env.owner", "cve-env")

# Result type re-export: the agent layer and tests type against
# run_in_container.ExecResult.
ExecResult = ExecOutcome


def _is_owned_container(container_id: str) -> bool:
    """Return True only if the container carries the
    ``cve-env.owner=cve-env`` label. Module-level so the test suite can
    keep patching the ownership gate here."""
    return container_has_label(container_id, *_OWNER_LABEL)


def run_in_container(
    *,
    container_id: str,
    command: str,
    timeout_seconds: float = _DEFAULT_TIMEOUT_SECONDS,
    workdir: str = "",
) -> ExecResult:
    """Execute ``command`` in ``container_id`` via ``docker exec``.

    Refuses containers that don't carry the ``cve-env.owner=cve-env``
    label — the agent can only exec into containers it launched via
    ``docker_run`` / ``docker_compose_up``.
    """
    if container_id and not _is_owned_container(container_id):
        return ExecResult(
            ok=False,
            container_id=container_id,
            command=command,
            reason="container is not owned by cve-env (missing label)",
        )
    return exec_in_container(
        container_id=container_id,
        command=command,
        timeout_seconds=timeout_seconds,
        workdir=workdir,
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

"""Container runtime substrate: docker-CLI invocation and failure taxonomy.

RAPTOR speaks to container runtimes through the ``docker`` CLI —
subprocess is portable, has no client-library deps, and behaves
identically on dockerd, Colima, and remote daemons. This package holds
the mechanical layer every consumer shares:

  * :mod:`core.container.proc` — the one subprocess boundary. A
    wall-clock-bounded runner that never raises on timeout/transport
    failure (``RunOutcome``), plus the allowlisted child environment
    (``get_safe_env`` + the docker CLI daemon vars).
  * :mod:`core.container.failures` — docker stderr → failure class
    (``disk_full`` / ``manifest_unknown`` / ``rate_limited`` / ...)
    with retry-eligibility. Purely textual; no I/O.

Consumers: ``packages/cve_env`` (the CVE environment builder keeps its
agent-facing hints and per-run pivot state and delegates the mechanics
here), and the ``core.env`` provisioning API.

Policy boundary: nothing in this package prints to the operator,
carries LLM-facing hint text, or holds cross-call state. Those belong
to the calling planner.
"""

from core.container.failures import (
    DockerFailureClass,
    classify_docker_stderr,
    is_retry_eligible,
)
from core.container.proc import (
    DOCKER_CHILD_ENV_VARS,
    RunOutcome,
    docker_child_env,
    run_cli,
)

__all__ = [
    "DOCKER_CHILD_ENV_VARS",
    "DockerFailureClass",
    "RunOutcome",
    "classify_docker_stderr",
    "docker_child_env",
    "is_retry_eligible",
    "run_cli",
]

"""Child-process env sanitisation — delegates to ``RaptorConfig.get_safe_env``.

Pre-integration this module carried its own ~90-entry denylist,
documented as "ported from raptor's get_safe_env pattern". The
integration replaces the copy with the original: core's
allowlist-primary :meth:`~core.config.RaptorConfig.get_safe_env` is the
single mechanism. The allowlist direction is strictly stronger — a
denylist keeps every unknown future secret (AWS_*, GH_TOKEN, the next
provider's key) unless someone remembers to add it; the allowlist drops
them by construction.

What stays here is only the cve-env-specific composition: the docker
CLI child vars the core allowlist deliberately omits (most RAPTOR
children must not see the docker-daemon configuration), and the
``keep`` opt-in for call sites that need one specific var back.

Proxy vars are dropped, matching both the old denylist and core's
default — docker children don't need them (the daemon does the pulls),
and git transport hygiene is handled at those call sites.
"""

from __future__ import annotations

import os

# Single source: the docker CLI daemon vars live with the container
# substrate. Alias retained for the package-local name.
from core.container.proc import DOCKER_CHILD_ENV_VARS as _DOCKER_CHILD_VARS


def safe_subprocess_env(*, keep: frozenset[str] = frozenset()) -> dict[str, str]:
    """Allowlisted env for a tool child process.

    ``core.config.RaptorConfig.get_safe_env()`` plus the docker CLI
    vars, plus any ``keep`` vars the call site opts back in (use
    sparingly and document why at each call site). Pass the result as
    ``env=`` to ``subprocess.run`` / ``Popen``.
    """
    from core.config import RaptorConfig

    env = dict(RaptorConfig.get_safe_env())
    for k in (*_DOCKER_CHILD_VARS, *keep):
        if k in os.environ:
            env[k] = os.environ[k]
    return env

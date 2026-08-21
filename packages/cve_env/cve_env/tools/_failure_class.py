"""Docker-stderr failure classifier — re-exported from ``core.container``.

The classifier (patterns, precedence table, retry-eligibility) moved to
:mod:`core.container.failures` unchanged so every RAPTOR consumer of
the docker CLI shares one taxonomy. This shim preserves the
package-local import surface (``from cve_env.tools._failure_class
import classify_docker_stderr``).
"""

from __future__ import annotations

from core.container.failures import (
    DockerFailureClass,
    classify_docker_stderr,
    is_retry_eligible,
)

__all__ = [
    "DockerFailureClass",
    "classify_docker_stderr",
    "is_retry_eligible",
]

"""Project platform matrix discovery — what (arch, libc) combinations
the project actually runs on.

Walks Dockerfile FROM lines, GitHub Actions ``runs-on:``, and
devcontainer JSON to enumerate every (architecture, libc family,
libc version) tuple a Python pin needs to install cleanly on.

The output feeds :mod:`packages.sca.wheel_compat` which then
cross-checks each candidate pin's PyPI wheel list against the
matrix to flag wheels that require a newer libc than the
project's base images supply.

Why this exists: the canonical bite was z3-solver==4.16.0.0
shipping ``manylinux_2_38_aarch64`` wheels — fine on the
``debian:bookworm`` devcontainer base (glibc 2.36) for x86_64
because a manylinux_2_17 fallback existed, but the aarch64
side had no fallback and silently failed for ARM-Mac
contributors. SCA had every input to flag this and didn't.
"""

from __future__ import annotations

from packages.sca.platform_matrix.matrix import (
    PlatformPair,
    ProjectPlatformMatrix,
    discover_platform_matrix,
)

__all__ = [
    "PlatformPair",
    "ProjectPlatformMatrix",
    "discover_platform_matrix",
]

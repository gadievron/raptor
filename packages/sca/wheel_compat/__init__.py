"""Cross-check a Python pin's PyPI wheel set against a project's
platform matrix and flag incompat (no installable wheel for an
arch the project actually runs on).

Two pieces:
  * :mod:`wheel_tags` — PEP 425 wheel-filename parser
  * :mod:`compat`     — WheelMatrix builder + cross-check engine

The bumper's evaluator consumes the public API here to flag
bumps that introduce new platform-compat regressions (and surface
existing-pin issues during scan)."""

from __future__ import annotations

from packages.sca.wheel_compat.compat import (
    CompatVerdict,
    WheelMatrix,
    check_compat,
    find_compatible_version,
    wheel_matrix_for_version,
)
from packages.sca.wheel_compat.wheel_tags import (
    WheelTag,
    parse_wheel_filename,
)

__all__ = [
    "CompatVerdict",
    "WheelMatrix",
    "WheelTag",
    "check_compat",
    "find_compatible_version",
    "parse_wheel_filename",
    "wheel_matrix_for_version",
]

"""Scan-time wheel-platform-compat hygiene check.

Mirrors the bumper-side ``platform_compat_regression`` detector
but operates on CURRENT pins (not proposed bumps). Emits a
``sca:hygiene:platform_compat`` finding when a project's
declared PyPI pin can't install on one of the project's
discovered (arch, libc) platforms.

The canonical bite: ``z3-solver==4.16.0.0`` pinned in
requirements-dev.txt; ships ``manylinux_2_38_aarch64`` wheels;
devcontainer base is ``debian:bookworm`` (glibc 2.36) — the
aarch64 side has no installable wheel. Before this check the
scanner was silent; after, a HIGH-severity hygiene finding fires
with the recommended earlier-version pin in the detail line.

Network: needs ``pypi_client``. Caller is responsible for the
offline-aware client construction (pipeline does this already
for the supply-chain stage). Without a client, the check
silently no-ops.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterable, List, Optional

from packages.sca.models import (
    Confidence, Dependency, HygieneFinding,
)
from packages.sca.platform_matrix import (
    ProjectPlatformMatrix, discover_platform_matrix,
)
from packages.sca.wheel_compat.compat import (
    check_compat, find_compatible_version, wheel_matrix_for_version,
)

logger = logging.getLogger(__name__)


_FINDING_TIER = {
    # Per-verdict severity. Higher tiers reflect "harder to recover
    # from at install time".
    "libc_too_new":   "high",      # canonical z3-solver case
    "uninstallable":  "high",      # no wheel + no sdist
    "arch_gap":       "medium",    # arch not supported at all
    "sdist_only":     "low",       # works but requires build env
}


def evaluate_platform_compat(
    deps: Iterable[Dependency],
    *,
    target: Path,
    pypi_client,
    platform_matrix: Optional[ProjectPlatformMatrix] = None,
) -> List[HygieneFinding]:
    """For each exact-pinned PyPI dep, cross-check against the
    project's platform matrix and emit a hygiene finding when
    a platform pair has no installable wheel.

    Skipped silently:
      * Non-PyPI ecosystems (no wheels concept)
      * Non-exact pins (the range may resolve to a compat version)
      * Deps without a version (unpinned manifest entries)
      * Pure-Python ``any`` wheels (no platform constraint)

    Empty platform matrix → no findings (we have nothing to
    compare against). Caller passing ``platform_matrix=None``
    triggers discovery via :func:`discover_platform_matrix`.
    """
    if pypi_client is None:
        return []

    if platform_matrix is None:
        platform_matrix = discover_platform_matrix(target)
    if not platform_matrix:
        return []

    findings: List[HygieneFinding] = []
    seen: set = set()       # dedup on (name, version)

    for dep in deps:
        if dep.ecosystem != "PyPI":
            continue
        if not dep.version:
            continue
        # Exact pins only — ranges aren't single-version queries.
        if hasattr(dep.pin_style, "value"):
            if dep.pin_style.value != "exact":
                continue
        key = (dep.name, dep.version)
        if key in seen:
            continue
        seen.add(key)

        try:
            wm = wheel_matrix_for_version(
                pypi_client, dep.name, dep.version,
            )
        except Exception as e:                              # noqa: BLE001
            logger.debug(
                "platform_compat scan: PyPI fetch failed for %s==%s: %s",
                dep.name, dep.version, e,
            )
            continue

        if wm is None:
            continue
        if not wm.wheel_tags and not wm.has_sdist:
            # No data; treat as "no signal" rather than crash.
            continue

        verdicts = check_compat(platform_matrix, wm)
        non_ok = [v for v in verdicts if v.verdict != "ok"]
        if not non_ok:
            continue

        # Recommendation: search older versions for one that fully
        # satisfies the matrix. Bounded walk to avoid 200-version
        # release histories.
        try:
            rec = find_compatible_version(
                pypi_client, dep.name, platform_matrix,
            )
        except Exception:                                   # noqa: BLE001
            rec = None

        # One finding per (dep, problematic-pair) — operators see
        # which platform is the issue.
        for v in non_ok:
            findings.append(_make_finding(dep, v, rec))

    return findings


def _make_finding(
    dep: Dependency, verdict, recommendation: Optional[str],
) -> HygieneFinding:
    sev = _FINDING_TIER.get(verdict.verdict, "low")
    rec_note = (
        f" Recommended: pin {dep.name}=={recommendation} (last "
        f"version with wheels compatible across the project "
        f"platform matrix)."
        if recommendation else
        " No earlier release on PyPI has wheels compatible across "
        "the project platform matrix; consider upgrading the "
        "base-image's libc, adding ``--platform=linux/amd64`` for "
        "emulation, or installing build tools in the image so "
        "sdist build works."
    )
    detail = f"{verdict.reason}.{rec_note}"
    return HygieneFinding(
        finding_id=(
            f"sca:hygiene:platform_compat:PyPI:{dep.name}:"
            f"{dep.version}:{verdict.pair.arch}"
        ),
        kind="platform_compat",
        dependency=dep,
        detail=detail,
        severity=sev,
        confidence=Confidence(
            "high",
            reason="wheel platform tags compared against project matrix",
        ),
    )

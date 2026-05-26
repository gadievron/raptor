"""GHA action freshness — flag deps multiple majors behind latest.

The curated sunset list (``gha_sunset``) catches versions that are
explicitly broken or compromised. This detector catches the long
tail: actions that aren't formally sunset yet but whose pinned
major is far enough behind the current release that the operator
is missing security fixes, performance work, and (eventually) the
next sunset window.

Mechanic:

  1. For each Dependency with ecosystem ``"GitHub Actions"``, look
     up ``<owner>/<repo>``'s latest stable release via
     :class:`GitHubActionsClient` (which caches per-repo).
  2. Extract the major-version integer from both the pinned
     version and the latest release's tag.
  3. Compute ``majors_behind = latest_major - pinned_major``.
  4. Emit a finding with severity scaled by the gap:
       * 1 major → ``info`` — typically intentional pinning
       * 2 majors → ``low``
       * 3 majors → ``medium``
       * 4+ majors → ``high``

What we skip (deliberately):

  * SHA pins — would need to resolve the SHA back to a tag for
    comparison. Too expensive (per-action tag-by-tag scan), no
    win for the typical case.
  * Branch pins (``main``, ``master``) — already flagged by
    ``gha_drift`` for the bigger supply-chain reason.
  * Pinned major == latest major — by definition not behind.
  * Tags that don't parse to ``v<int>...`` — calendar-versioned
    actions (``2024.05.01``), commit-hash tags, etc. Not enough
    operators use these for the heuristic to be worth tuning.
  * Sub-action references (``actions/cache/restore``) — looked up
    against the parent repo (``actions/cache``); the release tag
    typically governs the whole repository.

When the network call fails (404, rate limit, transient), the
freshness check silently doesn't fire for that action. We never
emit a finding without confirmed latest-version data.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, List, Optional, Tuple

from ..models import (
    Confidence,
    Dependency,
    Severity,
    SupplyChainFinding,
)

logger = logging.getLogger(__name__)


# Major-component extractor. Tags shape ``v1``, ``v1.2``, ``v1.2.3``,
# ``release-1.0``. We reject anything else (calver, suffix-lite,
# pre-releases) because the comparison would be ambiguous.
_MAJOR_RE = re.compile(r"^[A-Za-z\-]*v?(?P<major>\d+)(?:[.\-].*)?$")


# Severity ladder — index by majors_behind (1-based). Index 0
# unused; consumers always pass >=1.
_SEVERITY_LADDER: Tuple[Severity, ...] = (
    "info",      # placeholder, never used (majors_behind never 0 here)
    "info",      # 1 behind: maintainers often pin to a known major
    "low",       # 2 behind
    "medium",    # 3 behind
    "high",      # 4+ behind — clamped at this index
)


def scan_dependencies(
    deps: Iterable[Dependency],
    *,
    client,
) -> List[SupplyChainFinding]:
    """Walk Dependencies and emit one SupplyChainFinding per action
    pinned multiple majors behind its latest release.

    ``client`` is a :class:`GitHubActionsClient`; tests inject a stub.
    Production callers use the cached client constructed in the
    pipeline alongside the existing PyPI / npm clients.
    """
    if client is None:
        return []

    out: List[SupplyChainFinding] = []
    for dep in deps:
        if dep.ecosystem != "GitHub Actions":
            continue
        if not dep.version:
            continue
        pinned_major = _extract_major(dep.version)
        if pinned_major is None:
            continue                                # SHA, branch, calver
        latest_tag = client.get_latest_tag(dep.name)
        if latest_tag is None:
            continue
        latest_major = _extract_major(latest_tag)
        if latest_major is None:
            continue
        if latest_major <= pinned_major:
            continue                                # current or ahead

        gap = latest_major - pinned_major
        severity = _SEVERITY_LADDER[min(gap, len(_SEVERITY_LADDER) - 1)]
        out.append(_build_finding(
            dep=dep, pinned_major=pinned_major,
            latest_tag=latest_tag, latest_major=latest_major,
            gap=gap, severity=severity,
        ))
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------


def _extract_major(version: str) -> Optional[int]:
    """Pull the major-version integer out of a tag-shape string.

    Returns None for SHAs, branch names, calver tags, or anything
    else we can't classify as a clean ``v<int>...`` shape. Calver
    detection: a 4-digit "major" is a year, not a semver major —
    rejected so calver-pinned actions don't get nonsense
    "1 major behind" findings every January."""
    if not version:
        return None
    m = _MAJOR_RE.match(version.strip())
    if m is None:
        return None
    try:
        major = int(m.group("major"))
    except (TypeError, ValueError):
        return None
    # Calendar-year filter — semver majors above ~99 are
    # vanishingly rare (the highest-numbered popular package today
    # is ``hashicorp/terraform`` at v1.x, with rare projects in the
    # mid-double digits). A 4-digit major is almost always a calver
    # tag. Below 100 is treated as semver.
    if major >= 1000:
        return None
    return major


def _build_finding(
    *,
    dep: Dependency,
    pinned_major: int,
    latest_tag: str,
    latest_major: int,
    gap: int,
    severity: Severity,
) -> SupplyChainFinding:
    detail = (
        f"GHA action `{dep.name}@{dep.version}` is {gap} "
        f"major version{'s' if gap != 1 else ''} behind the latest "
        f"release `{latest_tag}` (major {latest_major}). "
        f"Upgrade for security fixes and to avoid the next "
        f"sunset window."
    )
    finding_id = (
        f"sca:supplychain:gha_action_outdated:"
        f"{dep.name}:{dep.version}".replace(" ", "_")
    )
    return SupplyChainFinding(
        finding_id=finding_id,
        kind="gha_action_outdated",
        dependency=dep,
        detail=detail,
        evidence={
            "action": dep.name,
            "pinned_version": dep.version,
            "pinned_major": pinned_major,
            "latest_tag": latest_tag,
            "latest_major": latest_major,
            "majors_behind": gap,
        },
        severity=severity,
        confidence=Confidence(
            "high",
            reason=(
                f"compared pinned major {pinned_major} against "
                f"latest release {latest_tag}"
            ),
        ),
    )


__all__ = ["scan_dependencies"]

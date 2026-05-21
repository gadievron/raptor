"""Detector for ``git_tag_drift``.

When a manifest pins a dep to a git source (``git+https://…@<ref>``,
``foo @ git+ssh://…@<ref>``, Poetry's ``{git=…, branch=…}``,
``{git=…, tag=…}``), the ``<ref>`` segment can be:

- a 40-char commit SHA — immutable; the bytes are pinned forever
- a tag — typically immutable on tag servers but the publisher can
  re-tag; ``git fetch`` will pick up the rewritten tag
- a branch / HEAD — wildly mutable; every install picks up whatever
  the head commit is at that moment

Branch refs are the strongest signal — they're the shape that lets a
malicious commit on ``main`` propagate the moment it's merged. Tag
refs are weaker (the tag would have to be re-pushed) but still
worth surfacing. SHAs are fine.

This detector is mechanical (no network — we don't ``git ls-remote``
or compare to a baseline). It's a *shape* check on the version field
of every dep with ``pin_style=GIT``.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, List

from ..models import Confidence, Dependency, PinStyle

logger = logging.getLogger(__name__)


_SHA_RE = re.compile(r"^[a-f0-9]{40}$")
# Tag-like: starts with `v` + digit, or pure semver, or a date-shaped tag.
_TAG_LIKE_RE = re.compile(
    r"^(?:v?\d+(?:\.\d+)*(?:[-+][\w.]+)?|release-?\d|\d{8})$"
)
# Go module pseudo-versions encode a commit SHA prefix — fully
# reproducible despite looking branch-shaped. Three canonical
# forms (Go ref: https://go.dev/ref/mod#pseudo-versions):
#
#   * ``v0.0.0-yyyymmddhhmmss-{12hex}``      (no semver tag exists)
#   * ``vX.Y.Z-0.yyyymmddhhmmss-{12hex}``    (release tag at base)
#   * ``vX.Y.Z-pre.0.yyyymmddhhmmss-{12hex}`` (pre-release tag at base)
#
# The trailing 12-char hex is the commit SHA prefix; go.sum carries
# the full hash for verification. Treating these as
# ``branch_or_other`` produced 406 spurious medium-severity findings
# on Helm-3.5 alone — every Go dep pinned via go.mod's standard
# untagged-commit shape.
_GO_PSEUDO_RE = re.compile(
    r"^v\d+\.\d+\.\d+"
    r"(?:-(?:pre\.)?0\.|-)"
    r"\d{14}-[0-9a-f]{12}$"
)


@dataclass(frozen=True)
class GitDriftFinding:
    dependency: Dependency
    detail: str
    severity: str
    confidence: Confidence
    ref: str
    ref_kind: str          # "tag" / "branch_or_other"


def scan_deps(deps: Iterable[Dependency]) -> List[GitDriftFinding]:
    """Walk deps; flag any git-pinned entry whose ref isn't a SHA."""
    out: List[GitDriftFinding] = []
    for dep in deps:
        if dep.pin_style is not PinStyle.GIT:
            continue
        ref = (dep.version or "").strip()
        if not ref:
            continue
        kind = _classify_ref(ref)
        if kind == "sha":
            continue
        severity = "medium" if kind == "branch_or_other" else "low"
        if kind == "branch_or_other":
            reason = (
                "git ref is a branch (or non-versionish identifier) — "
                "every install fetches whatever the head commit is at "
                "that moment"
            )
        else:
            reason = (
                "git ref is a tag — the upstream maintainer can move "
                "the tag to a different commit"
            )
        out.append(GitDriftFinding(
            dependency=dep,
            detail=(
                f"`{dep.ecosystem}:{dep.name}` is git-pinned to `{ref}` — "
                f"{reason}; pin to a 40-char commit SHA for "
                "supply-chain integrity"
            ),
            severity=severity,
            confidence=Confidence(
                "high",
                reason=f"git ref shape classified as {kind}",
            ),
            ref=ref,
            ref_kind=kind,
        ))
    return out


def _classify_ref(ref: str) -> str:
    if _SHA_RE.match(ref.lower()):
        return "sha"
    if _GO_PSEUDO_RE.match(ref):
        # Pseudo-versions are SHA-equivalent for drift purposes —
        # immutable, reproducible, verified by go.sum.
        return "sha"
    if _TAG_LIKE_RE.match(ref):
        return "tag"
    return "branch_or_other"


__all__ = ["GitDriftFinding", "scan_deps"]

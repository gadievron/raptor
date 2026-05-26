"""Detector for ``gha_action_ref_drift``.

GitHub Actions workflows reference third-party actions via
``uses: <owner>/<action>@<ref>`` lines. ``<ref>`` can be:

- a 40-char commit SHA (immutable; the action's bytes are pinned)
- a tag (mutable; the publisher can re-tag, ``v1`` and ``v1.2.3``
  alike)
- a branch (very mutable; new commits land continuously)

Tags and branches are *runtime-replaceable* by the action owner.
Real attacks have happened: an action gets compromised or a
maintainer's account is hijacked, the attacker re-publishes
``v3`` to point at malicious code, every workflow that
``uses: foo/action@v3`` runs the new code on next CI invocation.

GitHub's official guidance is to pin to a SHA. We flag any
non-SHA ref so the operator can decide whether the convenience
of a tag pin is worth the supply-chain risk.

Walks ``.github/workflows/*.yml`` and ``.github/workflows/*.yaml``.
Doesn't require PyYAML — the ``uses:`` lines have a regular shape
that's safe to grep.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List

from ..models import Confidence, Dependency, Manifest, PinStyle

logger = logging.getLogger(__name__)


# `uses:` line shape (after YAML key trimming):
#   uses: owner/repo@ref
#   uses: owner/repo/sub-action@ref
#   uses: ./local-action          (no @ref — local action, ignore)
#   uses: docker://image:tag      (Docker action — different threat model)
_USES_RE = re.compile(
    r"""
    ^\s*-?\s*uses\s*:\s*
    (?P<spec>[A-Za-z0-9_./-]+@[A-Za-z0-9_./-]+)
    \s*(?:\#.*)?$
    """,
    re.VERBOSE,
)

_SHA_RE = re.compile(r"^[a-f0-9]{40}$")


@dataclass(frozen=True)
class GhaDriftFinding:
    dependency: Dependency
    detail: str
    path: Path
    line: int
    severity: str
    confidence: Confidence
    action: str
    ref: str
    ref_kind: str          # "sha" / "tag" / "branch_or_other"


def scan_target(
    target: Path,
    manifests: Iterable[Manifest],
) -> List[GhaDriftFinding]:
    """Walk ``.github/workflows/`` and flag mutable refs."""
    target = target.resolve()
    workflows_dir = target / ".github" / "workflows"
    if not workflows_dir.exists():
        return []
    manifests_list = list(manifests)
    out: List[GhaDriftFinding] = []
    for path in sorted(workflows_dir.iterdir()):
        if not path.is_file():
            continue
        if path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            logger.debug(
                "sca.supply_chain.gha_drift: read failed for %s: %s",
                path, e,
            )
            continue
        for finding in _scan_text(text, path, target, manifests_list):
            out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _scan_text(
    text: str,
    path: Path,
    target: Path,
    manifests: List[Manifest],
) -> Iterable[GhaDriftFinding]:
    for line_no, line in enumerate(text.splitlines(), start=1):
        m = _USES_RE.match(line)
        if not m:
            continue
        spec = m.group("spec")
        # Docker / local-action specs go to a different uses: shape — we
        # already filtered those out by requiring `@` in the regex, but
        # docker://image:tag has `@` only on a digest pin.
        if spec.startswith(("./", "../", "docker://")):
            continue
        action, ref = spec.rsplit("@", 1)
        ref_kind = _classify_ref(ref)
        if ref_kind == "sha":
            continue
        severity = "medium" if ref_kind == "branch_or_other" else "low"
        reason = (
            "branch / non-tag ref — every CI run picks up whatever the "
            "head commit is at that moment"
            if ref_kind == "branch_or_other"
            else "tag ref — the action's owner can re-publish the same "
                 "tag pointing at different code"
        )
        yield GhaDriftFinding(
            dependency=_project_host_dep(manifests, path, target),
            detail=(
                f"`{_rel(path, target)}:{line_no}` uses `{action}@{ref}` — "
                f"{reason}; pin to a 40-char commit SHA for "
                "supply-chain integrity"
            ),
            path=path,
            line=line_no,
            severity=severity,
            confidence=Confidence(
                "high",
                reason=f"action ref is a {ref_kind}, not a commit SHA",
            ),
            action=action,
            ref=ref,
            ref_kind=ref_kind,
        )


def _classify_ref(ref: str) -> str:
    """Categorise a ``uses: owner/repo@<ref>`` ref."""
    if _SHA_RE.match(ref.lower()):
        return "sha"
    # Tags typically look like `v1`, `v1.2`, `v1.2.3`, `release-1.0`.
    # Branches like `main`, `master`, `dev`, `feature/x`. Both are
    # mutable; the distinction tunes severity.
    if re.match(r"^v?\d", ref) and "/" not in ref:
        return "tag"
    return "branch_or_other"


def _project_host_dep(
    manifests: List[Manifest], path: Path, target: Path,
) -> Dependency:
    """Anchor the finding to whichever manifest sits closest to the
    workflow file. For most projects this'll be the root pyproject /
    package.json / pom.xml — fine for the report's source column."""
    closest: "Manifest | None" = None
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            import os
            common = os.path.commonpath([m.path.parent, path])
        except ValueError:
            continue
        if not closest:
            closest = m
        else:
            import os
            existing_common = os.path.commonpath(
                [closest.path.parent, path]
            )
            if len(common) > len(existing_common):
                closest = m
    declared_in = closest.path if closest else target
    ecosystem = closest.ecosystem if closest else "Project"
    return Dependency(
        ecosystem=ecosystem,
        name="<github-actions>",
        version=None,
        declared_in=declared_in,
        scope="build",
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence(
            "low",
            reason="placeholder for gha-drift finding host",
        ),
    )


def _rel(path: Path, target: Path) -> Path:
    try:
        return path.relative_to(target)
    except ValueError:
        return path


__all__ = ["GhaDriftFinding", "scan_target"]

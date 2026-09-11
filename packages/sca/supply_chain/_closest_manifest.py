"""Shared closest-manifest placeholder-dependency builder.

Several tree-walking detectors (``artefacts``, ``exfil_destinations``,
``gha_drift``, ``python_imports``) attach their findings to a
synthesised placeholder ``Dependency`` anchored at whichever
non-lockfile manifest sits closest to the flagged file. The walk and
the placeholder shape are identical across them; only the
placeholder's name / scope / confidence reason differ. One
parameterised implementation here keeps the callers from drifting
apart.
"""

from __future__ import annotations

import os
from pathlib import Path
from collections.abc import Sequence

from ..models import Confidence, Dependency, Manifest, PinStyle


def closest_manifest(
    manifests: Sequence[Manifest], path: Path,
) -> Manifest | None:
    """Return the non-lockfile manifest whose parent directory shares
    the longest common path prefix with ``path`` (None when there is
    no usable manifest).

    The best common-prefix LENGTH is tracked across the loop rather
    than recomputing the incumbent's commonpath for every candidate —
    ``os.path.commonpath`` is not free and the old shape called it
    twice per manifest.
    """
    best: Manifest | None = None
    best_len = -1
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            common = os.path.commonpath([m.path.parent, path])
        except ValueError:
            continue
        if len(common) > best_len:
            best = m
            best_len = len(common)
    return best


def project_host_dep(
    manifests: Sequence[Manifest],
    path: Path,
    target: Path,
    *,
    reason: str,
    name: str = "<project>",
    scope: str = "main",
    ecosystem_fallback: str = "Project",
) -> Dependency:
    """Synthesise the placeholder host ``Dependency`` for a
    project-level finding at ``path``, anchored to the closest
    manifest (or ``target`` itself when no manifest dominates)."""
    closest = closest_manifest(manifests, path)
    declared_in = closest.path if closest else target
    ecosystem = closest.ecosystem if closest else ecosystem_fallback
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=None,
        declared_in=declared_in,
        scope=scope,
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl="",
        parser_confidence=Confidence("low", reason=reason),
    )


def rel_to_target(path: Path, target: Path) -> Path:
    """``path`` relative to ``target`` when possible, else ``path``."""
    try:
        return path.relative_to(target)
    except ValueError:
        return path


__all__ = ["closest_manifest", "project_host_dep", "rel_to_target"]

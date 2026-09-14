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

from pathlib import Path
from collections.abc import Sequence

from ..models import Confidence, Dependency, Manifest, PinStyle
from . import _own_host


def closest_manifest(
    manifests: Sequence[Manifest], path: Path,
) -> Manifest | None:
    """Return the deepest non-lockfile manifest whose directory
    DOMINATES ``path`` (is one of its ancestors); None when no
    manifest dominates.

    Dominance — not longest-common-prefix.  The prefix rule could
    select a manifest in a SIBLING directory
    (``/repo/a/b/c/d/package.json`` beat ``/repo/package.json`` for
    a file at ``/repo/a/b/c/f``), which both mis-anchored the
    finding and, worse, disagreed with the dominance rule
    ``binary_in_package`` uses — splitting the composite
    chokepoint's per-manifest keys so cross-family pairs
    (HOOK+BINARY / HOOK+EGRESS) never co-fired.  One resolver, one
    rule: every anchor consumer routes through here.
    """
    best: Manifest | None = None
    best_depth = -1
    try:
        resolved_path = path.resolve()
    except OSError:
        return None
    for m in manifests:
        if m.is_lockfile:
            continue
        try:
            m_dir = m.path.parent.resolve()
            resolved_path.relative_to(m_dir)
        except (OSError, ValueError):
            continue
        depth = len(m_dir.parts)
        if depth > best_depth:
            best = m
            best_depth = depth
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
    """Synthesise the host ``Dependency`` for a project-level finding
    at ``path``, anchored to the closest manifest (or ``target``
    itself when no manifest dominates).

    Anchored hosts carry the package's OWN name when the manifest
    declares one (via the shared :mod:`._own_host` resolver), so
    every tree-walking detector produces the same host key for the
    same manifest — the composite chokepoint's cross-family pairs
    depend on that.  ``name`` is the per-detector placeholder used
    when no own name resolves (must stay ``<``-prefixed)."""
    closest = closest_manifest(manifests, path)
    if closest is not None:
        return _own_host.resolve_own_host(
            closest,
            reason=reason,
            placeholder_name=name,
            scope=scope,
        )
    return Dependency(
        ecosystem=ecosystem_fallback,
        name=name,
        version=None,
        declared_in=target,
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

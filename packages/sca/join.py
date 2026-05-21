"""Join manifest + lockfile views of the same dependency tree.

Discovery + parsers emit one ``Dependency`` per declared row. For a
single library that appears in both a manifest *and* a lockfile,
those rows describe the same thing from two angles:

- The manifest carries the operator's intent (``pin_style``, scope,
  declared at this path).
- The lockfile carries the resolved truth (exact version, full
  transitive set).

Downstream layers (OSV matching, triage, SBOM) need a reconciled view.
This module performs the reconciliation in two passes:

1. **Direct-flag promotion** — a lockfile row whose ``(ecosystem, name)``
   also appears in a manifest *in an ancestor directory* is flipped to
   ``direct=True``. The asymmetric ancestor walk handles two layouts
   in one rule: deps declared in the same directory as the lockfile
   (most common) and monorepo lockfiles that aggregate leaf manifests
   (root lockfile, leaf manifests).

2. **Pin-style propagation** — when a lockfile row gains ``direct=True``,
   it inherits the manifest's ``pin_style`` so triage output can show
   what was *requested* alongside what was *resolved* (e.g., the
   operator wrote ``^1.2.0`` and got ``1.2.4``).

We do **not** collapse the row count: if you had ``django`` in both a
manifest and a lockfile, you still have two ``Dependency`` rows after
the join. Collapsing is left to the consumer (OSV layer dedups on
``(ecosystem, name, version)`` naturally; SBOM emitters want both).

We do **not** propagate scope — lockfiles often see the same dep through
multiple resolution paths, each with a different scope flag, and
reconciling those needs a transitive-graph walk we don't have yet. The
manifest scope is preserved on the manifest row; the lockfile row keeps
whatever its parser inferred.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Dict, Iterable, List, Set, Tuple

from .models import Confidence, Dependency

# Cap on ancestor walks. Real repos have tens of levels at most; a cap
# stops the join from doing unbounded work on adversarial paths.
_MAX_ANCESTOR_WALK = 64


def join(deps: Iterable[Dependency]) -> List[Dependency]:
    """Apply both passes — direct-flag promotion and pin-style propagation.

    Returns a new list; the input is not mutated.
    """
    deps_list = list(deps)
    manifest_index = _index_manifest_rows(deps_list)
    return [_resolve_one(d, manifest_index) for d in deps_list]


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

# Index entry: (ecosystem, manifest_dir, name) -> the matching manifest
# Dependency. We store the actual Dependency so we can copy attributes
# (pin_style, parser_confidence) onto the lockfile row.
_ManifestIndex = Dict[Tuple[str, Path, str], Dependency]


def _index_manifest_rows(deps: List[Dependency]) -> _ManifestIndex:
    """Build (ecosystem, manifest_dir, name) → manifest Dependency map.

    When the same (ecosystem, name) appears in multiple manifests in
    the same directory (rare — a project shouldn't declare a dep in
    both its package.json and pyproject.toml, but it's not illegal),
    the first row wins. The lockfile row only needs *some* manifest
    evidence to be considered direct.
    """
    index: _ManifestIndex = {}
    for d in deps:
        if d.is_lockfile:
            continue
        key = (d.ecosystem, d.declared_in.parent, d.name)
        index.setdefault(key, d)
    return index


def _resolve_one(
    dep: Dependency, manifest_index: _ManifestIndex,
) -> Dependency:
    """Return ``dep`` possibly with ``direct``/``pin_style`` updated."""
    if not dep.is_lockfile:
        return dep
    match = _find_manifest_match(dep, manifest_index)
    if match is None:
        return dep
    if dep.direct and dep.pin_style == match.pin_style:
        # Already reconciled (parser may have set direct=True, e.g. for
        # the root entry of a v3 package-lock.json). Don't churn confidence.
        return dep
    return replace(
        dep,
        direct=True,
        pin_style=match.pin_style,
        parser_confidence=_combine_confidence(dep.parser_confidence,
                                              match.parser_confidence),
    )


def _find_manifest_match(
    dep: Dependency, manifest_index: _ManifestIndex,
) -> Dependency | None:
    """Walk ancestors of ``dep.declared_in`` looking for a manifest row
    that shares this lockfile's ``(ecosystem, name)``.

    Walking *up* from the lockfile means a leaf-package lockfile sees
    leaf manifests, sibling root manifests, but not unrelated peer
    leaves — exactly the workspace boundary we want.
    """
    walked = 0
    cursor: Path = dep.declared_in.parent
    seen: Set[Path] = set()
    while walked < _MAX_ANCESTOR_WALK:
        if cursor in seen:
            break
        seen.add(cursor)
        candidate = manifest_index.get((dep.ecosystem, cursor, dep.name))
        if candidate is not None:
            return candidate
        parent = cursor.parent
        if parent == cursor:
            # Reached the filesystem root.
            break
        cursor = parent
        walked += 1
    return None


def _combine_confidence(
    lockfile_conf: Confidence, manifest_conf: Confidence,
) -> Confidence:
    """When join succeeds, the row has been corroborated from two sources.

    - If both sides are high → high, with a richer reason.
    - Otherwise take the lower of the two and explain why.
    """
    if lockfile_conf.level == "high" and manifest_conf.level == "high":
        return Confidence(
            "high",
            reason="manifest+lockfile agree on dep",
        )
    # Pick the weaker side's level — the pipeline should reflect the
    # most uncertain input.
    weaker = lockfile_conf if _level_rank(lockfile_conf.level) <= _level_rank(
        manifest_conf.level
    ) else manifest_conf
    return Confidence(
        weaker.level,
        reason=f"join: weaker side {weaker.reason}"[:200],
    )


def _level_rank(level: str) -> int:
    return {"low": 0, "medium": 1, "high": 2}.get(level, 0)


__all__ = ["join"]

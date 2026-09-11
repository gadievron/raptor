"""Corridor matching honours OSV's range/versions UNION semantics.

An OSV affected block matches when the version is inside any range OR
listed in the explicit ``versions`` array — the array is not a
redundant enumeration of the ranges (backport streams are often
enumerated only by version), so it must be evaluated even when ranges
were evaluable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from packages.osv import parse_record
from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.osv import _matches_corridor


def _corridor_dep(
    name: str, *, floor: str | None, ceiling: str | None,
) -> Dependency:
    return Dependency(
        ecosystem="npm",
        name=name,
        version=None,
        declared_in=Path("./package.json"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.RANGE,
        direct=True,
        purl=f"pkg:npm/{name}",
        parser_confidence=Confidence("high", reason="t"),
        version_floor=floor,
        version_ceiling=ceiling,
    )


# One range covering 1.0.0..1.5.0 plus an explicitly enumerated
# affected version (2.3.0) that no range covers.
_RECORD = parse_record({
    "id": "GHSA-UNION-1",
    "summary": "union semantics fixture",
    "details": "d",
    "affected": [{
        "package": {"ecosystem": "npm", "name": "leftpad"},
        "ranges": [{
            "type": "SEMVER",
            "events": [{"introduced": "1.0.0"}, {"fixed": "1.5.0"}],
        }],
        "versions": ["2.3.0"],
    }],
    "references": [],
})


def test_version_listed_only_in_versions_array_matches() -> None:
    """Corridor admits 2.3.0 — outside every range, but explicitly
    enumerated as affected. Union semantics: match."""
    dep = _corridor_dep("leftpad", floor="2.0.0", ceiling="2.5.0")
    assert _matches_corridor(_RECORD, dep)


def test_version_in_neither_surface_does_not_match() -> None:
    """Corridor 3.x reaches neither the range nor the enumerated
    version: no match."""
    dep = _corridor_dep("leftpad", floor="3.0.0", ceiling="3.5.0")
    assert not _matches_corridor(_RECORD, dep)


def test_range_matching_is_unchanged() -> None:
    """The range surface keeps working alongside the union fix."""
    dep = _corridor_dep("leftpad", floor="1.0.0", ceiling="1.2.0")
    assert _matches_corridor(_RECORD, dep)


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-v"]))

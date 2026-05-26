"""Tests for ``packages.sca.supply_chain.typosquat``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.typosquat import scan_deps


def _dep(name: str, ecosystem: str = "npm", direct: bool = True) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=Path("/x/manifest"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=direct,
        purl=f"pkg:{ecosystem.lower()}/{name}@1.0.0",
        parser_confidence=Confidence("high", reason="t"),
    )


def test_exact_match_is_not_a_typosquat() -> None:
    """The popular package itself must never be flagged."""
    findings = scan_deps([_dep("lodash")])
    assert findings == []


def test_distance_one_flagged_as_high() -> None:
    findings = scan_deps([_dep("loadash")])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "high"
    assert f.nearest_popular == "lodash"
    assert f.distance == 1


def test_transposition_caught_by_damerau_variant() -> None:
    findings = scan_deps([_dep("loadsh")])
    assert findings and findings[0].nearest_popular == "lodash"


def test_distance_two_flagged_as_medium() -> None:
    # `lodash` → `lodaash` (insert) → `lodaasch` (insert) = distance 2.
    findings = scan_deps([_dep("lodaasch")])
    assert findings and findings[0].severity == "medium"
    assert findings[0].distance == 2


def test_far_away_name_not_flagged() -> None:
    findings = scan_deps([_dep("xyzzy-fooblat")])
    assert findings == []


def test_transitive_deps_skipped() -> None:
    """Typosquat checks only run on direct deps — a transitive dep is
    chosen by the resolver and isn't an operator-typed name."""
    findings = scan_deps([_dep("loadash", direct=False)])
    assert findings == []


def test_pypi_list_is_separate() -> None:
    """The PyPI list shouldn't be loaded for npm, and vice versa."""
    findings = scan_deps([_dep("requestz", ecosystem="PyPI")])
    assert findings and findings[0].nearest_popular == "requests"


def test_unsupported_ecosystem_returns_no_findings() -> None:
    findings = scan_deps([_dep("g:a", ecosystem="Maven")])
    assert findings == []


def test_scoped_npm_package_compared_against_bare_form() -> None:
    """``@evil/lodash`` should still flag against ``lodash``."""
    findings = scan_deps([_dep("@evil/lodash")])
    assert findings and findings[0].nearest_popular == "lodash"

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


def test_single_char_name_not_falsely_matched_as_distance_zero() -> None:
    """Regression: ``_damerau_levenshtein`` previously initialised its
    ``prev`` row to all zeros and rotated at the START of the loop,
    discarding the canonical ``[0,1,2,…]`` base row. The DP then
    propagated a 0 to ``cur[j]`` whenever ``a[0] == b[j-1]``, so e.g.
    ``DL("a", "cma")`` returned 0 instead of 2. The detector
    interpreted that as a distance-0 bare-form match (scoped-name
    namespace squat) and flagged short legitimate names like the
    PyPI dep ``a`` as high-confidence typosquats — which the
    transitive cascade refused with ``skipped_typosquat_refused``."""
    findings = scan_deps([_dep("a", ecosystem="PyPI")])
    # ``a`` is not in the popular list and is genuinely distance-2
    # from short popular names (e.g. ``cma``). It should either not
    # be flagged or be flagged at low/medium severity — but never
    # high (distance 0 is reserved for the bare-form scoped-squat
    # case, which a non-scoped name can't satisfy).
    for f in findings:
        assert f.distance >= 1, (
            f"short name spuriously matched distance-0 to "
            f"{f.nearest_popular!r}"
        )
        assert f.confidence.level != "high" or f.distance == 0, (
            "high-confidence only legitimate for distance-0 bare-form "
            "match; this finding claims high without the matching shape"
        )


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

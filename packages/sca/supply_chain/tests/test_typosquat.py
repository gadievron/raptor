"""Tests for ``packages.sca.supply_chain.typosquat``."""

from __future__ import annotations

from pathlib import Path

from packages.sca.models import Confidence, Dependency, PinStyle
from packages.sca.supply_chain.typosquat import (
    _SYMDIFF_CUTOFF,
    _char_mask,
    _damerau_levenshtein,
    scan_deps,
)


def _dep(
    name: str,
    ecosystem: str = "npm",
    direct: bool = True,
    declared_in: str = "/x/manifest",
) -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version="1.0.0",
        declared_in=Path(declared_in),
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


def test_duplicate_dep_across_manifests_yields_per_manifest_findings() -> None:
    """The per-``(eco, name)`` memo computes the verdict once but must
    still emit one finding per declaring dep object — each keeps its
    own ``declared_in`` so the downstream finding id stays distinct."""
    deps = [
        _dep("loadash", declared_in="/repo/a/package.json"),
        _dep("loadash", declared_in="/repo/b/package.json"),
    ]
    findings = scan_deps(deps)
    assert len(findings) == 2
    declared = {str(f.dependency.declared_in) for f in findings}
    assert declared == {"/repo/a/package.json", "/repo/b/package.json"}
    # Verdict fields identical across the duplicates.
    assert {f.nearest_popular for f in findings} == {"lodash"}
    assert {f.distance for f in findings} == {1}


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
    transitive cascade refused with ``skipped_typosquat_refused``.

    The fix (commit 7612f138) was silently reverted by a stale-branch
    rebase in #690; this test guards against that recurring."""
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


def test_damerau_levenshtein_short_cases() -> None:
    """Pin the short-name distances the base-row bug got wrong."""
    assert _damerau_levenshtein("a", "cma", 99) == 2
    assert _damerau_levenshtein("a", "ba", 99) == 1
    assert _damerau_levenshtein("a", "aa", 99) == 1
    assert _damerau_levenshtein("kitten", "sitting", 99) == 3
    assert _damerau_levenshtein("lodash", "lodahs", 99) == 1  # transposition


def test_char_mask_prefilter_is_sound() -> None:
    """The bitmask prefilter must never skip a pair the DP would flag.

    ``distance >= popcount(set_a △ set_b) / 2`` is exact, so any pair
    whose symmetric set-difference exceeds ``_SYMDIFF_CUTOFF`` has true
    distance ``> _MAX_DISTANCE`` and is safe to skip. Fuzz it: every
    pair the prefilter would skip must genuinely be out of range."""
    import random
    import string

    rng = random.Random(20260528)
    alphabet = string.ascii_lowercase + string.digits + "-_.@"
    max_distance = _SYMDIFF_CUTOFF // 2
    checked = 0
    for _ in range(50_000):
        a = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
        b = "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 14)))
        if (_char_mask(a) ^ _char_mask(b)).bit_count() > _SYMDIFF_CUTOFF:
            checked += 1
            assert _damerau_levenshtein(a, b, 99) > max_distance, (
                f"prefilter would skip {a!r} vs {b!r} but their true "
                f"distance is within {max_distance}"
            )
    assert checked > 0, "fuzz generated no skippable pairs — vacuous test"


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

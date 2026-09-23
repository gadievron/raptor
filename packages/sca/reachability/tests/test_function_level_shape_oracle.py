"""Cross-tier advisory-entry shape oracle for the function-level tiers.

The tier universe is derived MECHANICALLY from the module set
(``packages/sca/reachability/*_function_level.py``): a new tier module
cannot ship without joining this oracle — the completeness test fails
until it gets a spec row. The build / refine entry points are located
by introspection, so the oracle exercises whatever the module actually
exports rather than a hand-maintained call list.

For every tier the oracle drives three scenarios through the REAL
producer chain (advisory → ``build_*_symbol_map`` →
``refine_*_verdicts`` with a hand-built inventory — hermetic, no
tree-sitter needed):

  * ``mixed_unbindable_exercised`` — a mixed advisory list where the
    entry the project actually exercises is the one the tier cannot
    bind (or historically mangled). The tier must either bind it
    correctly (upgrade) or abstain honestly — NEVER downgrade to a
    high-confidence ``not_function_reachable`` on the bindable
    remainder. Silent-drop-to-unreachable is the recurring
    false-suppression mechanism this oracle exists to pin shut.
  * ``all_bindable_uncalled`` — every entry bindable, none called:
    the downgrade MUST still fire (the honesty gate may not vacuously
    disable the tier's suppression arm).
  * ``bindable_called`` — a bindable entry the project calls:
    ``likely_called`` must come back (the tier binds correctly).
  * ``imports_path_unbindable_exercised`` — the exercised entry rides
    an ``imports[].path`` the tier cannot bind (hyphenated / slashed /
    coordinate spellings that fail the resolver's dotted-identifier
    grammar, or outright junk). Composing ``<path>.<symbol>`` anyway
    mints a well-formed garbage query that pairs NOT_CALLED and
    satisfies the coverage gate — the same false-suppression
    mechanism as the flat arms, one arm over. The tier must bind the
    entry through its own convention or route it to the counted
    marker and abstain — never downgrade.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

import pytest

import packages.sca.reachability as _reachability_pkg
from packages.sca.models import Confidence, Dependency, PinStyle, Reachability


# ---------------------------------------------------------------------------
# Mechanical tier enumeration
# ---------------------------------------------------------------------------


def _tier_module_names() -> list[str]:
    return sorted(
        name
        for _, name, _ in pkgutil.iter_modules(_reachability_pkg.__path__)
        if name.endswith("_function_level")
    )


def _tier_entry_points(module_name: str):
    """Locate the tier's ``build_*_symbol_map`` / ``refine_*_verdicts``
    pair by introspection, plus the refine function's symbol-map
    keyword name."""
    mod = importlib.import_module(
        f"packages.sca.reachability.{module_name}",
    )
    builds = [
        getattr(mod, n) for n in dir(mod)
        if n.startswith("build_") and n.endswith("_symbol_map")
    ]
    refines = [
        getattr(mod, n) for n in dir(mod)
        if n.startswith("refine_") and n.endswith("_verdicts")
    ]
    assert len(builds) == 1, f"{module_name}: expected one builder"
    assert len(refines) == 1, f"{module_name}: expected one refiner"
    map_kwargs = [
        p for p in inspect.signature(refines[0]).parameters
        if p.endswith("_symbol_map")
    ]
    assert len(map_kwargs) == 1, f"{module_name}: expected one map kwarg"
    return builds[0], refines[0], map_kwargs[0]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@dataclass
class _Adv:
    ecosystem_specific: Optional[Dict[str, Any]] = None
    database_specific: Optional[Dict[str, Any]] = None


@dataclass
class _OsvResult:
    dep_key: str
    advisories: List[_Adv] = field(default_factory=list)


def _dep(name: str, ecosystem: str, version: str = "1.0.0") -> Dependency:
    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=Path("manifest"),
        scope="main",
        is_lockfile=False,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl=f"pkg:generic/{name}@{version}",
        parser_confidence=Confidence("high", reason="t"),
    )


def _imported() -> Reachability:
    return Reachability(
        verdict="imported",
        confidence=Confidence("high", reason="prior tier"),
        evidence=[],
    )


def _inventory(
    imports: Dict[str, str], chains: List[List[str]],
) -> Dict[str, Any]:
    """A minimal inventory the cross-language resolver accepts —
    one non-test source file with an import map and call chains.
    Language-agnostic by design (the resolver only reads the
    ``call_graph`` dicts), so one shape serves every tier."""
    return {"files": [{
        "path": "src/app.code",
        "call_graph": {
            "imports": dict(imports),
            "calls": [
                {"chain": list(c), "line": i + 1}
                for i, c in enumerate(chains)
            ],
            "indirection": [],
        },
    }]}


@dataclass(frozen=True)
class _Scenario:
    ecosystem_specific: Optional[Dict[str, Any]]
    database_specific: Optional[Dict[str, Any]]
    imports: Dict[str, Any]
    chains: tuple
    expected: str


@dataclass(frozen=True)
class _TierSpec:
    ecosystem: str          # Dependency.ecosystem == dep_key prefix
    dep_name: str
    scenarios: Dict[str, _Scenario]


_SCENARIO_NAMES = (
    "mixed_unbindable_exercised",
    "all_bindable_uncalled",
    "bindable_called",
    "imports_path_unbindable_exercised",
)


# Per-tier fixture data. The KEYS of this table are pinned to the
# mechanical module enumeration by test_every_tier_has_a_spec — the
# values are necessarily hand-written (each ecosystem's advisory
# spelling and import-map conventions differ), but the UNIVERSE is
# derived, so a new tier can't silently sit outside the oracle.
_TIER_SPECS: Dict[str, _TierSpec] = {
    "npm_function_level": _TierSpec(
        ecosystem="npm",
        dep_name="lodash",
        scenarios={
            # The dotted entry (the one actually exercised) is out of
            # the tier's chain grammar and must block the downgrade.
            "mixed_unbindable_exercised": _Scenario(
                None, {"affected_functions": ["set", "Parser.parse"]},
                {"lodash": "lodash"}, (("lodash", "Parser", "parse"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                None, {"affected_functions": ["set"]},
                {"lodash": "lodash"}, (("lodash", "get"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                None, {"affected_functions": ["get"]},
                {"lodash": "lodash"}, (("lodash", "get"),),
                expected="likely_called",
            ),
            # npm's builder reads bare names only — the junk path is
            # discarded and the symbol binds through the dep-head
            # convention (pinned so the arm can't drift).
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "lo-dash/internals",
                              "symbols": ["get"]}]}, None,
                {"lodash": "lodash"}, (("lodash", "get"),),
                expected="likely_called",
            ),
        },
    ),
    "python_function_level": _TierSpec(
        ecosystem="PyPI",
        dep_name="pyyaml",     # dist != module: candidates → ["yaml"]
        scenarios={
            # A module-named entry ("yaml") admits no query spelling
            # (the verbatim dot-less query raises) — it must count
            # against the downgrade, not silently vanish.
            "mixed_unbindable_exercised": _Scenario(
                None, {"affected_functions": ["yaml", "helper"]},
                {"yaml": "yaml"}, (("yaml", "load"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                None, {"affected_functions": ["helper"]},
                {"yaml": "yaml"}, (("yaml", "load"),),
                expected="not_function_reachable",
            ),
            # Module-head-qualified spelling binds verbatim.
            "bindable_called": _Scenario(
                None, {"affected_functions": ["yaml.load"]},
                {"yaml": "yaml"}, (("yaml", "load"),),
                expected="likely_called",
            ),
            # The PyPI builder reads bare names only — the junk path
            # is discarded and the symbol binds through the candidate
            # modules (pinned so the arm can't drift).
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "py-yaml/junk",
                              "symbols": ["load"]}]}, None,
                {"yaml": "yaml"}, (("yaml", "load"),),
                expected="likely_called",
            ),
        },
    ),
    "go_function_level": _TierSpec(
        ecosystem="Go",
        dep_name="example.com/lib",
        scenarios={
            # A flat entry already carrying the module-path head used
            # to be double-prefixed into an unbindable garbage query;
            # it must bind verbatim. The package-TAIL flat spelling
            # (``lib.Parse``) has its own dedicated pin below —
            # test_go_flat_pkg_tail_spelling_binds.
            "mixed_unbindable_exercised": _Scenario(
                {"affected_functions": ["example.com/lib.Parse",
                                        "Absent"]}, None,
                {"lib": "example.com/lib"}, (("lib", "Parse"),),
                expected="likely_called",
            ),
            "all_bindable_uncalled": _Scenario(
                {"imports": [{"path": "example.com/lib",
                              "symbols": ["Absent"]}]}, None,
                {"lib": "example.com/lib"}, (("lib", "Parse"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"imports": [{"path": "example.com/lib",
                              "symbols": ["Parse"]}]}, None,
                {"lib": "example.com/lib"}, (("lib", "Parse"),),
                expected="likely_called",
            ),
            # A junk (non-string) path admits no honest composition:
            # dep-qualifying its symbols is a GUESS whose wrong
            # readings pair NOT_CALLED — the entry must be counted
            # unresolved so the tier abstains.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": 123, "symbols": ["Parse"]}]},
                None,
                {"sub": "example.com/lib/sub"}, (("sub", "Parse"),),
                expected="imported",
            ),
        },
    ),
    "java_function_level": _TierSpec(
        ecosystem="Maven",
        dep_name="com.example:foo",
        scenarios={
            # Flat entries can't be qualified from a Maven coordinate;
            # they must block the downgrade the path-qualified
            # remainder would otherwise mint.
            "mixed_unbindable_exercised": _Scenario(
                {"imports": [{"path": "com.example.foo",
                              "symbols": ["Other.absent"]}]},
                {"affected_functions": ["Mapper.readValue"]},
                {"Mapper": "com.example.foo.Mapper"},
                (("Mapper", "readValue"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                {"imports": [{"path": "com.example.foo",
                              "symbols": ["Other.absent"]}]}, None,
                {"Mapper": "com.example.foo.Mapper"},
                (("Mapper", "readValue"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"imports": [{"path": "com.example.foo",
                              "symbols": ["Mapper.readValue"]}]}, None,
                {"Mapper": "com.example.foo.Mapper"},
                (("Mapper", "readValue"),),
                expected="likely_called",
            ),
            # A Maven COORDINATE in the path slot is not a Java
            # package — composing it mints a colon-headed garbage
            # query; the entry must be counted unresolved instead.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "com.example:foo",
                              "symbols": ["Mapper.readValue"]}]}, None,
                {"Mapper": "com.example.foo.Mapper"},
                (("Mapper", "readValue"),),
                expected="imported",
            ),
        },
    ),
    "cargo_function_level": _TierSpec(
        ecosystem="Cargo",
        dep_name="my-crate",   # hyphen: not a namespace head shape
        scenarios={
            # The bare entry has no bindable spelling under a
            # hyphenated crate name; it must block the downgrade.
            "mixed_unbindable_exercised": _Scenario(
                {"affected_symbols": ["my_crate::parser::absent",
                                      "insert_many"]}, None,
                {"parser": "my_crate.parser"}, (("parser", "spawn"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                {"affected_symbols": ["my_crate::parser::absent"]},
                None,
                {"parser": "my_crate.parser"}, (("parser", "parse"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"affected_symbols": ["my_crate::parser::parse"]},
                None,
                {"parser": "my_crate.parser"}, (("parser", "parse"),),
                expected="likely_called",
            ),
            # A hyphenated CRATE-NAME spelling in the path slot fails
            # the resolver grammar — composing it mints a garbage
            # query on a function the project genuinely calls (as
            # ``serde_json.from_str``); the entry must be counted
            # unresolved so the tier abstains.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "my-crate",
                              "symbols": ["from_str"]}]}, None,
                {"my_crate": "my_crate"}, (("my_crate", "from_str"),),
                expected="imported",
            ),
        },
    ),
    "rubygems_function_level": _TierSpec(
        ecosystem="RubyGems",
        dep_name="actionpack",
        scenarios={
            # Gem names never head code namespaces: the bare entry is
            # unbindable and must block the downgrade.
            "mixed_unbindable_exercised": _Scenario(
                {"imports": [{"path": "ActionDispatch::Routing",
                              "symbols": ["Mapper#absent"]}]},
                {"affected_functions": ["helper"]},
                {"Mapper": "ActionDispatch.Routing.Mapper"},
                (("Mapper", "draw"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                {"imports": [{"path": "ActionDispatch::Routing",
                              "symbols": ["Mapper#absent"]}]}, None,
                {"Mapper": "ActionDispatch.Routing.Mapper"},
                (("Mapper", "draw"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"imports": [{"path": "ActionDispatch::Routing",
                              "symbols": ["Mapper#draw"]}]}, None,
                {"Mapper": "ActionDispatch.Routing.Mapper"},
                (("Mapper", "draw"),),
                expected="likely_called",
            ),
            # A hyphenated gem-name spelling in the path slot fails
            # the resolver grammar after ``::``→``.`` normalisation —
            # counted unresolved, never composed.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "action-dispatch::Routing",
                              "symbols": ["Mapper#draw"]}]}, None,
                {"Mapper": "ActionDispatch.Routing.Mapper"},
                (("Mapper", "draw"),),
                expected="imported",
            ),
        },
    ),
    "nuget_function_level": _TierSpec(
        ecosystem="NuGet",
        dep_name="My-Pkg",     # hyphen: not a namespace head shape
        scenarios={
            "mixed_unbindable_exercised": _Scenario(
                {"imports": [{"path": "MyPkg",
                              "symbols": ["Widget.Absent"]}]},
                {"affected_symbols": ["Setup"]},
                {"Widget": "MyPkg.Widget"}, (("Widget", "Run"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                {"imports": [{"path": "MyPkg",
                              "symbols": ["Widget.Absent"]}]}, None,
                {"Widget": "MyPkg.Widget"}, (("Widget", "Run"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"imports": [{"path": "MyPkg",
                              "symbols": ["Widget.Run"]}]}, None,
                {"Widget": "MyPkg.Widget"}, (("Widget", "Run"),),
                expected="likely_called",
            ),
            # A hyphenated PACKAGE-ID spelling in the path slot fails
            # the resolver grammar — counted unresolved, never
            # composed into a garbage query.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [{"path": "My-Pkg",
                              "symbols": ["Widget.Run"]}]}, None,
                {"Widget": "MyPkg.Widget"}, (("Widget", "Run"),),
                expected="imported",
            ),
        },
    ),
    "packagist_function_level": _TierSpec(
        ecosystem="Packagist",
        dep_name="symfony/http-foundation",
        scenarios={
            # vendor/pkg names never head code namespaces: the bare
            # entry is unbindable and must block the downgrade.
            "mixed_unbindable_exercised": _Scenario(
                {"imports": [
                    {"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request::absent"]}]},
                {"affected_symbols": ["sanitize"]},
                {"Request": "Symfony.Component.HttpFoundation.Request"},
                (("Request", "create"),),
                expected="imported",
            ),
            "all_bindable_uncalled": _Scenario(
                {"imports": [
                    {"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request::absent"]}]}, None,
                {"Request": "Symfony.Component.HttpFoundation.Request"},
                (("Request", "create"),),
                expected="not_function_reachable",
            ),
            "bindable_called": _Scenario(
                {"imports": [
                    {"path": "Symfony\\Component\\HttpFoundation",
                     "symbols": ["Request::create"]}]}, None,
                {"Request": "Symfony.Component.HttpFoundation.Request"},
                (("Request", "create"),),
                expected="likely_called",
            ),
            # A vendor/pkg PACKAGE-NAME spelling in the path slot
            # (slash survives normalisation) fails the resolver
            # grammar — counted unresolved, never composed.
            "imports_path_unbindable_exercised": _Scenario(
                {"imports": [
                    {"path": "symfony/http-foundation",
                     "symbols": ["Request::create"]}]}, None,
                {"Request": "Symfony.Component.HttpFoundation.Request"},
                (("Request", "create"),),
                expected="imported",
            ),
        },
    ),
}


# ---------------------------------------------------------------------------
# Completeness — the spec table is pinned to the derived universe
# ---------------------------------------------------------------------------


def test_every_tier_module_has_a_spec():
    """The oracle's universe is the MODULE SET, not this table: a new
    ``*_function_level`` module fails here until it declares its
    advisory-shape fixtures (and a removed tier's stale row fails the
    other direction)."""
    assert set(_TIER_SPECS) == set(_tier_module_names())


def test_every_spec_covers_every_scenario():
    for name, spec in _TIER_SPECS.items():
        assert set(spec.scenarios) == set(_SCENARIO_NAMES), name


# ---------------------------------------------------------------------------
# The oracle
# ---------------------------------------------------------------------------


def _run_tier(module_name: str, scenario: _Scenario) -> str:
    spec = _TIER_SPECS[module_name]
    build, refine, map_kwarg = _tier_entry_points(module_name)
    dep = _dep(spec.dep_name, spec.ecosystem)
    adv = _Adv(
        ecosystem_specific=scenario.ecosystem_specific,
        database_specific=scenario.database_specific,
    )
    symbol_map = build([_OsvResult(dep_key=dep.key(), advisories=[adv])])
    assert dep.key() in symbol_map, (
        f"{module_name}: builder produced no entry for the scenario "
        f"advisory — the shape fell out of the producer entirely"
    )
    out: Dict[str, Reachability] = {dep.key(): _imported()}
    refine(
        [dep], out,
        target=Path("/nonexistent-target"),
        inventory=_inventory(scenario.imports, list(scenario.chains)),
        **{map_kwarg: symbol_map},
    )
    return out[dep.key()].verdict


@pytest.mark.parametrize("scenario_name", _SCENARIO_NAMES)
@pytest.mark.parametrize("module_name", sorted(_TIER_SPECS))
def test_shape_oracle(module_name: str, scenario_name: str):
    scenario = _TIER_SPECS[module_name].scenarios[scenario_name]
    verdict = _run_tier(module_name, scenario)
    if scenario_name == "mixed_unbindable_exercised":
        # The universal invariant first (the silent-drop-to-false-
        # suppression mechanism): a list containing an entry the tier
        # could not evaluate must never mint the high-confidence
        # suppression.
        assert verdict != "not_function_reachable", (
            f"{module_name}: downgraded on a mixed advisory list "
            f"whose exercised entry was silently discarded"
        )
    assert verdict == scenario.expected, (
        f"{module_name} / {scenario_name}: expected "
        f"{scenario.expected!r}, got {verdict!r}"
    )


def test_go_flat_pkg_tail_spelling_binds():
    """A flat Go advisory entry spelled with the package TAIL
    (``lib.Parse`` under module ``example.com/lib`` — the source-level
    spelling human-written advisory function lists use, since Go call
    sites read ``lib.Parse``) used to be blindly prefixed into
    ``example.com/lib.lib.Parse``: a well-formed garbage query the
    resolver answers NOT_CALLED, vacuously satisfying the coverage
    gate and minting the high-confidence suppression on a function
    the project genuinely calls. The entry must rebind onto the
    module path and hit the real call."""
    tail_only = _Scenario(
        {"affected_functions": ["lib.Parse"]}, None,
        {"lib": "example.com/lib"}, (("lib", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", tail_only) == "likely_called"

    # Mixed with an uncalled fully-qualified entry: the tail-spelled
    # exercised entry must still win the upgrade — never downgrade.
    mixed = _Scenario(
        {"affected_functions": ["lib.Parse", "example.com/lib.Absent"]},
        None,
        {"lib": "example.com/lib"}, (("lib", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", mixed) == "likely_called"

    # The blindly-prefixed twin stays counted and queried alongside
    # the rebind: a type genuinely named after its own package
    # (call chain ``lib.lib.Parse``) still binds.
    type_named_after_pkg = _Scenario(
        {"affected_functions": ["lib.Parse"]}, None,
        {"lib": "example.com/lib"}, (("lib", "lib", "Parse"),),
        expected="likely_called",
    )
    assert (
        _run_tier("go_function_level", type_named_after_pkg)
        == "likely_called"
    )

    # Counter-direction: the rebind must not vacuously disable the
    # suppression arm — an uncalled tail-spelled entry still
    # downgrades.
    tail_uncalled = _Scenario(
        {"affected_functions": ["lib.Absent"]}, None,
        {"lib": "example.com/lib"}, (("lib", "Parse"),),
        expected="not_function_reachable",
    )
    assert (
        _run_tier("go_function_level", tail_uncalled)
        == "not_function_reachable"
    )


def test_go_flat_subpackage_tail_spelling_binds():
    """A flat Go advisory entry spelled with a SUBPACKAGE tail
    (``sub.Parse`` under module ``example.com/lib`` where the project
    imports ``example.com/lib/sub`` — the realistic shape is
    ``ssh.ParsePublicKey`` under ``golang.org/x/crypto``) composed
    only the dot-joined reading ``example.com/lib.sub.Parse``: a
    well-formed garbage query pairing NOT_CALLED, minting the
    high-confidence suppression on a genuinely-called function. The
    slash-joined subpackage twin (``example.com/lib/sub.Parse``) must
    be counted and queried alongside, so whichever reading the
    advisory meant, the honest query is present."""
    subpkg_tail = _Scenario(
        {"affected_functions": ["sub.Parse"]}, None,
        {"sub": "example.com/lib/sub"}, (("sub", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", subpkg_tail) == "likely_called"

    # Mixed with an uncalled fully-qualified entry: still never a
    # downgrade when the subpackage-tail entry is the exercised one.
    mixed = _Scenario(
        {"affected_functions": ["sub.Parse", "example.com/lib.Absent"]},
        None,
        {"sub": "example.com/lib/sub"}, (("sub", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", mixed) == "likely_called"

    # A flat entry already spelled with the full slash-qualified
    # sub-package path (the canonical OSV symbol shape appearing in a
    # flat list) binds verbatim instead of being blindly prefixed.
    slash_qualified = _Scenario(
        {"affected_functions": ["example.com/lib/sub.Parse"]}, None,
        {"sub": "example.com/lib/sub"}, (("sub", "Parse"),),
        expected="likely_called",
    )
    assert (
        _run_tier("go_function_level", slash_qualified) == "likely_called"
    )

    # Counter-direction: a genuinely-uncalled subpackage-tail entry
    # still downgrades — every twin paired NOT_CALLED.
    subpkg_uncalled = _Scenario(
        {"affected_functions": ["sub.Absent"]}, None,
        {"sub": "example.com/lib/sub"}, (("sub", "Parse"),),
        expected="not_function_reachable",
    )
    assert (
        _run_tier("go_function_level", subpkg_uncalled)
        == "not_function_reachable"
    )


def test_go_flat_nested_subpackage_tail_binds():
    """A flat Go advisory entry naming a NESTED sub-package by its
    tail (``b.Parse`` meaning ``example.com/lib/a/b.Parse``) has no
    statically-composable honest spelling — but a project can only
    CALL such a function by IMPORTING its package, so the refine pass
    derives twins from the project's own imports of the advisory's
    module: every imported path under the module whose tail (or
    relative dotted path) matches the entry's head yields a
    ``<import_path>.<rest>`` query. Whatever spelling a called
    function is given, the import-derived twin exists and binds —
    the composed reading can never pair vacuously alone."""
    for entry in ("b.Parse", "a.b.Parse", "example.com/lib.a.b.Parse"):
        nested = _Scenario(
            {"affected_functions": [entry]}, None,
            {"b": "example.com/lib/a/b"}, (("b", "Parse"),),
            expected="likely_called",
        )
        assert _run_tier("go_function_level", nested) == "likely_called", entry

    # Mixed with an uncalled fully-qualified entry alongside.
    mixed = _Scenario(
        {"affected_functions": ["b.Parse", "example.com/lib.Absent"]},
        None,
        {"b": "example.com/lib/a/b"}, (("b", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", mixed) == "likely_called"

    # Two same-tail imports: twins derive for BOTH; either binding
    # blocks the downgrade.
    two_imports = _Scenario(
        {"affected_functions": ["b.Parse"]}, None,
        {"ab": "example.com/lib/a/b", "cb": "example.com/lib/c/b"},
        (("cb", "Parse"),),
        expected="likely_called",
    )
    assert _run_tier("go_function_level", two_imports) == "likely_called"

    # Counter-direction: an uncalled entry whose nested package is
    # NOT imported derives no twin — the composed readings pair
    # NOT_CALLED and the downgrade still fires.
    uncalled_unimported = _Scenario(
        {"affected_functions": ["b.Absent"]}, None,
        {"lib": "example.com/lib"}, (("lib", "Parse"),),
        expected="not_function_reachable",
    )
    assert (
        _run_tier("go_function_level", uncalled_unimported)
        == "not_function_reachable"
    )

    # Counter-direction: imported nested package, function genuinely
    # uncalled — the import-derived twin itself pairs NOT_CALLED and
    # the downgrade still fires.
    uncalled_imported = _Scenario(
        {"affected_functions": ["b.Absent"]}, None,
        {"b": "example.com/lib/a/b"}, (("b", "Parse"),),
        expected="not_function_reachable",
    )
    assert (
        _run_tier("go_function_level", uncalled_imported)
        == "not_function_reachable"
    )

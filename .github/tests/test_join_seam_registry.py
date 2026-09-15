"""Registry of shared join-key seams — constructor usage on both sides.

Producer/consumer joins keep dying the same way: one side mints keys
with a hand-rolled spelling, the other side looks up a shape or
vocabulary nothing produces, and the lane goes silently inert. Each
converted seam is registered here with its constructor's home module,
the producer/consumer files that must reference the constructor, and
the exact phantom idiom whose reappearance would re-open the seam.

The checks are mechanical text/AST proofs over the real tree — a seam
cannot silently drop its constructor on either side, and the replaced
idiom cannot quietly come back, without failing this test. New shared
join-key constructors must be registered here.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Seam:
    name: str
    #: module defining the constructor(s), repo-relative
    home: str
    #: constructor function names that must be defined in ``home``
    constructors: tuple[str, ...]
    #: repo-relative file → constructor names it must reference
    sides: dict[str, tuple[str, ...]] = field(default_factory=dict)
    #: repo-relative file → exact substrings that must be ABSENT
    #: (the phantom idiom the constructor replaced)
    forbidden: dict[str, tuple[str, ...]] = field(default_factory=dict)


SEAMS: tuple[Seam, ...] = (
    Seam(
        name="checklist files/items walk",
        home="core/inventory/__init__.py",
        constructors=("iter_checklist_items",),
        sides={
            "core/analysis/typestate.py": ("iter_checklist_items",),
            "core/audit/orchestrator.py": ("iter_checklist_items",),
        },
        forbidden={
            # The flat top-level read no producer ever fed.
            "core/analysis/typestate.py": ('checklist.get("items"',),
        },
    ),
    Seam(
        name="per-function taint result keys",
        home="core/analysis/taint_approx.py",
        constructors=("function_key", "bare_function_name"),
        sides={
            # Producer mints keys through the constructor…
            "core/audit/loaders.py": ("function_key",),
            # …and the transitive walk resolves hops through the
            # bare-name projection of the same vocabulary.
            "core/analysis/taint_approx.py": ("bare_function_name",),
        },
        forbidden={
            "core/audit/loaders.py": ('f"{rel}:{func_name}"',),
        },
    ),
    Seam(
        name="vuln_type → primitive-graph start node",
        home="packages/exploit_feasibility/primitives.py",
        constructors=("vuln_node_for",),
        sides={
            "packages/exploit_feasibility/api.py": ("vuln_node_for",),
        },
        forbidden={
            # Blind suffixing minted nodes the graph never modeled.
            "packages/exploit_feasibility/api.py": (
                "normalized += '_vuln'",
                'normalized += "_vuln"',
            ),
        },
    ),
    Seam(
        name="rule-library entry identity / graduated stem",
        home="packages/checker_synthesis/library.py",
        constructors=("rule_join_key", "graduated_stem"),
        sides={
            "packages/checker_synthesis/replay_sweep.py": (
                "rule_join_key", "graduated_stem",
            ),
            "packages/llm_analysis/checker_followup.py": (
                "rule_join_key",
            ),
        },
        forbidden={
            # First-entry-wins rule_id resolution in the sweep joins.
            "packages/checker_synthesis/replay_sweep.py": (
                "e.rule_id == rule_id",
            ),
        },
    ),
    Seam(
        name="raw registry document → renderer contract",
        home="packages/sca/llm/registry_view.py",
        constructors=("build_registry_view", "iter_maintainers"),
        sides={
            "packages/sca/pipeline.py": ("build_registry_view",),
            "packages/sca/llm/maintainer_trust.py": ("iter_maintainers",),
            "packages/sca/llm/slopsquat_verdict.py": ("iter_maintainers",),
        },
        forbidden={
            # Raw documents handed straight to the renderers.
            "packages/sca/pipeline.py": (
                "pypi.get_metadata(dep.name) or {}",
                "npm.get_metadata(dep.name) or {}",
            ),
        },
    ),
)


def _defined_functions(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {
        node.name
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }


def test_registry_is_nonempty_and_paths_exist():
    assert SEAMS
    for seam in SEAMS:
        assert (REPO / seam.home).is_file(), seam.home
        for rel in (*seam.sides, *seam.forbidden):
            assert (REPO / rel).is_file(), rel


def test_constructors_are_defined_in_their_home():
    for seam in SEAMS:
        defined = _defined_functions(REPO / seam.home)
        for ctor in seam.constructors:
            assert ctor in defined, (
                f"{seam.name}: constructor {ctor} missing from {seam.home}"
            )


def test_both_sides_reference_the_constructor():
    for seam in SEAMS:
        for rel, ctors in seam.sides.items():
            src = (REPO / rel).read_text(encoding="utf-8")
            for ctor in ctors:
                assert ctor in src, (
                    f"{seam.name}: {rel} no longer references {ctor} — "
                    "one side of the seam dropped the shared key "
                    "constructor"
                )


def test_replaced_phantom_idioms_stay_dead():
    for seam in SEAMS:
        for rel, idioms in seam.forbidden.items():
            src = (REPO / rel).read_text(encoding="utf-8")
            for idiom in idioms:
                assert idiom not in src, (
                    f"{seam.name}: the phantom join idiom {idiom!r} "
                    f"reappeared in {rel}"
                )

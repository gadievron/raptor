"""Registry of shared join-key seams — constructor usage on both sides.

Producer/consumer joins keep dying the same way: one side mints keys
with a hand-rolled spelling, the other side looks up a shape or
vocabulary nothing produces, and the lane goes silently inert. Each
converted seam is registered here with its constructor's home module,
the producer/consumer files that must reference the constructor, and
the exact phantom idiom whose reappearance would re-open the seam.

The checks are mechanical text/AST proofs over the real tree — a seam
cannot silently drop its constructor CALL on either side, and the
replaced idiom cannot quietly come back, without failing this test.
Side binding is call-shaped (an AST ``Call`` whose callee names the
constructor), not textual: a dead ``import rule_join_key`` satisfied
the earlier substring check while the registered side minted keys by
hand — the exact regression class the tripwire exists for. New shared
join-key constructors must be registered here.

Canonical constructors: for the ``file:function`` seams registered
here, ``core.analysis.taint_approx.function_key`` is THE constructor
(plain ``f"{rel}:{func}"``). ``core.coverage.journal.make_function_key``
is a SEPARATE constructor for the coverage vocabulary with different
injectivity (``%``-encoded ``:``-bearing paths); the two byte-agree on
ordinary checklist paths but are deliberately NOT unified here —
consumers joining across the coverage↔audit boundary must pick one
side's constructor knowingly. Unifying them is recorded as an open
residual, not attempted by this registry.
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
            # The evidence index joins on the same vocabulary (its
            # index keys, Joern reachability joins, context-map sink
            # attach)…
            "core/evidence/__init__.py": ("function_key",),
            # …as do the audit bridge's attack-path constraint and
            # summary joins (bare-name fallback keys included:
            # function_key("", func)).
            "core/orchestration/audit_bridge.py": ("function_key",),
            # The SCC fixed-point propagator joins caller/callee
            # summaries on the same vocabulary.
            "core/analysis/summaries.py": ("function_key",),
        },
        forbidden={
            "core/audit/loaders.py": ('f"{rel}:{func_name}"',),
            # The hand-built spellings the conversion replaced — the
            # seam contract was violated by these exact idioms while
            # the substring tripwire read the constructor's IMPORT as
            # compliance.
            "core/evidence/__init__.py": (
                'f"{file_path}:{func_name}"',
                'f"{t.file}:{t.function}"',
                'f"{s.file}:{s.function}"',
                'f"{sink_file}:{sink_func}"',
            ),
            "core/analysis/summaries.py": (
                "f\"{edge.get('caller_file', '')}:{edge.get('caller', '')}\"",
                'f"{callee_file}:{edge.get(\'callee\', \'\')}"',
            ),
            "core/orchestration/audit_bridge.py": (
                'f"{file_path}:{func}"',
                'f":{func}"',
            ),
        },
    ),
    Seam(
        name="understand-graph function node keys",
        home="core/understand_graph/schema.py",
        constructors=("function_ref",),
        sides={
            # Every function-key mint in the ingest layer builds the
            # ref through the constructor. The binary-verdict CONSUMER
            # (queries.propagate_binary_verdicts) receives pre-joined
            # keys minted by core/inventory/builder.py — converting
            # that side belongs to the pending constructor
            # unification, recorded there, not silently here.
            "core/understand_graph/ingest.py": ("function_ref",),
        },
        forbidden={
            # The hand-rolled spellings the constructor replaced.
            "core/understand_graph/ingest.py": (
                'f"{path}::{name}"',
                'f"{file_path}::{fn_name}"',
                'f"{step_file}::{step_fn}"',
                'f"{ann.file}::{ann.function}"',
            ),
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
            # The raw-id join the constructor replaced on the followup
            # side (the drop-the-call-keep-the-import mutation
            # reintroduced exactly this).
            "packages/llm_analysis/checker_followup.py": (
                "record_match(entry.rule_id",
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


def _called_names(path: Path) -> set[str]:
    """Names invoked as calls: ``ctor(...)`` and ``mod.ctor(...)``.

    A bare import or a mention in a comment/string is NOT a call —
    binding the side check to call sites is what makes the
    drop-the-call-keep-the-import mutation fail. A side that ever
    needs to pass a registered constructor as a VALUE (map/key=
    callbacks) must re-register with that usage recorded; today every
    registered side calls directly."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Name):
                called.add(fn.id)
            elif isinstance(fn, ast.Attribute):
                called.add(fn.attr)
    return called


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


def test_both_sides_call_the_constructor():
    """Call-site presence, not text presence: a dead
    ``from ... import rule_join_key`` satisfied a substring check
    while the registered side minted keys by hand — the constructor
    must appear as an actual call on every side."""
    for seam in SEAMS:
        for rel, ctors in seam.sides.items():
            called = _called_names(REPO / rel)
            for ctor in ctors:
                assert ctor in called, (
                    f"{seam.name}: {rel} no longer CALLS {ctor} — one "
                    "side of the seam dropped the shared key "
                    "constructor call (an import alone is not a join)"
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

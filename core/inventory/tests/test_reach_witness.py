"""Tests for the proof-carrying reachability witness layer."""

from __future__ import annotations

from core.inventory.reach_witness import (
    STRUCTURALLY_SUPPRESSIBLE_KINDS,
    Reachability,
    Soundness,
    WitnessKind,
    resolve_reachability,
    verdict_from_classification,
)

# The corpus-earned set the enforcement consumer would pass once a labelled
# corpus shows zero false-suppress for these kinds.
_EARNED = STRUCTURALLY_SUPPRESSIBLE_KINDS


def test_may_suppress_is_safe_by_default_for_everything():
    # The chokepoint must never authorise suppression without an explicit
    # corpus-earned set — a static "sound" label is necessary, not
    # sufficient (the detectors are heuristic; a detector bug must not be
    # able to license a false negative).
    for v in ("module_aborts", "lexical_dead", "build_excluded",
              "no_path_from_entry", "not_called", "called",
              "framework_callable", "registered_via_call", "reachable",
              "uncertain"):
        assert verdict_from_classification(v).may_suppress() is False, v


def test_structural_dead_witnesses_suppress_only_when_earned():
    for v in ("module_aborts", "lexical_dead"):
        rv = verdict_from_classification(v)
        assert rv.status is Reachability.UNREACHABLE
        assert rv.witness.soundness is Soundness.SOUND
        assert rv.may_suppress() is False             # no earned set
        assert rv.may_suppress(_EARNED) is True        # corpus-earned


def test_heuristic_dead_witnesses_never_suppress_even_when_earned():
    # Unreachable, but evidence not proof — 1-hop / entry-completeness
    # assumptions can miss reflection, cross-file, or address-of edges.
    # Even if an over-eager consumer puts them in the earned set, soundness
    # gates them out.
    for v in ("no_path_from_entry", "not_called", "build_excluded"):
        rv = verdict_from_classification(v)
        assert rv.status is Reachability.UNREACHABLE
        assert rv.witness.soundness is Soundness.HEURISTIC
        over_eager = frozenset({rv.witness.kind})
        assert rv.may_suppress(over_eager) is False


def test_reachable_verdicts_never_suppress():
    for v in ("called", "framework_callable", "registered_via_call",
              "reachable"):
        rv = verdict_from_classification(v)
        assert rv.status is Reachability.REACHABLE
        assert rv.may_suppress(frozenset({rv.witness.kind})) is False


def test_uncertain_never_suppresses():
    rv = verdict_from_classification("uncertain")
    assert rv.status is Reachability.UNCERTAIN
    assert rv.may_suppress(frozenset({WitnessKind.UNCERTAIN})) is False


def test_unknown_verdict_fails_safe_to_uncertain():
    rv = verdict_from_classification("something_new")
    assert rv.status is Reachability.UNCERTAIN
    assert rv.may_suppress(_EARNED) is False


def test_to_priority_reason_preserves_legacy_strings():
    # The witness must regenerate the exact reachability:<kind> strings the
    # prepass / prompt consumers already key on — no forced migration.
    assert verdict_from_classification(
        "module_aborts").witness.to_priority_reason() == (
        "reachability:module_aborts")
    assert verdict_from_classification(
        "lexical_dead").witness.to_priority_reason() == (
        "reachability:lexical_dead")
    assert verdict_from_classification(
        "no_path_from_entry").witness.to_priority_reason() == (
        "reachability:no_path_from_entry")


def test_only_two_kinds_can_ever_be_suppress_eligible():
    # Lock the FN-safety surface: even with EVERY kind in the earned set,
    # exactly the two structural config-independent witnesses can suppress —
    # nothing else, in any combination.
    all_kinds = frozenset(WitnessKind)
    suppressible = {
        v for v in (
            "module_aborts", "lexical_dead", "no_path_from_entry",
            "not_called", "called", "framework_callable",
            "registered_via_call", "reachable", "uncertain",
        )
        if verdict_from_classification(v).may_suppress(all_kinds)
    }
    assert suppressible == {"module_aborts", "lexical_dead"}
    assert STRUCTURALLY_SUPPRESSIBLE_KINDS == {
        WitnessKind.MODULE_ABORTS, WitnessKind.LEXICAL_DEAD,
    }


def test_verdict_map_covers_every_classifier_output():
    # Drift guard: every string classify_reachability can emit must be
    # explicitly mapped (not silently routed to the uncertain fail-safe).
    # If classify_reachability gains a verdict, this fails until it's mapped.
    from core.inventory.reach_audit import _DEAD_VERDICTS, _LIVE_VERDICTS
    from core.inventory.reach_witness import VERDICTS
    emitted = set(_DEAD_VERDICTS) | set(_LIVE_VERDICTS) | {"uncertain"}
    unmapped = emitted - set(VERDICTS)
    assert not unmapped, f"classifier verdicts missing from VERDICTS: {unmapped}"


def test_resolve_reachability_end_to_end():
    # Synthetic inventory: a function below a top-level abort → MODULE_ABORTS
    # witness, suppress-eligible.
    inv = {"files": [{
        "path": "d.py", "language": "python",
        "items": [{"name": "vuln", "kind": "function", "line_start": 3,
                   "metadata": {}}],
        "call_graph": {"imports": {}, "calls": [],
                       "module_aborts_on_load": None},
        "module_aborts_on_load": {"line": 1, "summary": "raise ImportError"},
    }]}
    rv = resolve_reachability(inv, "d.py", "vuln", 3, "d")
    assert rv.witness.kind is WitnessKind.MODULE_ABORTS
    assert rv.may_suppress() is False              # not earned by default
    assert rv.may_suppress(_EARNED) is True        # corpus-earned


def test_structurally_suppressible_derived_from_table():
    # The suppressible set is DERIVED from VERDICTS[*].earns_suppression, not
    # hand-maintained. Pin the expected membership so a stray earns_suppression
    # flip is caught.
    from core.inventory.reach_witness import (
        STRUCTURALLY_SUPPRESSIBLE_KINDS, WitnessKind,
    )
    assert STRUCTURALLY_SUPPRESSIBLE_KINDS == frozenset({
        WitnessKind.MODULE_ABORTS, WitnessKind.LEXICAL_DEAD,
    })


def test_verdicts_blocker_detail_consistency():
    # A {detail} slot in a blocker template requires a detail source, and a
    # declared detail source requires a {detail} slot — else the demoter
    # silently drops/misformats the witness summary.
    from core.inventory.reach_witness import VERDICTS
    for v, spec in VERDICTS.items():
        if "{detail}" in spec.blocker_template:
            assert spec.blocker_detail in ("module_aborts", "build_excluded"), v
        if spec.blocker_detail:
            assert "{detail}" in spec.blocker_template, v


def test_blocker_for_and_prompt_verdict_for_round_trip():
    from core.inventory.reach_witness import blocker_for, prompt_verdict_for
    # blocker fills fq + detail; non-dead verdicts have no blocker.
    b = blocker_for("module_aborts", "`m.f`", "raise ImportError")
    assert b and "`m.f`" in b and "raise ImportError" in b
    assert blocker_for("reachable", "`m.f`") is None
    # prompt verdict present for structural dead verdicts, empty for the rest.
    assert prompt_verdict_for("build_excluded").startswith("Verdict: BUILD_EXCLUDED")
    assert prompt_verdict_for("not_called") == ""
    assert prompt_verdict_for("framework_callable") == ""

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
    for v in ("module_aborts", "lexical_dead", "binary_oracle_absent",
              "build_excluded", "no_path_from_entry", "not_called",
              "called", "framework_callable", "registered_via_call",
              "reachable", "uncertain"):
        assert verdict_from_classification(v).may_suppress() is False, v


def test_binary_oracle_absent_witness_resolves_end_to_end():
    """End-to-end: a function with ``metadata.binary_oracle.classification
    == 'absent'`` AND a non-empty ``binaries`` list (every entry
    full-tier) resolves to a SOUND, suppress-eligible witness via
    ``resolve_reachability``. Phase 2 wire: binary_oracle data on the
    inventory → reachability witness → /validate demoter picks up via
    ``may_suppress``."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{"name": "dead_helper", "kind": "function",
                   "line_start": 10,
                   "metadata": {"binary_oracle": {
                       "classification": "absent",
                       "build_id": "a1b2c3d4",
                       "binary_path": "/path/to/binary",
                       "address": None,
                       "binaries": [{
                           "path": "/path/to/binary",
                           "tier": "full",
                       }],
                   }}}],
    }]}
    rv = resolve_reachability(inv, "lib.c", "dead_helper", 10, "lib")
    assert rv.status is Reachability.UNREACHABLE
    assert rv.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT
    assert rv.witness.soundness is Soundness.SOUND
    # Suppression behavior: not earned by default (empty set) — earned
    # when the consumer passes STRUCTURALLY_SUPPRESSIBLE_KINDS.
    assert rv.may_suppress() is False
    assert rv.may_suppress(_EARNED) is True


def test_binary_oracle_absent_refuses_when_no_tier_evidence():
    """Adversarial review P0-C-4: a legacy / partial inventory whose
    ``binary_oracle`` block is missing ``binaries`` (or has an empty
    list, or has any non-full-tier entry) MUST NOT earn suppression.
    The SOUND witness is conditional on full-DWARF evidence; without
    it the function falls through to the rest of the precedence
    chain rather than silently suppressing a real finding."""
    base_item = {"name": "f", "kind": "function", "line_start": 1}

    # (a) ``binaries`` key absent — legacy single-binary writer.
    inv_a = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{**base_item, "metadata": {"binary_oracle": {
            "classification": "absent", "binary_path": "/b"}}}],
    }]}
    rv = resolve_reachability(inv_a, "lib.c", "f", 1, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT

    # (b) Empty ``binaries`` list — writer attached the key but found
    # no contributors. No tier evidence ⇒ no trust.
    inv_b = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{**base_item, "metadata": {"binary_oracle": {
            "classification": "absent", "binaries": []}}}],
    }]}
    rv = resolve_reachability(inv_b, "lib.c", "f", 1, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT

    # (c) Mixed tier — one full + one symbol_only. The symbol_only
    # could be hiding inlined-into-caller; refuse to fire.
    inv_c = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{**base_item, "metadata": {"binary_oracle": {
            "classification": "absent",
            "binaries": [{"tier": "full"}, {"tier": "symbol_only"}],
        }}}],
    }]}
    rv = resolve_reachability(inv_c, "lib.c", "f", 1, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT


def test_binary_oracle_absent_line_disambiguates_name_collisions():
    """Adversarial review P0-C-3: when two items in one file share a
    name (C static helpers, #if/#else, C++ overloads extracted as
    separate items), the accessor MUST consult ``line`` to identify
    the intended function. Querying for the live one's line MUST NOT
    return the dead one's verdict."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [
            # The dead namesake — would suppress if line wasn't checked.
            {"name": "helper", "kind": "function", "line_start": 10,
             "metadata": {"binary_oracle": {
                 "classification": "absent",
                 "binaries": [{"tier": "full"}]}}},
            # The live namesake — different line, no binary_oracle.
            {"name": "helper", "kind": "function", "line_start": 42},
        ],
    }]}
    # Query for the LIVE function (line=42) — must not be dropped by
    # the dead namesake's verdict.
    rv = resolve_reachability(inv, "lib.c", "helper", 42, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT
    # Sanity: the dead namesake (line=10) IS suppressible.
    rv_dead = resolve_reachability(inv, "lib.c", "helper", 10, "lib")
    assert rv_dead.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT


def test_binary_oracle_absent_fires_on_interior_finding_line():
    """Production scanners (semgrep, codeql) emit findings at the
    line WHERE THE ISSUE IS, not at the function's first line.
    The accessor must accept any line inside the function's range —
    the strict ``line == line_start`` check the closed-loop test
    surfaced was silently refusing to suppress every interior-line
    finding on a dead function."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{
            "name": "dead_helper", "kind": "function",
            "line_start": 140, "line_end": 180,
            "metadata": {"binary_oracle": {
                "classification": "absent",
                "binaries": [{"tier": "full"}]}},
        }],
    }]}
    # Finding emitted at line 154 (inside the function body).
    rv = resolve_reachability(inv, "lib.c", "dead_helper", 154, "lib")
    assert rv.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT
    # Single-candidate path with no line_end set works too — the
    # function-containing-line heuristic accepts any line >= line_start.
    inv["files"][0]["items"][0]["line_end"] = None
    rv = resolve_reachability(inv, "lib.c", "dead_helper", 154, "lib")
    assert rv.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT


def test_binary_oracle_absent_picks_innermost_enclosing_on_collision():
    """When two same-name items both enclose the query line (line_end
    missing on both), pick the one whose line_start is the LATEST
    <= query line — the standard ``function containing this line''
    heuristic."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [
            # Outer (e.g. a top-level dead function)
            {"name": "helper", "kind": "function", "line_start": 10,
             "metadata": {"binary_oracle": {
                 "classification": "absent",
                 "binaries": [{"tier": "full"}]}}},
            # Inner (e.g. a live namesake later in the file)
            {"name": "helper", "kind": "function", "line_start": 100},
        ],
    }]}
    # Query inside the second (live) helper — must NOT pick the dead one.
    rv = resolve_reachability(inv, "lib.c", "helper", 150, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT
    # Query inside the first (dead) helper — must pick that one.
    rv = resolve_reachability(inv, "lib.c", "helper", 20, "lib")
    assert rv.witness.kind is WitnessKind.BINARY_ORACLE_ABSENT


def test_binary_oracle_inlined_does_not_demote_function():
    """An ``inlined`` classification is REACHABLE evidence (function ran,
    just merged into its caller). The accessor must NOT return absent for
    it — finding falls through to the rest of the precedence chain."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{"name": "small_helper", "kind": "function",
                   "line_start": 5,
                   "metadata": {"binary_oracle": {
                       "classification": "inlined",
                       "build_id": "a1b2c3d4",
                       "binary_path": "/path/to/binary",
                       "address": None,
                       "binaries": [{"tier": "full"}],
                   }}}],
        "call_graph": {"imports": {}, "calls": []},
    }]}
    rv = resolve_reachability(inv, "lib.c", "small_helper", 5, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT


def test_no_binary_oracle_metadata_is_silent_fallthrough():
    """If ``--binary`` wasn't passed, items don't carry binary_oracle
    metadata. The stage must NOT fire (don't claim deadness based on
    missing evidence)."""
    inv = {"files": [{
        "path": "lib.c", "language": "c",
        "items": [{"name": "f", "kind": "function", "line_start": 1}],
        "call_graph": {"imports": {}, "calls": []},
    }]}
    rv = resolve_reachability(inv, "lib.c", "f", 1, "lib")
    assert rv.witness.kind is not WitnessKind.BINARY_ORACLE_ABSENT


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


def test_only_earned_sound_kinds_can_ever_be_suppress_eligible():
    # Lock the FN-safety surface: even with EVERY kind in the earned set,
    # only the SOUND + earns_suppression witnesses can suppress — nothing
    # else, in any combination. Set grew when binary_oracle_absent landed
    # (Inc 3d earned suppression via the precision corpus).
    all_kinds = frozenset(WitnessKind)
    suppressible = {
        v for v in (
            "module_aborts", "lexical_dead", "binary_oracle_absent",
            "build_excluded", "no_path_from_entry",
            "not_called", "called", "framework_callable",
            "registered_via_call", "reachable", "uncertain",
        )
        if verdict_from_classification(v).may_suppress(all_kinds)
    }
    assert suppressible == {
        "module_aborts", "lexical_dead", "binary_oracle_absent",
    }
    assert STRUCTURALLY_SUPPRESSIBLE_KINDS == {
        WitnessKind.MODULE_ABORTS,
        WitnessKind.LEXICAL_DEAD,
        WitnessKind.BINARY_ORACLE_ABSENT,
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
    # The suppressible set is DERIVED from VERDICTS[*].earns_suppression,
    # not hand-maintained. Pin the expected membership so a stray
    # earns_suppression flip is caught. Grew when binary_oracle_absent
    # earned the right via the Inc 3 precision corpus.
    from core.inventory.reach_witness import (
        STRUCTURALLY_SUPPRESSIBLE_KINDS, WitnessKind,
    )
    assert STRUCTURALLY_SUPPRESSIBLE_KINDS == frozenset({
        WitnessKind.MODULE_ABORTS,
        WitnessKind.LEXICAL_DEAD,
        WitnessKind.BINARY_ORACLE_ABSENT,
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

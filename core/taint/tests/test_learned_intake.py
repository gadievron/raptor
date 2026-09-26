"""Learned-channel intake bounds: closed vocabulary, per-role caps
with tier-ordered truncation, tag-only sanitizers, additive-only
propagators, and hostile-name refusal — each rule pinned so removing
its enforcing line turns a test red."""

from __future__ import annotations

import pytest

from core.evidence import EvidenceTier
from core.iris.specs import TaintSpec
from core.taint.learned_intake import (
    DEMOTED_SANITIZER_KILL,
    MAX_CLASSES_PER_SPEC,
    MAX_LEARNED_SANITIZERS,
    MAX_LEARNED_SINKS,
    MAX_LEARNED_SOURCES,
    REFUSED_CLASS_OUTSIDE_VOCABULARY,
    REFUSED_INVALID_FUNCTION_NAME,
    REFUSED_NO_TAINT_CLASSES,
    REFUSED_PROPAGATOR_NARROWING,
    REFUSED_TOO_MANY_CLASSES,
    REFUSED_UNKNOWN_ROLE,
    LearnedSpec,
    intake_learned_specs,
)
from core.taint.packs import FlowEdge

VOCAB = frozenset({"user-input", "sql-injection", "command-injection"})


def spec(role: str = "sink", function: str = "app.db.run_query",
         classes: tuple[str, ...] = ("sql-injection",), **extra) -> dict:
    base = {
        "role": role,
        "function": function,
        "file": "app/db.py",
        "taint_classes": list(classes),
        "params_affected": [0],
        "return_tainted": True,
        "confidence": 0.8,
        "evidence_tier": "xref_backed",
        "source": "",
    }
    base.update(extra)
    return base


# ── admission ────────────────────────────────────────────────────────


def test_admits_all_roles():
    result = intake_learned_specs(
        [
            spec("source", classes=("user-input",)),
            spec("sink"),
            spec("sanitiser"),
            spec("propagator", classes=()),
        ],
        vocabulary=VOCAB,
    )
    assert result.admitted == 4
    assert len(result.sources) == len(result.sinks) == 1
    assert len(result.sanitizers) == len(result.propagators) == 1
    assert result.refusals == () and result.caps_hit == ()
    assert result.to_dict()["admitted"]["sinks"] == 1


def test_accepts_real_taint_spec_objects():
    """Real synthesis output uses the prompt's SHORT labels ("sql",
    "cmd", "path", …) — the intake must join them, not just the
    dashed spellings a hand-written test might guess."""
    real = TaintSpec(
        function="app.views.lookup", file="app/views.py", role="sink",
        taint_classes=["sql"], params_affected=[0],
        confidence=0.7, evidence_tier=EvidenceTier.XREF_BACKED,
    )
    result = intake_learned_specs([real], vocabulary=VOCAB)
    (admitted,) = result.sinks
    # short store label aliased into the pack vocabulary
    assert admitted.taint_classes == ("sql-injection",)
    assert admitted.tier == "learned"
    assert admitted.evidence_tier == "xref_backed"


def test_real_synthesis_spellings_join_the_seed_vocabulary():
    """End-to-end join proof: every synthesis short label whose class
    the seed packs declare must be admitted against the REAL loaded
    vocabulary; labels for classes no pack declares refuse counted."""
    from core.taint.packs import default_pack_names, load_packs

    vocab = load_packs(default_pack_names("python")).taint_class_vocabulary()
    joining = {
        "sql": "sql-injection",
        "cmd": "command-injection",
        "command": "command-injection",
        "path": "path-traversal",
        "xss": "xss",
        "ssti": "template-injection",
        "template": "template-injection",
        "eval": "code-injection",
        "code": "code-injection",
        "redirect": "url-redirection",
    }
    specs = [spec(function=f"app.mod.f_{label}", classes=(label,))
             for label in joining]
    result = intake_learned_specs(specs, vocabulary=vocab)
    admitted = {s.function.rsplit("_", 1)[1]: s.taint_classes[0]
                for s in result.sinks}
    assert admitted == joining
    # labels with no pack-expressible class stay counted refusals
    unroutable = intake_learned_specs(
        [spec(classes=("deserialize",)), spec(classes=("ldap",))],
        vocabulary=vocab,
    )
    assert unroutable.sinks == ()
    assert unroutable.refusal_count(REFUSED_CLASS_OUTSIDE_VOCABULARY) == 2


def test_sanitizer_role_spelling_variants():
    result = intake_learned_specs(
        [spec("sanitiser"), spec("sanitizer")], vocabulary=VOCAB,
    )
    assert len(result.sanitizers) == 2


# ── closed taint-class vocabulary ────────────────────────────────────


def test_unknown_class_dropped_with_counted_refusal():
    result = intake_learned_specs(
        [spec(classes=("minted-class",))], vocabulary=VOCAB,
    )
    assert result.sinks == ()
    assert result.refusal_count(REFUSED_CLASS_OUTSIDE_VOCABULARY) == 1


def test_unknown_class_cannot_ride_beside_a_valid_one():
    result = intake_learned_specs(
        [spec(classes=("sql-injection", "minted-class"))], vocabulary=VOCAB,
    )
    assert result.sinks == ()
    assert result.refusal_count(REFUSED_CLASS_OUTSIDE_VOCABULARY) == 1


def test_class_normalization_is_spelling_not_semantics():
    result = intake_learned_specs(
        [spec(classes=("SQL_Injection",))], vocabulary=VOCAB,
    )
    assert result.sinks and result.sinks[0].taint_classes == ("sql-injection",)


def test_classless_source_sink_sanitizer_refused():
    result = intake_learned_specs(
        [spec("source", classes=()), spec("sink", classes=()),
         spec("sanitiser", classes=())],
        vocabulary=VOCAB,
    )
    assert result.admitted == 0
    assert result.refusal_count(REFUSED_NO_TAINT_CLASSES) == 3


def test_class_overflow_drops_whole_spec():
    """No truncate-then-admit: a spam-shaped class list refuses whole
    (slicing would let a flooded row smuggle its head through)."""
    over = spec(classes=tuple(f"c{i}" for i in range(MAX_CLASSES_PER_SPEC + 1)))
    result = intake_learned_specs([over], vocabulary=VOCAB)
    assert result.admitted == 0
    assert result.refusal_count(REFUSED_TOO_MANY_CLASSES) == 1
    at_cap = spec(classes=("sql-injection",) * MAX_CLASSES_PER_SPEC)
    assert intake_learned_specs([at_cap], vocabulary=VOCAB).admitted == 1


def test_propagator_needs_no_classes():
    result = intake_learned_specs(
        [spec("propagator", classes=())], vocabulary=VOCAB,
    )
    assert len(result.propagators) == 1


# ── caps + tier-ordered truncation ───────────────────────────────────


def test_per_role_caps_bind_with_markers():
    specs = [spec(function=f"app.mod.f{i}") for i in range(MAX_LEARNED_SINKS + 25)]
    result = intake_learned_specs(specs, vocabulary=VOCAB)
    assert len(result.sinks) == MAX_LEARNED_SINKS
    assert "learned_sinks" in result.caps_hit
    assert result.refusal_count("capped_sinks") == 25


def test_truncation_is_tier_ordered_human_first():
    specs = [
        spec(function=f"app.mod.f{i}", confidence=0.9)
        for i in range(MAX_LEARNED_SOURCES)
    ]
    for s in specs:
        s["role"] = "source"
        s["taint_classes"] = ["user-input"]
    promoted = spec(
        "source", function="app.mod.operator_pick",
        classes=("user-input",), confidence=0.1,
        source="operator_confirmed",
    )
    result = intake_learned_specs([*specs, promoted], vocabulary=VOCAB)
    assert len(result.sources) == MAX_LEARNED_SOURCES
    survivors = {s.function for s in result.sources}
    # the operator-promoted spec survives despite lowest confidence
    assert "app.mod.operator_pick" in survivors
    assert result.sources[0].human_promoted


def test_truncation_orders_by_confidence_within_tier():
    lo = spec("sanitiser", function="app.mod.lo", confidence=0.1)
    hi = spec("sanitiser", function="app.mod.hi", confidence=0.9)
    result = intake_learned_specs(
        [lo, hi] + [spec("sanitiser", function=f"app.mod.f{i}", confidence=0.5)
                    for i in range(MAX_LEARNED_SANITIZERS)],
        vocabulary=VOCAB,
    )
    survivors = {s.function for s in result.sanitizers}
    assert "app.mod.hi" in survivors and "app.mod.lo" not in survivors


def test_cap_overrides_are_parameters():
    result = intake_learned_specs(
        [spec(function=f"app.mod.f{i}") for i in range(10)],
        vocabulary=VOCAB, max_sinks=3,
    )
    assert len(result.sinks) == 3 and "learned_sinks" in result.caps_hit


# ── tag-only sanitizers ──────────────────────────────────────────────


def test_learned_sanitizers_are_tag_only():
    result = intake_learned_specs([spec("sanitiser")], vocabulary=VOCAB)
    (admitted,) = result.sanitizers
    assert admitted.semantics == "tag"


def test_no_input_shape_yields_kill_semantics():
    hostile = spec("sanitiser", semantics="kill")  # unknown key riding along
    result = intake_learned_specs([hostile], vocabulary=VOCAB)
    assert all(s.semantics == "tag" for s in result.sanitizers)


def test_kill_claim_demotion_is_counted_not_silent():
    """The tag-only rule admits a claimed-kill sanitizer as tag — but
    the claim is exactly the steering shape the rule exists for, so
    the demotion carries a counted marker."""
    result = intake_learned_specs(
        [spec("sanitiser", semantics="kill"),
         spec("sanitiser", function="app.mod.other", semantics="KILL"),
         spec("sanitiser", function="app.mod.plain")],
        vocabulary=VOCAB,
    )
    assert len(result.sanitizers) == 3
    assert result.demotion_count("learned_sanitizer_kill_demoted") == 2
    assert result.demotion_count(DEMOTED_SANITIZER_KILL) == 2
    assert result.to_dict()["demotions"][DEMOTED_SANITIZER_KILL] == 2


def test_hostile_file_and_tier_fields_neutralised():
    """`file` is informational target bytes: escaped at admit.
    `evidence_tier` is an enum token: anything off-charset floors."""
    result = intake_learned_specs(
        [spec(file="src/\x1b]0;pwned\x07/a.py", evidence_tier="xref\x1b_backed")],
        vocabulary=VOCAB,
    )
    (admitted,) = result.sinks
    assert "\x1b" not in admitted.file and "\\x1b" in admitted.file
    assert admitted.evidence_tier == ""
    clean = intake_learned_specs(
        [spec(evidence_tier="xref_backed")], vocabulary=VOCAB,
    )
    assert clean.sinks[0].evidence_tier == "xref_backed"


# ── additive-only propagators ────────────────────────────────────────


def test_propagator_flows_are_additions():
    result = intake_learned_specs(
        [spec("propagator", classes=(), params_affected=[0, 2])],
        vocabulary=VOCAB,
    )
    (admitted,) = result.propagators
    assert admitted.added_flows == (
        FlowEdge(src="Argument[0]", dst="ReturnValue"),
        FlowEdge(src="Argument[2]", dst="ReturnValue"),
    )


def test_propagator_without_params_adds_star_edge():
    result = intake_learned_specs(
        [spec("propagator", classes=(), params_affected=[])],
        vocabulary=VOCAB,
    )
    (admitted,) = result.propagators
    assert admitted.added_flows == (
        FlowEdge(src="Argument[*]", dst="ReturnValue"),
    )


def test_narrowing_claim_refused():
    result = intake_learned_specs(
        [spec("propagator", classes=(), narrowing=True)], vocabulary=VOCAB,
    )
    assert result.propagators == ()
    assert result.refusal_count(REFUSED_PROPAGATOR_NARROWING) == 1


def test_learned_model_has_no_narrowing_field():
    assert not hasattr(LearnedSpec(role="propagator", function="a.b"),
                       "narrowing")


# ── hostile inputs ───────────────────────────────────────────────────


@pytest.mark.parametrize("function", [
    "", "rm -rf /", "a..b", "name\x1b[31m", "x" * 400, 42, None,
])
def test_invalid_function_names_refused(function):
    result = intake_learned_specs(
        [spec(function=function)], vocabulary=VOCAB,
    )
    assert result.admitted == 0
    assert result.refusal_count(REFUSED_INVALID_FUNCTION_NAME) == 1


@pytest.mark.parametrize("role", ["", "barrier", None, 7])
def test_unknown_roles_refused(role):
    result = intake_learned_specs([spec(role=role)], vocabulary=VOCAB)
    assert result.admitted == 0
    assert result.refusal_count(REFUSED_UNKNOWN_ROLE) == 1


@pytest.mark.parametrize("confidence,expected", [
    (float("nan"), 0.0), (float("inf"), 0.0), (-3, 0.0), (7, 1.0),
    (True, 0.0), ("high", 0.0), (0.4, 0.4),
])
def test_confidence_clamped(confidence, expected):
    result = intake_learned_specs(
        [spec(confidence=confidence)], vocabulary=VOCAB,
    )
    assert result.sinks[0].confidence == expected


def test_hostile_params_ignored():
    result = intake_learned_specs(
        [spec("propagator", classes=(),
              params_affected=[True, -1, 99, "0", 1])],
        vocabulary=VOCAB,
    )
    (admitted,) = result.propagators
    assert admitted.params_affected == (1,)


def test_empty_vocabulary_admits_nothing_classed():
    result = intake_learned_specs(
        [spec("source", classes=("user-input",)), spec("propagator", classes=())],
        vocabulary=frozenset(),
    )
    assert result.sources == () and len(result.propagators) == 1


def test_pure_function_is_deterministic():
    specs = [spec(function=f"app.mod.f{i}", confidence=i / 10)
             for i in range(5)]
    first = intake_learned_specs(specs, vocabulary=VOCAB)
    second = intake_learned_specs(specs, vocabulary=VOCAB)
    assert first == second
    # inputs not mutated
    assert specs[0]["taint_classes"] == ["sql-injection"]

"""Baseline mutation-operator regression floors (fixture package).

Exercises the FULL synthetic-mutant path end-to-end and hermetically
(no network, no LLM): generator site finding → verified spec → label
construction → mutation application → the LLM-free consistency
prepass over the clean and the mutated tree.

HONESTY FRAMING (binding, mirrored in the corpus README): the
outcomes asserted here are mutation-operator regression floors
conditioned on family-found — an end-to-end plumbing harness
(family formation → census → thresholds → lead), NOT a real-bug
recall estimate.  Dimension gates on mutants alone certify
self-consistency only.  A floor value changing on these fixtures
means census/dimension behaviour changed; a floor staying green says
nothing about recall on real code.

Two-direction by construction: every case asserts BOTH that the
clean family scores consistent (no hit pre-mutation) and the
operator's expected post-mutation outcome.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from core.audit.corpus import mutate
from core.audit.corpus.mutation import apply_mutation_to_text

FIXTURES = Path(__file__).parent / "fixtures" / "mutcorpus"


def _c_grammar_available() -> bool:
    try:
        from core.audit.condition_extraction import _get_parser
        return _get_parser("c") is not None
    except Exception:  # noqa: BLE001 — availability probe
        return False


pytestmark = pytest.mark.skipif(
    not _c_grammar_available(),
    reason="tree-sitter C grammar unavailable "
           "(census/ordering extraction needs it)",
)

# The cleanup dimension admits LEARNED pairs only (study
# paired_operations / project verbs — never a hardcoded list); the
# harness supplies the study-output SHAPE the prepass consumes.
_DOMAIN_MODEL = {
    "paired_operations": [
        {"acquire": "dev_open", "release": "dev_close",
         "kind": "alloc_free"},
    ],
}

# The baseline floors, one row per mutation operator:
# (fixture file, mutated function, operator, find_site kwargs,
#  needs domain model, expected detected).
#
# Each row pins the operator's CURRENT floor value; update a row's
# expected value when a consuming dimension lands.
BASELINE_FLOORS = [
    ("ret_check.c", "reader_e", "drop-return-check", {}, False, True),
    ("guard.c", "use_d", "drop-guard", {}, False, True),
    ("ordering.c", "op_d", "swap-order", {}, False, True),
    ("cleanup.c", "job_d", "remove-pair-release",
     {"callee": "dev_close"}, True, True),
    ("flip_bound.c", "sum_d", "flip-bound", {}, False, False),
    ("iface.c", "raw_send", "drop-slot-guard", {}, False, True),
    ("enum_switch.c", "handle_d", "drop-case-arm",
     {"callee": "PKT_RESET"}, False, True),
]


def _span_of(text: str, function: str) -> tuple[int, int]:
    """Pinned span of *function* in the fixture (header to its
    closing brace at column 0)."""
    lines = text.split("\n")
    start = next(
        i for i, ln in enumerate(lines, 1)
        if f"{function}(" in ln and ln[:1].isalpha()
    )
    end = next(
        i for i in range(start, len(lines) + 1)
        if lines[i - 1].startswith("}")
    )
    return (start, end)


def _run_case(fname, function, operator, kwargs, needs_dm):
    text = (FIXTURES / fname).read_text(encoding="utf-8")
    span = _span_of(text, function)
    label = mutate.build_mutant_label(
        text,
        repo_key="mutcorpus", ref="deadbeef",
        file=fname, function=function, span=span,
        operator=operator, **kwargs,
    )
    mutated = apply_mutation_to_text(text, label)
    outcome = mutate.check_detection(
        {fname: text}, {fname: mutated},
        operator=operator, file=fname, function=function,
        domain_model=_DOMAIN_MODEL if needs_dm else None,
    )
    return label, outcome


@pytest.mark.parametrize(
    ("fname", "function", "operator", "kwargs", "needs_dm",
     "expected_detected"),
    BASELINE_FLOORS,
    ids=[row[2] for row in BASELINE_FLOORS],
)
def test_baseline_floor(
    fname, function, operator, kwargs, needs_dm, expected_detected,
):
    label, outcome = _run_case(
        fname, function, operator, kwargs, needs_dm,
    )
    # Direction 1: the CLEAN family scores consistent — no hit of
    # this dimension at the target function before mutation.  A
    # pre-mutation hit means the family fixture regressed and the
    # "detected" assertion below would be vacuous.
    assert outcome["family_clean"], outcome["pre_hits"]
    # Direction 2: the mutant's floor.
    assert outcome["detected"] is expected_detected, outcome
    if expected_detected:
        # Every hit rides the single consistency namespace.
        rule_ids = {
            h.get("rule_id", "") for h in outcome["post_hits"]
        }
        assert any(r.startswith("consistency:") for r in rule_ids), (
            rule_ids
        )
    # The label itself is a valid synthetic mutant.
    assert label.provenance_kind == "synthetic_mutant"
    assert label.bug_class == "consistency"


def test_flip_bound_baseline_floor_pin():
    """Pins the current baseline floor for this operator; update the
    expected values when a consuming dimension lands (a change here
    without one means an unexpected consumer claimed the dimension
    name)."""
    _, outcome = _run_case(
        "flip_bound.c", "sum_d", "flip-bound", {}, False,
    )
    assert outcome["dimension"] == "guard-predicate"
    assert outcome["detected"] is False
    assert outcome["post_hits"] == []

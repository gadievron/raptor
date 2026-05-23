"""Tests for derive_mitigations_found — structured mitigation list
per design strict invariant."""

from __future__ import annotations


from core.build.build_flags import BuildFlagsContext
from packages.source_intel.analyze import (
    AbortEvidence,
    CapabilityEvidence,
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    PairedFreeEvidence,
    SourceIntelResult,
)
from packages.source_intel.render import (
    derive_mitigations_found,
)


def test_empty_result_yields_no_mitigations():
    assert derive_mitigations_found(SourceIntelResult()) == []


def test_abort_dominates_emits_high_confidence():
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON", location=("/x.c", 5),
        grade=GRADE_DOMINATES, enclosing_function="op",
    ),))
    m = derive_mitigations_found(r, finding_function="op")
    assert len(m) == 1
    assert m[0].name == "abort_dominates"
    assert m[0].axis == "axis_2"
    assert m[0].confidence == "high"


def test_abort_same_path_emits_medium():
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="panic", location=("/x.c", 5),
        grade=GRADE_SAME_PATH, enclosing_function="op",
    ),))
    m = derive_mitigations_found(r, finding_function="op")
    assert m[0].name == "abort_on_path"
    assert m[0].confidence == "medium"


def test_abort_same_function_emits_low():
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="abort", location=("/x.c", 5),
        grade=GRADE_SAME_FUNCTION, enclosing_function="op",
    ),))
    m = derive_mitigations_found(r, finding_function="op")
    assert m[0].name == "abort_proximate"
    assert m[0].confidence == "low"


def test_abort_in_different_function_filtered_out():
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON", location=("/x.c", 5),
        grade=GRADE_DOMINATES, enclosing_function="sibling_op",
    ),))
    m = derive_mitigations_found(r, finding_function="actual_op")
    assert m == []


def test_capability_emits_axis_4_medium():
    r = SourceIntelResult(capabilities=(CapabilityEvidence(
        cap_function="capable", location=("/x.c", 5),
        grade=GRADE_SAME_FUNCTION, enclosing_function="op",
    ),))
    m = derive_mitigations_found(r, finding_function="op")
    assert m[0].axis == "axis_4"
    assert m[0].name == "privilege_gate"


def test_fortify_emits_high_at_level_2():
    bf = BuildFlagsContext(fortify_source_level=2)
    r = SourceIntelResult(build_flags=bf)
    m = derive_mitigations_found(r)
    assert m[0].name == "fortify_source"
    assert m[0].confidence == "high"


def test_fortify_emits_medium_at_level_1():
    bf = BuildFlagsContext(fortify_source_level=1, source="kconfig")
    r = SourceIntelResult(build_flags=bf)
    m = derive_mitigations_found(r)
    assert m[0].confidence == "medium"


def test_paired_free_emits_axis_3():
    r = SourceIntelResult(paired_frees=(PairedFreeEvidence(
        allocator="kmalloc", free_fn="kfree",
        location=("/x.c", 5), enclosing_function="op",
    ),))
    m = derive_mitigations_found(r, finding_function="op")
    assert m[0].name == "paired_free"
    assert m[0].axis == "axis_3"


def test_absence_does_not_emit_hardened_false():
    """Design strict invariant: absence is NOT unhardened.
    derive_mitigations_found returns an EMPTY list, never a
    list with a `hardened: False` entry or similar."""
    r = SourceIntelResult()
    m = derive_mitigations_found(r)
    assert m == []
    # No "unhardened" / "False" / "hardened" entry anywhere.
    for entry in m:
        assert "hardened" not in entry.name
        assert "unhardened" not in entry.name

"""Tests for ``core.dataflow.sanitizer_evidence``."""

from __future__ import annotations

import pytest

from core.dataflow.sanitizer_evidence import (
    PROVENANCE_FRAMEWORK_CATALOG,
    PROVENANCE_LLM,
    SCHEMA_VERSION,
    SEMANTICS_AUTH_CHECK,
    SEMANTICS_SQL_ESCAPE,
    SEMANTICS_URL_ALLOWLIST,
    CandidateValidator,
    SanitizerEvidence,
    StepAnnotation,
)


def _candidate(
    name: str = "escape_sql",
    qualified_name: str = "proj.db.helpers.escape_sql",
    semantics_tag: str = SEMANTICS_SQL_ESCAPE,
    confidence: float = 0.85,
    extraction_provenance: str = PROVENANCE_LLM,
) -> CandidateValidator:
    return CandidateValidator(
        name=name,
        qualified_name=qualified_name,
        semantics_tag=semantics_tag,
        semantics_text="doubles single quotes; intended for SQL string contexts",
        confidence=confidence,
        source_file="db/helpers.py",
        source_line=18,
        extraction_provenance=extraction_provenance,
    )


def _annotation(
    step_index: int = 1,
    on_path_validators=("proj.db.helpers.escape_sql",),
) -> StepAnnotation:
    return StepAnnotation(
        step_index=step_index,
        on_path_validators=on_path_validators,
        variables_referenced=("user_input", "sql"),
        inlined_helpers=("normalize",),
    )


def _evidence() -> SanitizerEvidence:
    return SanitizerEvidence(
        candidate_pool=(_candidate(),),
        step_annotations=(_annotation(0), _annotation(1)),
        pool_completeness="scoped_to_5_files",
        extraction_failures=("utils/legacy.py: parse error",),
    )


# ---------------------------------------------------------------------
# CandidateValidator
# ---------------------------------------------------------------------


def test_candidate_roundtrip():
    c = _candidate()
    assert CandidateValidator.from_dict(c.to_dict()) == c


@pytest.mark.parametrize("field_name", ["name", "qualified_name", "semantics_text", "source_file"])
def test_candidate_rejects_empty_required_string(field_name: str):
    kwargs = dict(
        name="x",
        qualified_name="m.x",
        semantics_tag=SEMANTICS_SQL_ESCAPE,
        semantics_text="t",
        confidence=0.5,
        source_file="x.py",
        source_line=1,
        extraction_provenance=PROVENANCE_LLM,
    )
    kwargs[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        CandidateValidator(**kwargs)


def test_candidate_rejects_unknown_semantics_tag():
    with pytest.raises(ValueError, match="semantics_tag"):
        CandidateValidator(
            name="x",
            qualified_name="m.x",
            semantics_tag="made_up",
            semantics_text="t",
            confidence=0.5,
            source_file="x.py",
            source_line=1,
            extraction_provenance=PROVENANCE_LLM,
        )


def test_candidate_rejects_unknown_extraction_provenance():
    with pytest.raises(ValueError, match="extraction_provenance"):
        CandidateValidator(
            name="x",
            qualified_name="m.x",
            semantics_tag=SEMANTICS_SQL_ESCAPE,
            semantics_text="t",
            confidence=0.5,
            source_file="x.py",
            source_line=1,
            extraction_provenance="hand_typed",
        )


@pytest.mark.parametrize("conf", [-0.1, 1.1, 2.0])
def test_candidate_rejects_out_of_range_confidence(conf: float):
    with pytest.raises(ValueError, match="confidence"):
        _candidate(confidence=conf)


@pytest.mark.parametrize("conf", [0.0, 0.5, 1.0])
def test_candidate_accepts_boundary_confidence(conf: float):
    assert _candidate(confidence=conf).confidence == conf


def test_candidate_rejects_zero_source_line():
    with pytest.raises(ValueError, match="source_line"):
        CandidateValidator(
            name="x",
            qualified_name="m.x",
            semantics_tag=SEMANTICS_SQL_ESCAPE,
            semantics_text="t",
            confidence=0.5,
            source_file="x.py",
            source_line=0,
            extraction_provenance=PROVENANCE_LLM,
        )


def test_candidate_from_dict_rejects_unknown_fields():
    blob = _candidate().to_dict()
    blob["mystery"] = "boo"
    with pytest.raises(ValueError, match="unknown fields"):
        CandidateValidator.from_dict(blob)


def test_candidate_is_hashable():
    """Frozen dataclass with all-immutable fields → hashable. Useful
    for de-duplication of candidate pools by qualified_name."""
    a = _candidate(qualified_name="m.x")
    b = _candidate(qualified_name="m.x")
    c = _candidate(qualified_name="m.y")
    assert {a, b, c} == {a, c}


# ---------------------------------------------------------------------
# StepAnnotation
# ---------------------------------------------------------------------


def test_annotation_roundtrip():
    a = _annotation()
    assert StepAnnotation.from_dict(a.to_dict()) == a


def test_annotation_defaults_to_empty_tuples():
    a = StepAnnotation(step_index=0)
    assert a.on_path_validators == ()
    assert a.variables_referenced == ()
    assert a.inlined_helpers == ()


def test_annotation_coerces_list_to_tuple():
    a = StepAnnotation(
        step_index=2,
        on_path_validators=["v1", "v2"],
        variables_referenced=["x"],
    )
    assert isinstance(a.on_path_validators, tuple)
    assert isinstance(a.variables_referenced, tuple)


def test_annotation_rejects_negative_step_index():
    with pytest.raises(ValueError, match="step_index"):
        StepAnnotation(step_index=-1)


def test_annotation_rejects_empty_string_in_lists():
    with pytest.raises(ValueError, match="non-empty"):
        StepAnnotation(step_index=0, on_path_validators=("",))


def test_annotation_from_dict_rejects_unknown_fields():
    blob = _annotation().to_dict()
    blob["bonus"] = 1
    with pytest.raises(ValueError, match="unknown fields"):
        StepAnnotation.from_dict(blob)


def test_annotation_from_dict_handles_missing_optional_lists():
    a = StepAnnotation.from_dict({"step_index": 3})
    assert a == StepAnnotation(step_index=3)


# ---------------------------------------------------------------------
# SanitizerEvidence
# ---------------------------------------------------------------------


def test_evidence_roundtrip():
    e = _evidence()
    assert SanitizerEvidence.from_dict(e.to_dict()) == e


def test_evidence_json_roundtrip():
    e = _evidence()
    assert SanitizerEvidence.from_json(e.to_json()) == e


def test_evidence_to_dict_records_schema_version():
    assert _evidence().to_dict()["schema_version"] == SCHEMA_VERSION


def test_evidence_from_dict_rejects_mismatched_schema_version():
    blob = _evidence().to_dict()
    blob["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema_version"):
        SanitizerEvidence.from_dict(blob)


def test_evidence_from_dict_rejects_missing_schema_version():
    blob = _evidence().to_dict()
    del blob["schema_version"]
    with pytest.raises(KeyError):
        SanitizerEvidence.from_dict(blob)


def test_evidence_from_dict_rejects_unknown_fields():
    blob = _evidence().to_dict()
    blob["bogus"] = "x"
    with pytest.raises(ValueError, match="unknown fields"):
        SanitizerEvidence.from_dict(blob)


def test_evidence_defaults_to_empty_pools():
    e = SanitizerEvidence()
    assert e.candidate_pool == ()
    assert e.step_annotations == ()
    assert e.pool_completeness == "unknown"
    assert e.extraction_failures == ()


def test_evidence_rejects_empty_pool_completeness():
    with pytest.raises(ValueError, match="pool_completeness"):
        SanitizerEvidence(pool_completeness="")


def test_evidence_rejects_wrong_type_in_candidate_pool():
    with pytest.raises(TypeError, match="CandidateValidator"):
        SanitizerEvidence(candidate_pool=("not_a_candidate",))  # type: ignore[arg-type]


def test_evidence_rejects_wrong_type_in_step_annotations():
    with pytest.raises(TypeError, match="StepAnnotation"):
        SanitizerEvidence(step_annotations=("not_an_annotation",))  # type: ignore[arg-type]


def test_evidence_coerces_list_to_tuple():
    e = SanitizerEvidence(
        candidate_pool=[_candidate()],
        step_annotations=[_annotation()],
        extraction_failures=["x.py: parse error"],
    )
    assert isinstance(e.candidate_pool, tuple)
    assert isinstance(e.step_annotations, tuple)
    assert isinstance(e.extraction_failures, tuple)


def test_evidence_with_multiple_candidates_distinguishes_them():
    e = SanitizerEvidence(
        candidate_pool=(
            _candidate(name="escape_sql", qualified_name="m.escape_sql", semantics_tag=SEMANTICS_SQL_ESCAPE),
            _candidate(name="check_url", qualified_name="m.check_url", semantics_tag=SEMANTICS_URL_ALLOWLIST),
            _candidate(name="require_admin", qualified_name="m.require_admin", semantics_tag=SEMANTICS_AUTH_CHECK),
        ),
        pool_completeness="scoped_to_5_files",
    )
    tags = {c.semantics_tag for c in e.candidate_pool}
    assert tags == {SEMANTICS_SQL_ESCAPE, SEMANTICS_URL_ALLOWLIST, SEMANTICS_AUTH_CHECK}


def test_evidence_does_not_carry_verdict_field():
    """Regression guard: the rejected design tried a ``verdict`` field
    that short-circuited the validator pipeline. The current schema
    deliberately has no such field — evidence is fed *into* the
    existing LLM gate, not around it."""
    e = _evidence()
    blob = e.to_dict()
    forbidden = {"verdict", "is_validated", "is_exploitable", "bypass_possible"}
    assert not (set(blob.keys()) & forbidden), (
        f"SanitizerEvidence must not expose verdict-shaped fields; saw {set(blob.keys()) & forbidden}"
    )


def test_evidence_extraction_provenance_distinguishes_sources():
    """LLM-extracted candidates should be distinguishable from
    framework-catalog or source-annotation candidates downstream —
    a high-confidence LLM extraction is weaker evidence than a
    framework-catalog match."""
    llm = _candidate(extraction_provenance=PROVENANCE_LLM)
    catalog = _candidate(extraction_provenance=PROVENANCE_FRAMEWORK_CATALOG)
    assert llm.extraction_provenance != catalog.extraction_provenance

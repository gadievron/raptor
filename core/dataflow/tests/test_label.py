"""Round-trip and validation tests for ``core.dataflow.label``."""

from __future__ import annotations

import pytest

from core.dataflow.label import (
    FP_FRAMEWORK_MITIGATION,
    FP_MISSING_SANITIZER_MODEL,
    GroundTruth,
    SCHEMA_VERSION,
    VERDICT_FALSE_POSITIVE,
    VERDICT_TRUE_POSITIVE,
)


def _tp() -> GroundTruth:
    return GroundTruth(
        finding_id="codeql:py/sql-injection:001",
        verdict=VERDICT_TRUE_POSITIVE,
        rationale="confirmed reachable; no validator on path",
        labeler="johnc",
        labeled_at="2026-05-10",
    )


def _fp() -> GroundTruth:
    return GroundTruth(
        finding_id="codeql:py/sql-injection:002",
        verdict=VERDICT_FALSE_POSITIVE,
        fp_category=FP_MISSING_SANITIZER_MODEL,
        rationale="path traverses proj.utils.escape_sql which CodeQL doesn't model",
        labeler="johnc",
        labeled_at="2026-05-10",
    )


def test_true_positive_roundtrip():
    assert GroundTruth.from_dict(_tp().to_dict()) == _tp()


def test_false_positive_roundtrip():
    assert GroundTruth.from_dict(_fp().to_dict()) == _fp()


def test_true_positive_rejects_fp_category():
    with pytest.raises(ValueError, match="fp_category must be None"):
        GroundTruth(
            finding_id="x",
            verdict=VERDICT_TRUE_POSITIVE,
            fp_category=FP_FRAMEWORK_MITIGATION,
            rationale="r",
            labeler="x",
            labeled_at="2026-05-10",
        )


def test_false_positive_requires_fp_category():
    with pytest.raises(ValueError, match="fp_category required"):
        GroundTruth(
            finding_id="x",
            verdict=VERDICT_FALSE_POSITIVE,
            rationale="r",
            labeler="x",
            labeled_at="2026-05-10",
        )


def test_unknown_fp_category_rejected():
    with pytest.raises(ValueError, match="fp_category"):
        GroundTruth(
            finding_id="x",
            verdict=VERDICT_FALSE_POSITIVE,
            fp_category="something_made_up",
            rationale="r",
            labeler="x",
            labeled_at="2026-05-10",
        )


def test_unknown_verdict_rejected():
    with pytest.raises(ValueError, match="verdict"):
        GroundTruth(
            finding_id="x",
            verdict="maybe",
            rationale="r",
            labeler="x",
            labeled_at="2026-05-10",
        )


@pytest.mark.parametrize("field_name", ["finding_id", "rationale", "labeler"])
def test_empty_required_string_rejected(field_name: str):
    kwargs = dict(
        finding_id="x",
        verdict=VERDICT_TRUE_POSITIVE,
        rationale="r",
        labeler="x",
        labeled_at="2026-05-10",
    )
    kwargs[field_name] = ""
    with pytest.raises(ValueError, match=field_name):
        GroundTruth(**kwargs)


@pytest.mark.parametrize(
    "bad_date",
    ["yesterday", "2026/05/10", "2026-5-10", "10-05-2026", "", "2026-05-10T00:00:00"],
)
def test_non_iso_labeled_at_rejected(bad_date: str):
    with pytest.raises(ValueError, match="labeled_at"):
        GroundTruth(
            finding_id="x",
            verdict=VERDICT_TRUE_POSITIVE,
            rationale="r",
            labeler="x",
            labeled_at=bad_date,
        )


def test_to_dict_records_schema_version():
    assert _tp().to_dict()["schema_version"] == SCHEMA_VERSION


def test_from_dict_rejects_mismatched_schema_version():
    blob = _tp().to_dict()
    blob["schema_version"] = SCHEMA_VERSION + 1
    with pytest.raises(ValueError, match="schema_version"):
        GroundTruth.from_dict(blob)


def test_from_dict_rejects_missing_schema_version():
    blob = _tp().to_dict()
    del blob["schema_version"]
    with pytest.raises(KeyError):
        GroundTruth.from_dict(blob)


def test_from_dict_rejects_unknown_fields():
    blob = _tp().to_dict()
    blob["verdict_typo"] = "true_positive"
    with pytest.raises(ValueError, match="unknown fields"):
        GroundTruth.from_dict(blob)


def test_json_roundtrip():
    assert GroundTruth.from_json(_fp().to_json()) == _fp()

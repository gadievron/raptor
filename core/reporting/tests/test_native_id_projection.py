"""Projection preserves valid zero-valued producer IDs and field priority."""
from copy import deepcopy

import pytest

from core.reporting.adapters import native_findings


def test_zero_primary_finding_id_keeps_priority_and_native_evidence():
    captured = [{"finding_id": 0, "id": "secondary", "title": "captured"}]
    original = deepcopy(captured)
    normalized = native_findings(captured, run_id="captured", producer="fixture")
    assert normalized[0]["source_id"] == 0
    assert type(normalized[0]["source_id"]) is int
    assert normalized[0]["native"] == original[0] and captured == original


@pytest.mark.parametrize("primary, secondary, expected", [
    (0, None, 0), (False, "fallback", "fallback"),
    (None, "fallback", "fallback"), ("", "fallback", "fallback"),
    (2, "fallback", 2), ("primary", "fallback", "primary"),
])
def test_other_id_priority_and_fallback_cases_remain_compatible(primary, secondary, expected):
    captured = [{"finding_id": primary, "id": secondary, "title": "first"},
                {"finding_id": primary, "id": secondary, "title": "second"}]
    normalized = native_findings(captured, run_id="captured", producer="fixture")
    assert [row["source_id"] for row in normalized] == [expected, expected]
    assert normalized[0]["occurrence_ref"] != normalized[1]["occurrence_ref"]
    assert [row["native"] for row in normalized] == captured

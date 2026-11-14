"""Unknown explicit status shapes keep the legacy reader contract."""
from copy import deepcopy

import pytest

from core.run import finding_status as mod


@pytest.mark.parametrize("status", [[], {}], ids=["array", "object"])
@pytest.mark.parametrize("fields,expected", [
    ({"error": "owned failure"}, mod.ERROR),
    ({"file": "owned.c"}, mod.SKIPPED),
    ({"is_true_positive": True, "is_exploitable": False,
      "self_contradictory": True}, mod.ANALYSIS_INCONSISTENT),
], ids=["error", "legacy-skip", "contradictory-negative"])
def test_unrecognized_status_keeps_derived_classification(status, fields, expected):
    finding = dict(fields, status=status)
    before = deepcopy(finding)
    assert mod.get_status(finding) == expected
    assert mod.is_errored(finding) is (expected == mod.ERROR)
    assert mod.is_skipped(finding) is (expected == mod.SKIPPED)
    assert mod.needs_review(finding) is (expected == mod.ANALYSIS_INCONSISTENT)
    assert finding == before


@pytest.mark.parametrize("status", [[], {}], ids=["array", "object"])
def test_unrecognized_explicit_status_is_not_terminal(status):
    finding = {"status": status, "is_true_positive": True}
    before = deepcopy(finding)
    assert mod.is_terminal(finding) is False
    assert finding == before


def test_known_explicit_statuses_still_override_legacy_fields():
    for status in mod.ALL_STATUSES:
        finding = {"status": status, "error": "legacy conflict"}
        assert mod.get_status(finding) == status
        assert mod.is_terminal(finding) is True

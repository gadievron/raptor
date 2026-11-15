import pytest

from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.hypothesis_validation.verdict import verdict_from


def test_unrecognized_unhashable_claim_is_inconclusive():
    evidence = ToolEvidence(tool="semgrep", rule="", success=True, matches=[{"line": 1}])
    assert verdict_from(evidence, []) == "inconclusive"


@pytest.mark.parametrize("claim", [[], {}, set(), None, 1, True, "unknown"])
def test_unknown_claims_keep_safe_floor(claim):
    from packages.hypothesis_validation.verdict import aggregate

    evidence = ToolEvidence(tool="semgrep", rule="", success=True, matches=[{"line": 1}])
    assert verdict_from(evidence, claim) == "inconclusive"
    assert aggregate([evidence], claim) == "inconclusive"


@pytest.mark.parametrize("stored", ["confirmed", "refuted", "inconclusive", "unknown"])
def test_claim_uses_stored_verdict_text(stored):
    class Claim(str):
        def __hash__(self):
            raise AssertionError("custom hash must not select verdict")
        def __eq__(self, other):
            raise AssertionError("custom equality must not select verdict")
        def __str__(self):
            raise AssertionError("custom conversion must not select verdict")

    evidence = ToolEvidence(tool="semgrep", rule="", success=True, matches=[{"line": 1}])
    expected = "confirmed" if stored == "confirmed" else "inconclusive"
    result = verdict_from(evidence, Claim(stored))
    assert type(result) is str
    assert result == expected

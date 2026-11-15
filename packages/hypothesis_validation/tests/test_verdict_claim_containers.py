"""Public verdict combinators safely floor malformed JSON claim shapes."""
from packages.hypothesis_validation.adapters.base import ToolEvidence
from packages.hypothesis_validation.verdict import aggregate, verdict_from


def test_verdict_combinators_floor_container_claims():
    matched = ToolEvidence(tool="owned", rule="owned", success=True,
                           matches=[{"file": "owned.c", "line": 1}])
    for claim in ({}, [], {"verdict": "confirmed"}, ["confirmed"], None, 1, True):
        assert verdict_from(matched, claim) == "inconclusive"
        assert aggregate([matched, matched], claim) == "inconclusive"
    assert verdict_from(matched, "confirmed") == "confirmed"
    assert aggregate([matched, matched], "confirmed") == "confirmed"
    assert verdict_from(matched, "refuted") == "inconclusive"
    assert aggregate([], {}) == "inconclusive"
    failed = ToolEvidence(tool="owned", rule="owned", success=False)
    assert verdict_from(failed, {}) == "inconclusive"
    for predicate in ("sat", "unsat"):
        evidence = ToolEvidence(tool="smt", rule="owned", success=True,
                                predicate_verdict=predicate)
        for polarity in ("reachability", "infeasibility"):
            expected = "confirmed" if (predicate == "sat") == (polarity == "reachability") else "refuted"
            assert verdict_from(evidence, {}, polarity=polarity) == expected

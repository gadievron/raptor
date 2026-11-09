"""A failed site query cannot erase another site's validated counterexample."""

import pytest

from core.audit import invariant_smt as inv
from core.audit.protocol_state import check_invariant_multi_site

pytestmark = pytest.mark.usefixtures("invariant_unit_worker")


@pytest.mark.parametrize("unavailable", [(0,), (1,), (0, 1)],
                         ids=["first", "last", "all"])
def test_valid_counterexample_survives_unavailable_sibling(monkeypatch, unavailable):
    pytest.importorskip("tree_sitter_c")
    pytest.importorskip("z3")
    native_batch = inv.check_site_batch
    observed = []

    def interrupted_batch(invariant, sites, **kwargs):
        results = native_batch(invariant, sites, **kwargs)
        assert [site.verdict for site in results] == ["violable", "violable"]
        for site in results:
            assert site.model["Count"] <= site.model["Limit"]
            assert site.model["Count'"] == site.model["Count"] + 1 > site.model["Limit"]
        observed.extend(results)
        for index in unavailable:
            original = results[index]
            results[index] = inv.SiteResult(
                line=original.line, code=original.code, verdict="unknown",
                reason="z3 unavailable",
            )
        return results

    monkeypatch.setattr(inv, "check_site_batch", interrupted_batch)
    source = "void Increment(struct S *State){\nState->Count++;\nState->Count++;\n}"
    writes = [
        dict(file="a.c", function="Increment", line=line, code="State->Count++;")
        for line in (2, 3)
    ]
    result = check_invariant_multi_site(
        "Count <= Limit", {"fields": {"Count": {"writes": writes}}}, {"a.c": source},
    )
    assert len(observed) == 2, result
    assert result["guard_leg"] is True
    expected = "inconclusive" if len(unavailable) == 2 else "violable"
    assert result["outcome"] == expected, result
    assert [site["verdict"] for site in result["sites"]] == [
        "unknown" if index in unavailable else "violable" for index in range(2)
    ]
    if expected == "inconclusive":
        assert result["reason"] == "z3 unavailable"
    else:
        assert any(site["model"] for site in result["sites"] if site["verdict"] == "violable")

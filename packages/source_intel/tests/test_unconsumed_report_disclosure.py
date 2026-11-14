"""Deferred report families disclose loss through existing evidence text."""

import pytest

from packages.source_intel.analyze import SourceIntelResult, WarnEvidence
from packages.source_intel.render import derive_evidence_strings


@pytest.mark.parametrize("rule,families", [
    ("refcount_pairs", ("refcount_get", "refcount_put")),
    ("lock_pairs", ("lock_take", "lock_release", "lock_leak")),
    ("cred_manipulation", ("cred",)),
    ("setuid_setgid", ("setid",)),
    ("attr_pure", ("pure",)),
    ("attr_const", ("const",)),
    ("attr_deprecated", ("deprecated",)),
    ("attr_counted_by", ("counted_by",)),
])
def test_attempted_rule_discloses_unretained_families(rule, families):
    result = SourceIntelResult(rules_executed=(rule,))
    lines = derive_evidence_strings(result)
    notice = next(line for line in lines if "coverage limitation" in line)
    assert all(family in notice for family in families)
    assert "not retained" in notice
    assert "not a finding" in notice
    assert "does not establish absence" in notice


@pytest.mark.parametrize("rules", [(), ("warn_proximate",), ("attr_pure_INJECTED",)])
def test_unrelated_rules_do_not_mint_disclosure(rules):
    lines = derive_evidence_strings(SourceIntelResult(rules_executed=rules))
    assert not any("coverage limitation" in line for line in lines)


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_disclosure_coexists_with_failures_and_observations(style):
    result = SourceIntelResult(
        rules_executed=("refcount_pairs", "lock_pairs", "cred_manipulation",
                        "setuid_setgid", "attr_pure", "attr_const",
                        "attr_deprecated", "attr_counted_by", "attr_pure"),
        rules_failed=(("attr_const", "untrusted failure text"),),
        warns=(WarnEvidence(warn_fn="WARN_ON", location=("owned.c", 3)),),
    )
    lines = derive_evidence_strings(result, style=style)
    assert "rule failure" in lines[0]
    assert "coverage limitation" in lines[1]
    assert "WARN_ON" in lines[2]
    assert lines[1].count("pure") == 1
    assert "untrusted failure text" not in "\n".join(lines)
    for family in ("refcount_get", "refcount_put", "lock_take", "lock_release",
                   "lock_leak", "cred", "setid", "pure", "const",
                   "deprecated", "counted_by"):
        assert family in lines[1]


def test_disclosure_respects_existing_budget_and_skip_contract():
    result = SourceIntelResult(rules_executed=("attr_pure",))
    assert derive_evidence_strings(result, max_lines=0) == []
    lines = derive_evidence_strings(result, max_lines=1, binary_verdict="blocked")
    assert len(lines) == 1 and "SUPERSEDED" in lines[0]
    skipped = SourceIntelResult(rules_executed=("attr_pure",), skipped_reason="owned")
    assert not any("coverage limitation" in line for line in derive_evidence_strings(skipped))

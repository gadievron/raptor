"""Deferred report families disclose loss through existing evidence text."""

import pytest

from packages.source_intel.analyze import SourceIntelResult, WarnEvidence
from packages.source_intel.render import derive_evidence_strings, derive_mitigations_found


@pytest.mark.parametrize("rule,families", [
    ("refcount_pairs", ("refcount_get", "refcount_put")),
    ("lock_pairs", ("lock_take", "lock_release", "lock_leak")),
    ("cred_manipulation", ("cred",)),
    ("setuid_setgid", ("setid",)),
])
def test_attempted_rule_discloses_unretained_families(rule, families):
    result = SourceIntelResult(rules_executed=(rule,))
    lines = derive_evidence_strings(result)
    notice = next(line for line in lines if "coverage limitation" in line)
    assert all(family in notice for family in families)
    assert "not retained" in notice
    assert "not a finding" in notice
    assert "does not establish absence" in notice


@pytest.mark.parametrize("rules", [
    (), ("warn_proximate",), ("refcount_pairs_INJECTED",),
    ("attr_pure",), ("attr_const",), ("attr_deprecated",), ("attr_counted_by",),
])
def test_unrelated_rules_do_not_mint_disclosure(rules):
    lines = derive_evidence_strings(SourceIntelResult(rules_executed=rules))
    assert not any("coverage limitation" in line for line in lines)


@pytest.mark.parametrize("style", ["stage_d", "exploit_plan", "agentic_variant"])
def test_disclosure_coexists_with_failures_and_observations(style):
    result = SourceIntelResult(
        rules_executed=("refcount_pairs", "lock_pairs", "cred_manipulation",
                        "setuid_setgid", "attr_pure", "attr_const",
                        "attr_deprecated", "attr_counted_by", "refcount_pairs"),
        rules_failed=(("attr_const", "untrusted failure text"),),
        warns=(WarnEvidence(warn_fn="WARN_ON", location=("owned.c", 3)),),
    )
    lines = derive_evidence_strings(result, style=style)
    assert "rule failure" in lines[0]
    assert "coverage limitation" in lines[1]
    assert "WARN_ON" in lines[2]
    assert sum("coverage limitation" in line for line in lines) == 1
    assert lines[1].count("refcount_get") == 1
    assert not any(family in lines[1] for family in (
        "pure", "const", "deprecated", "counted_by",
    ))
    assert "untrusted failure text" not in "\n".join(lines)
    for family in ("refcount_get", "refcount_put", "lock_take", "lock_release",
                   "lock_leak", "cred", "setid"):
        assert family in lines[1]


def test_disclosure_respects_existing_budget_and_skip_contract():
    result = SourceIntelResult(rules_executed=("refcount_pairs",))
    assert derive_evidence_strings(result, max_lines=0) == []
    lines = derive_evidence_strings(result, max_lines=1, binary_verdict="blocked")
    assert len(lines) == 1 and "SUPERSEDED" in lines[0]
    skipped = SourceIntelResult(rules_executed=("refcount_pairs",), skipped_reason="owned")
    assert not any("coverage limitation" in line for line in derive_evidence_strings(skipped))


@pytest.mark.parametrize("budget,notice,observation", [
    (0, False, False), (1, False, False), (2, True, False),
    (3, True, True), (None, True, True),
])
def test_failure_notice_and_observation_budget_order(budget, notice, observation):
    result = SourceIntelResult(
        rules_executed=("lock_pairs", "lock_pairs"),
        rules_failed=(("lock_pairs", "owned failure"),),
        warns=(WarnEvidence(warn_fn="WARN_ON", location=("owned.c", 3)),),
    )
    lines = derive_evidence_strings(result, max_lines=budget)
    assert any("coverage limitation" in line for line in lines) is notice
    assert any("WARN_ON" in line for line in lines) is observation
    if lines:
        assert "rule failure" in lines[0]
    if notice:
        assert lines[1].count("lock_take") == 1


def test_default_attempts_and_text_do_not_add_mitigations_or_mutate_result():
    empty = SourceIntelResult()
    assert not any("coverage limitation" in line for line in derive_evidence_strings(empty))
    result = SourceIntelResult(rules_executed=("refcount_pairs",))
    before = result.__dict__.copy()
    text = derive_evidence_strings(result, max_lines=1)
    assert len(text) == 1 and "coverage limitation" in text[0]
    assert "whether these reports were emitted" in text[0]
    assert derive_mitigations_found(result) == derive_mitigations_found(empty) == []
    assert result.__dict__ == before
    prefixed = derive_evidence_strings(result, max_lines=2, binary_verdict="blocked")
    assert "SUPERSEDED" in prefixed[0] and "coverage limitation" in prefixed[1]

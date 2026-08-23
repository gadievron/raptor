"""Sweep verb outcome mapping for detector model-misses.

A detector whose prerequisites are absent from the source ('no auth
checks found', 'no lock acquires found', 'no allocations found', ...)
never tested the hypothesis — recording outcome=refuted for that
model miss let a non-analysis clear tool confirmations.  These tests
pin the mapping: model-not-applicable → inconclusive; applied and
negative → refuted; positive → confirmed.
"""

from __future__ import annotations

from core.audit.sweep import _negative_outcome, run_smt_verb_direct

_EMPTYISH = "int f(void) { return 0; }"


def _run(verb: str, source: str):
    return run_smt_verb_direct(
        file_path="a.c",
        function_name="f",
        verb=verb,
        source=source,
        hypothesis="hypothesis under test",
        target_path="/tmp",
    )


class TestModelMissIsInconclusive:
    def test_auth_bypass_no_auth_checks(self):
        r = _run("check-auth-bypass", _EMPTYISH)
        assert r.outcome == "inconclusive"
        assert r.details.get("applicable") is False

    def test_lock_discipline_no_acquires(self):
        r = _run("check-lock-discipline", _EMPTYISH)
        assert r.outcome == "inconclusive"

    def test_resource_leak_no_allocations(self):
        r = _run("check-resource-leak", _EMPTYISH)
        assert r.outcome == "inconclusive"

    def test_null_propagation_no_nullable_assigns(self):
        r = _run("check-null-propagation", _EMPTYISH)
        assert r.outcome == "inconclusive"

    def test_early_release_no_acquires(self):
        r = _run("check-early-release", _EMPTYISH)
        assert r.outcome == "inconclusive"

    def test_lock_domain_no_scopes(self):
        r = _run("check-lock-domain", _EMPTYISH)
        assert r.outcome == "inconclusive"

    def test_toctou_empty_source_stays_inconclusive(self):
        r = run_smt_verb_direct(
            file_path="a.c", function_name="f", verb="check-toctou",
            source="   ", hypothesis="toctou", target_path="/tmp",
        )
        assert r.outcome == "inconclusive"


class TestAppliedDetectorStillRefutesOrConfirms:
    def test_auth_bypass_applied_negative_refutes(self):
        src = (
            "int f(int x) {\n"
            "    if (!capable(CAP_SYS_ADMIN))\n"
            "        return -EPERM;\n"
            "    do_work();\n"
            "    return 0;\n"
            "}\n"
        )
        r = _run("check-auth-bypass", src)
        assert r.outcome == "refuted"

    def test_lock_discipline_positive_confirms(self):
        src = (
            "int f(struct s *p) {\n"
            "    spin_lock(&p->lock);\n"
            "    if (p->bad)\n"
            "        return -EINVAL;\n"
            "    spin_unlock(&p->lock);\n"
            "    return 0;\n"
            "}\n"
        )
        r = _run("check-lock-discipline", src)
        assert r.outcome == "confirmed"


class TestNegativeOutcomeHelper:
    def test_applicable_default_true(self):
        class R:
            pass
        assert _negative_outcome(R()) == "refuted"

    def test_inapplicable_maps_inconclusive(self):
        class R:
            applicable = False
        assert _negative_outcome(R()) == "inconclusive"

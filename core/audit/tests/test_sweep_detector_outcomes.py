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


class TestCheckerWrapperApplicability:
    """The four checker-sweep wrappers follow the same doctrine as
    the SMT verbs: a checker whose structural precondition never
    matched (no copy sites, no narrowing, no length candidates, no
    struct layouts) never tested the hypothesis — inconclusive, not
    refuted."""

    _NO_SITES = "int f(void) { return 1; }"

    def test_heap_copy_no_sites_inconclusive(self):
        from core.audit.sweep import run_heap_copy_sweep

        r = run_heap_copy_sweep(
            file_path="a.c", function_name="f",
            source=self._NO_SITES, cwe="CWE-122",
        )
        assert r.outcome == "inconclusive"
        assert any("prerequisites never matched" in e for e in r.errors)

    def test_integer_truncation_no_sites_inconclusive(self):
        from core.audit.sweep import run_integer_truncation_sweep

        r = run_integer_truncation_sweep(
            file_path="a.c", function_name="f",
            source=self._NO_SITES, cwe="CWE-190",
        )
        assert r.outcome == "inconclusive"

    def test_proto_length_no_sites_inconclusive(self):
        from core.audit.sweep import run_proto_length_sweep

        r = run_proto_length_sweep(
            file_path="a.c", function_name="f",
            source=self._NO_SITES, cwe="CWE-120",
        )
        assert r.outcome == "inconclusive"

    def test_struct_field_no_sites_inconclusive(self):
        from core.audit.sweep import run_struct_field_sweep

        r = run_struct_field_sweep(
            file_path="a.c", function_name="f",
            source=self._NO_SITES, cwe="CWE-120",
        )
        assert r.outcome == "inconclusive"

    def test_heap_copy_applied_negative_still_refutes(self):
        from core.audit.sweep import run_heap_copy_sweep

        src = (
            "int f(char *dst) {\n"
            "    char buf[64];\n"
            "    memcpy(buf, dst, 8);\n"
            "    return 0;\n"
            "}\n"
        )
        r = run_heap_copy_sweep(
            file_path="a.c", function_name="f", source=src,
            cwe="CWE-122",
        )
        assert r.outcome == "refuted"

    def test_integer_truncation_applied_negative_still_refutes(self):
        from core.audit.sweep import run_integer_truncation_sweep

        # A narrowing site exists (prerequisite matched) but never
        # reaches an allocation — applied and negative.
        src = (
            "void f(unsigned long n) {\n"
            "    unsigned short s = (unsigned short)n;\n"
            "    log_len(s);\n"
            "}\n"
        )
        r = run_integer_truncation_sweep(
            file_path="a.c", function_name="f", source=src,
            cwe="CWE-190",
        )
        assert r.outcome == "refuted"


class TestNegativeOutcomeHelper:
    def test_applicable_default_true(self):
        class R:
            pass
        assert _negative_outcome(R()) == "refuted"

    def test_inapplicable_maps_inconclusive(self):
        class R:
            applicable = False
        assert _negative_outcome(R()) == "inconclusive"

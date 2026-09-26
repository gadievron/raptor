"""Guard-predicate adjudication: SMT escalation grading, refutation,
and the hypothesis-check binding (census recompute, conforming-site
refutation, unformed-family fallback)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit.consistency_verify import (
    REASON_PREDICATE_FAMILY_UNFORMED,
    REFUTED_PATH_INFEASIBLE,
    REFUTED_PREDICATE_CONFORMS,
    RULE_GUARD_PREDICATE,
    guard_predicate_verdict,
    is_consistency_hypothesis,
    run_consistency_check,
    run_guard_predicate_check,
)
from core.audit.guard_predicate import (
    DIMENSION_GUARD_PREDICATE,
    KIND_MISSING_NULL_ARM,
    KIND_OFF_BY_ONE,
    KIND_SIGNEDNESS_MIX,
    KIND_WRONG_VARIABLE,
    REASON_PREDICATE_DATA_DEPENDENT,
    GuardPredicateDeviation,
)
from core.audit.peer_evidence import PeerEvidence, PeerExhibit
from core.testing import requires_ts


def _deviation(
    kind: str = KIND_OFF_BY_ONE,
    *,
    n: int = 10,
    conforming: int = 9,
    relop: str = "<=",
    majority_relop: str = "<",
    bound: str = "8",
    tested: str = "i",
) -> GuardPredicateDeviation:
    return GuardPredicateDeviation(
        kind=kind,
        group_key="a[i]",
        file="dev.c",
        line=4,
        enclosing_function="sum_d",
        n=n,
        conforming=conforming,
        majority_repr=f"{tested} {majority_relop} {bound}",
        deviant_repr=f"{tested} {relop} {bound}",
        tested_var=tested,
        relop=relop,
        majority_relop=majority_relop,
        bound_expr=bound,
        cwe="CWE-193",
        peer_evidence=PeerEvidence(
            dimension=DIMENSION_GUARD_PREDICATE,
            formation="loop_guard",
            group_key="a[i]",
            n=n,
            conforming=conforming,
            ratio=conforming / n,
            deviant=PeerExhibit("dev.c", 4, "for (i = 0; i <= 8; i++)"),
            contract_source="majority",
        ),
    )


class TestVerdictGrading:
    def test_boundary_witness_promotes_at_the_floor(self):
        # `i <= 8` where peers use `i < 8`: the admitted-but-excluded
        # value i == 8 is trivially satisfiable — a concrete witness.
        res = guard_predicate_verdict(_deviation())
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_GUARD_PREDICATE
        assert res.contract is not None
        assert res.contract["source"] == "smt_witness"
        assert res.peer_evidence.contract_source == "smt_witness"

    def test_below_promote_ratio_stays_detection_grade(self):
        res = guard_predicate_verdict(_deviation(n=4, conforming=3))
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:guard-predicate-majority"
        assert res.contract is None

    def test_symbolic_bound_stays_detection_grade(self):
        res = guard_predicate_verdict(_deviation(bound="n"))
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:guard-predicate-majority"
        assert "no SMT witness" in res.reason

    def test_wrong_variable_has_no_solver_partner(self):
        res = guard_predicate_verdict(
            _deviation(KIND_WRONG_VARIABLE, tested="j"),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == "consistency:guard-predicate-majority"

    def test_infeasible_refutes(self):
        res = guard_predicate_verdict(
            _deviation(),
            smt_check=lambda _d: SimpleNamespace(
                feasible=False, reasoning="unsat", witness=None,
            ),
        )
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_PATH_INFEASIBLE)

    def test_null_arm_promotes_on_injected_feasibility(self):
        res = guard_predicate_verdict(
            _deviation(KIND_MISSING_NULL_ARM),
            smt_check=lambda _d: SimpleNamespace(
                feasible=True, reasoning="sat", witness={"p": 0},
            ),
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_GUARD_PREDICATE

    def test_signedness_promotes_on_declared_unsigned(self):
        source = (
            "int sum_d(int *a, size_t n)\n"
            "{\n"
            "    size_t i = 0;\n"
            "    for (i = 0; i <= 1024; i++)\n"
            "        use(a[i]);\n"
            "    return 0;\n"
            "}\n"
        )
        res = guard_predicate_verdict(
            _deviation(
                KIND_SIGNEDNESS_MIX, bound="1024", relop="<=",
                majority_relop="<=",
            ),
            source_texts={"dev.c": source},
        )
        assert res.outcome == "confirmed"
        # The signed-mismatch checker needs the tree-sitter span; on
        # grammar-less runners the promote leg degrades to detection
        # grade — either way the verdict confirms and never guesses.
        assert res.rule_id in (
            RULE_GUARD_PREDICATE,
            "consistency:guard-predicate-majority",
        )


LOOP_FAMILY = (
    "int sum_a(int *a, int n)\n"
    "{\n"
    "    int i, t = 0;\n"
    "    for (i = 0; i < n; i++)\n"
    "        t += a[i];\n"
    "    return t;\n"
    "}\n"
    "int sum_b(int *a, int n)\n"
    "{\n"
    "    int i, t = 0;\n"
    "    for (i = 0; i < n; i++)\n"
    "        t += a[i];\n"
    "    return t;\n"
    "}\n"
    "int sum_c(int *a, int n)\n"
    "{\n"
    "    int i, t = 0;\n"
    "    for (i = 0; i < n; i++)\n"
    "        t += a[i];\n"
    "    return t;\n"
    "}\n"
    "int sum_d(int *a, int n)\n"
    "{\n"
    "    int i, t = 0;\n"
    "    for (i = 0; i <= n; i++)\n"
    "        t += a[i];\n"
    "    return t;\n"
    "}\n"
)

HYPOTHESIS = (
    "3/4 sibling loops bound i with < n; sum_d uses <= n"
)


@requires_ts("c")
class TestHypothesisCheck:
    def test_router_recognises_the_predicate_phrasing(self):
        assert is_consistency_hypothesis(HYPOTHESIS)

    def test_deviant_site_confirms(self, tmp_path: Path):
        res = run_guard_predicate_check(
            tmp_path, "loops.c", "sum_d", HYPOTHESIS,
            source_texts={"loops.c": LOOP_FAMILY},
        )
        assert res.outcome == "confirmed"
        assert res.dimension == DIMENSION_GUARD_PREDICATE
        assert res.peer_evidence is not None
        assert res.peer_evidence.n == 4

    def test_conforming_site_refutes(self, tmp_path: Path):
        res = run_guard_predicate_check(
            tmp_path, "loops.c", "sum_a", HYPOTHESIS,
            source_texts={"loops.c": LOOP_FAMILY},
        )
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_PREDICATE_CONFORMS)

    def test_skipped_group_never_refutes(self, tmp_path: Path):
        # Call-shaped bound: the group reaches the size floor but the
        # census SKIPS it without voting (predicate-data-dependent).
        # A drift claim over that group is UNADJUDICATED — refuting
        # it would quote a vote that never happened.
        family = "".join(
            f"int {nm}(int *a)\n{{\n    int i, t = 0;\n"
            f"    for (i = 0; i {op} get_n(); i++)\n"
            f"        t += a[i];\n    return t;\n}}\n"
            for nm, op in [
                ("s_a", "<"), ("s_b", "<"), ("s_c", "<"),
                ("s_d", "<="),
            ]
        )
        res = run_guard_predicate_check(
            tmp_path, "loops.c", "s_d",
            "3/4 sibling loops bound i with < get_n(); s_d uses <=",
            source_texts={"loops.c": family},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_PREDICATE_DATA_DEPENDENT)

    def test_other_loop_vote_never_answers_for_the_claim(
        self, tmp_path: Path,
    ):
        # The claimed drift is in the function's SECOND loop, whose
        # family is unformed; its FIRST loop conforms inside a voted
        # group.  The voted loop must not answer for the claimed one.
        family = "".join(
            f"int {nm}(int *a, int n)\n{{\n    int i, t = 0;\n"
            "    for (i = 0; i < n; i++)\n        t += a[i];\n"
            "    return t;\n}\n"
            for nm in ("t_a", "t_b", "t_c")
        ) + (
            "int t_d(int *a, int n, int m)\n{\n    int i, j, t = 0;\n"
            "    for (i = 0; i < n; i++)\n        t += a[i];\n"
            "    for (j = 0; j <= m; j++)\n        t += a[j];\n"
            "    return t;\n}\n"
        )
        res = run_guard_predicate_check(
            tmp_path, "loops.c", "t_d",
            "the other loops guard with j < m; t_d's second loop "
            "uses <= m",
            source_texts={"loops.c": family},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_PREDICATE_FAMILY_UNFORMED)

    def test_unformed_family_is_enumerated(self, tmp_path: Path):
        two = "".join(LOOP_FAMILY.split("int sum_c")[0:1])
        res = run_guard_predicate_check(
            tmp_path, "loops.c", "sum_a", HYPOTHESIS,
            source_texts={"loops.c": two.replace("sum_b", "zzz_b")},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_PREDICATE_FAMILY_UNFORMED)

    def test_run_consistency_check_routes_and_returns(
        self, tmp_path: Path,
    ):
        res = run_consistency_check(
            tmp_path, "loops.c", "sum_d", HYPOTHESIS,
            source_texts={"loops.c": LOOP_FAMILY},
        )
        assert res.dimension == DIMENSION_GUARD_PREDICATE
        assert res.outcome == "confirmed"

    def test_unformed_family_falls_back_to_the_census(
        self, tmp_path: Path,
    ):
        # Two-member family: the predicate detour answers unformed
        # and the return census gets its normal shot (which cannot
        # bind either — the point is that the detour did not eat it).
        two = (
            "int sum_a(int *a, int n)\n"
            "{\n"
            "    int i, t = 0;\n"
            "    for (i = 0; i < n; i++)\n"
            "        t += a[i];\n"
            "    return t;\n"
            "}\n"
            "int sum_d(int *a, int n)\n"
            "{\n"
            "    int i, t = 0;\n"
            "    for (i = 0; i <= n; i++)\n"
            "        t += a[i];\n"
            "    return t;\n"
            "}\n"
        )
        res = run_consistency_check(
            tmp_path, "loops.c", "sum_d", HYPOTHESIS,
            source_texts={"loops.c": two},
        )
        assert res.outcome == "inconclusive"
        assert not res.reason.startswith(
            REASON_PREDICATE_FAMILY_UNFORMED,
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

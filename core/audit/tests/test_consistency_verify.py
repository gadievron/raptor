"""Consistency verification channel — return-check dimension (§2.3).

Hermetic fixture pairs throughout: the deviant form must confirm with
full PeerEvidence receipts; the conforming / acknowledged twin must
refute or demote with the exact enumerated reason string.

The channel adjudicates over the return census, which has two
extraction tiers (tree-sitter / regex fallback). The tests that
historically flipped between tiers — peer counts inflated by header
prototypes, function binding collapsing to ``<module>`` — are
parametrised over ``parser_tier`` so both contracts stay pinned:
identical verdicts and receipts on both tiers, except the error-path
demotion, which needs a tree (the fallback has no error-path walk).
"""

from __future__ import annotations

import textwrap

import pytest

from core.audit.callsite_consistency import build_return_census
from core.audit.consistency_verify import (
    REASON_CONTRACT_UNRESOLVED,
    REASON_DEVIANT_ON_ERROR_PATH,
    REASON_GROUP_TOO_SMALL,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_PYTHON_EXCEPTION_SEMANTICS,
    REFUTED_ACKNOWLEDGED,
    REFUTED_DISCARD_OK,
    REFUTED_SITE_CHECKS,
    REFUTED_VOID_CALLEE,
    RULE_RETURN_CHECK,
    RULE_RETURN_CHECK_MAJORITY,
    census_verdict,
    consistency_applicable,
    is_consistency_hypothesis,
    run_consistency_check,
)
from core.audit.fail_open_roles import RoleContext
from core.testing import force_census_regex_fallback, ts_parser_available


@pytest.fixture(params=["tree-sitter", "regex-fallback"])
def parser_tier(request, monkeypatch):
    """Adjudicate over both census extraction tiers."""
    if request.param == "regex-fallback":
        force_census_regex_fallback(monkeypatch)
    return request.param


def _tier(parser_tier: str, *langs: str) -> str:
    if parser_tier == "tree-sitter":
        missing = [lang for lang in langs if not ts_parser_available(lang)]
        if missing:
            pytest.skip(
                "no tree-sitter grammar for: " + ", ".join(missing),
            )
        return "ts"
    return "rx"


def _fixture(checked: int, unchecked: int = 1, *,
             callee: str = "do_auth", ack: int = 0) -> dict[str, str]:
    parts = []
    for i in range(checked):
        parts.append(
            f"int c{i}(void) {{\n"
            f"    if ({callee}() != 0)\n"
            f"        return -1;\n"
            f"    return 0;\n}}\n"
        )
    for i in range(unchecked):
        parts.append(
            f"int u{i}(void) {{\n    {callee}();\n    return 0;\n}}\n"
        )
    for i in range(ack):
        parts.append(
            f"int a{i}(void) {{\n    (void){callee}();\n"
            f"    return 0;\n}}\n"
        )
    return {"src/callers.c": "\n".join(parts)}


def _verdict(texts, callee, *, ctx=None, inventory=None):
    census = build_return_census(texts)
    entry = census[callee]
    deviant = entry.deviants[0] if entry.deviants else \
        entry.acknowledged_sites[0]
    return census_verdict(
        entry, deviant, context=ctx or RoleContext(),
        inventory=inventory, source_texts=texts,
    )


class TestHypothesisClassifier:
    def test_ratio_phrasing_dispatches(self):
        assert is_consistency_hypothesis(
            "9/10 callers check the return value of do_auth()",
        )

    def test_other_sites_phrasing_dispatches(self):
        assert is_consistency_hypothesis(
            "other call sites check the return value of `do_auth()`; "
            "this one discards it",
        )

    def test_peers_phrasing_dispatches(self):
        assert is_consistency_hypothesis(
            "this handler is inconsistent with its peers",
        )
        assert is_consistency_hypothesis(
            "handle_delta deviates from the majority convention",
        )

    def test_plain_overflow_claim_does_not_dispatch(self):
        assert not is_consistency_hypothesis(
            "unchecked memcpy overflow of the destination buffer",
        )

    def test_plain_ignored_return_does_not_dispatch(self):
        """Role-bound / bare unchecked-return phrasing is fail_open
        territory (CWE-252 premise split) — no majority claim, no
        consistency dispatch."""
        assert not is_consistency_hypothesis(
            "the return value of setuid is ignored",
        )

    def test_cwe_family(self):
        assert consistency_applicable("CWE-252")
        assert consistency_applicable("467")
        assert not consistency_applicable("CWE-79")


class TestRegistryContractPath:
    def test_wur_contract_confirms_promote_capable(self, parser_tier):
        # Regression (both tiers): the fallback used to count the
        # header prototype below as an 11th, DISCARDED call site —
        # a phantom deviant inflating the peer receipts.
        _tier(parser_tier, "c")
        texts = _fixture(9, 1)
        texts["include/api.h"] = (
            "__attribute__((warn_unused_result)) int do_auth(void);\n"
        )
        ctx = RoleContext(wur_functions=frozenset({"do_auth"}))
        res = _verdict(texts, "do_auth", ctx=ctx)
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK
        pe = res.peer_evidence
        assert pe is not None
        assert pe.n == 10
        assert pe.conforming == 9
        assert pe.ratio == pytest.approx(0.9)
        assert pe.contract_source == "wur"
        assert pe.deviant is not None and pe.deviant.line > 0
        assert len(pe.exhibits) == 3
        assert all(e.snippet for e in pe.exhibits)
        assert res.contract["grade"] == "registry"

    def test_wur_contract_accepts_single_site(self):
        """Registry path accepts n >= 1: wur alone is a contract; the
        majority exhibit is corroboration, not premise (§2.3)."""
        texts = _fixture(0, 1)
        ctx = RoleContext(wur_functions=frozenset({"do_auth"}))
        res = _verdict(texts, "do_auth", ctx=ctx)
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK

    def test_tier_a_contract_confirms(self):
        texts = {
            "src/priv.c": textwrap.dedent("""\
                int drop(void) {
                    setuid(1000);
                    return 0;
                }
            """),
        }
        res = _verdict(texts, "setuid")
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK
        assert res.peer_evidence.contract_source == "tier_a"


class TestMajorityPath:
    def test_majority_only_is_detection_grade(self):
        res = _verdict(_fixture(9, 1, callee="frobnicate"), "frobnicate")
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK_MAJORITY
        assert res.peer_evidence.contract_source == "majority"

    def test_group_too_small(self):
        res = _verdict(_fixture(2, 1, callee="frobnicate"), "frobnicate")
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_GROUP_TOO_SMALL)

    def test_ratio_below_threshold_without_contract(self):
        res = _verdict(_fixture(5, 3, callee="frobnicate"), "frobnicate")
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_CONTRACT_UNRESOLVED)

    def test_python_exception_semantics(self):
        parts = []
        for i in range(4):
            parts.append(
                f"def c{i}():\n    x{i} = frobnicate()\n"
                f"    consume(x{i})\n"
            )
        parts.append("def u0():\n    frobnicate()\n")
        res = _verdict({"app.py": "\n".join(parts)}, "frobnicate")
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_PYTHON_EXCEPTION_SEMANTICS)


class TestRefutationsAndDemotions:
    def test_acknowledged_refutes_majority_leg(self):
        texts = _fixture(9, 0, ack=1, callee="frobnicate")
        res = _verdict(texts, "frobnicate")
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_ACKNOWLEDGED)
        assert res.fail_open_handoff is False

    def test_acknowledged_security_role_hands_to_fail_open(self):
        """An acknowledged discard of setuid is fail-open territory —
        role machinery, not contract machinery (§2.3)."""
        texts = _fixture(9, 0, ack=1, callee="setuid")
        res = _verdict(texts, "setuid")
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_ACKNOWLEDGED)
        assert res.fail_open_handoff is True

    def test_majority_discard_convention_refutes(self):
        res = _verdict(_fixture(0, 5, callee="log_line"), "log_line")
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_DISCARD_OK)

    def test_void_callee_refutes(self):
        texts = _fixture(9, 1, callee="notify_all")
        texts["include/api.h"] = "void notify_all(void);\n"
        res = _verdict(texts, "notify_all")
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_VOID_CALLEE)

    def test_deviant_on_error_path_is_inconclusive(self, parser_tier):
        tier = _tier(parser_tier, "python")
        parts = []
        for i in range(9):
            parts.append(
                f"def c{i}():\n"
                f"    if not release_slot():\n"
                f"        return False\n"
                f"    return True\n"
            )
        parts.append(textwrap.dedent("""\
            def u0():
                try:
                    step()
                except ValueError:
                    release_slot()
        """))
        res = _verdict({"app.py": "\n".join(parts)}, "release_slot")
        if tier == "ts":
            assert res.outcome == "inconclusive"
            assert res.reason.startswith(REASON_DEVIANT_ON_ERROR_PATH)
        else:
            # Fallback contract: no error-path walk without a tree —
            # the demotion cannot fire, so the majority evidence
            # confirms. Grammar-less hosts trade this refinement away.
            assert res.outcome == "confirmed"


class TestHypothesisAdjudication:
    def _tree(self, tmp_path, *, wur: bool):
        texts = _fixture(9, 1)
        if wur:
            texts["include/api.h"] = (
                "__attribute__((warn_unused_result)) "
                "int do_auth(void);\n"
            )
        for rel, content in texts.items():
            p = tmp_path / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content)
        return tmp_path

    def test_end_to_end_confirms_with_receipts(self, tmp_path, parser_tier):
        _tier(parser_tier, "c")
        target = self._tree(tmp_path, wur=True)
        res = run_consistency_check(
            target, "src/callers.c", "u0",
            "9/10 other call sites check the return value of "
            "`do_auth()`; u0 discards it",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK
        assert res.peer_evidence.contract_source == "wur"
        d = res.to_dict()
        assert d["peer_evidence"]["n"] == 10

    def test_end_to_end_majority_only_without_contract(self, tmp_path):
        target = self._tree(tmp_path, wur=False)
        res = run_consistency_check(
            target, "src/callers.c", "u0",
            "9/10 other call sites check the return value of "
            "`do_auth()`; u0 discards it",
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_RETURN_CHECK_MAJORITY

    def test_claim_refuted_when_function_checks(self, tmp_path, parser_tier):
        # Function-precise binding: needs the enclosing function of
        # each site, which the fallback's C header tracking now
        # supplies too (it used to collapse every site to <module>).
        _tier(parser_tier, "c")
        target = self._tree(tmp_path, wur=True)
        res = run_consistency_check(
            target, "src/callers.c", "c0",
            "9/10 other call sites check the return value of "
            "`do_auth()`; c0 discards it",
        )
        assert res.outcome == "refuted"
        assert res.reason.startswith(REFUTED_SITE_CHECKS)

    def test_unbindable_hypothesis(self, tmp_path):
        target = self._tree(tmp_path, wur=False)
        res = run_consistency_check(
            target, "src/callers.c", "u0",
            "9/10 callers behave differently somehow",
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HYPOTHESIS_UNBINDABLE)

    def test_arithmetic_recomputed_not_trusted(self, tmp_path, parser_tier):
        """A hypothesis over-claiming the majority (99/100) still gets
        the recomputed 9/10 receipt — the channel verifies arithmetic."""
        _tier(parser_tier, "c")
        target = self._tree(tmp_path, wur=True)
        res = run_consistency_check(
            target, "src/callers.c", "u0",
            "99/100 callers check `do_auth()`; this one does not",
        )
        assert res.outcome == "confirmed"
        assert res.peer_evidence.n == 10
        assert res.peer_evidence.conforming == 9

"""SMT invariant-preservation harness.

Observed field failure: invariant-shaped refutations (e.g.
``obuf_len <= obuf_size`` in linebuffer_write) had taint flows
confirmed by joern but NO channel able to check the invariant itself
— 2 smt inconclusive + 2 precondition promotions inconclusive, verdict
stuck at suspicious/tool_backed forever. The harness encodes one
inductive preservation step per mutation site and returns
sat (violable, model receipt) / unsat (preserved) / unknown
(inconclusive-with-reason). Hermetic — in-process z3 only.
"""

from __future__ import annotations

import pytest

from core.audit.invariant_smt import (
    check_invariant_preservation,
    extract_invariants,
    find_mutation_sites,
)

z3 = pytest.importorskip("z3")


class TestExtractInvariants:
    def test_extracts_member_comparison_from_prose(self):
        invs = extract_invariants(
            "the write is safe because the invariant "
            "obuf_len <= obuf_size holds at every mutation",
        )
        assert "obuf_len <= obuf_size" in invs

    def test_extracts_min_clamp_shapes(self):
        invs = extract_invariants(
            "copy length is clamped: n <= min(avail, sizeof(snp))",
        )
        assert any("min(" in i and "sizeof" in i for i in invs)

    def test_struct_member_chains(self):
        invs = extract_invariants("b->num <= ctx->limit always")
        assert "b->num <= ctx->limit" in invs

    def test_no_invariant_in_plain_prose(self):
        assert extract_invariants(
            "the function reads a message from the socket",
        ) == []

    def test_constant_only_comparison_is_not_an_invariant(self):
        assert extract_invariants("returns 0 when 1 < 2") == []


class TestFindMutationSites:
    SRC = (
        "static int f(CTX *c, int n) {\n"
        "    if (obuf_len <= obuf_size) return 0;   /* compare, not write */\n"
        "    obuf_len = 0;\n"
        "    obuf_len += n;\n"
        "    obuf_len++;\n"
        "    other = obuf_len;   /* read, not a mutation */\n"
        "}\n"
    )

    def test_finds_assignments_and_increments(self):
        sites = find_mutation_sites(self.SRC, {"obuf_len", "obuf_size"})
        lines = sorted(s[0] for s in sites)
        assert lines == [3, 4, 5]

    def test_comparisons_are_not_mutations(self):
        sites = find_mutation_sites(
            "if (a <= b) { x = a == b; }", {"a", "b"},
        )
        assert sites == []


class TestPreservation:
    def test_clamped_writes_preserve_invariant(self):
        # The linebuffer shape: every mutation keeps len <= size.
        src = (
            "len = 0;\n"
            "len = min(n, size);\n"
        )
        res = check_invariant_preservation("len <= size", src)
        assert res.outcome == "preserved", res.to_dict()
        # The reset site (len = 0) is preserved in the non-negative
        # regime and carries its negative-operand counterexample as a
        # receipt; the clamped site is preserved unconditionally.
        assert all(
            s.verdict in ("preserved", "preserved_nonneg")
            for s in res.sites
        )
        clamped = [s for s in res.sites if "min" in s.code]
        assert clamped and clamped[0].verdict == "preserved"

    def test_unclamped_increment_is_violable_with_model(self):
        src = "len += n;\n"
        res = check_invariant_preservation("len <= size", src)
        assert res.outcome == "violable", res.to_dict()
        violable = [s for s in res.sites if s.verdict == "violable"]
        assert violable and violable[0].model, (
            "a sat verdict must carry the violating model as receipt"
        )
        m = violable[0].model
        # The model really is a counterexample: len<=size before,
        # len' = len + n breaks it after.
        assert m["len"] <= m["size"]
        assert m["len'"] == m["len"] + m["n"]
        assert m["len'"] > m["size"]

    def test_plusplus_can_violate(self):
        res = check_invariant_preservation("len <= size", "len++;\n")
        assert res.outcome == "violable"

    def test_constant_reset_preserves_lower_bound(self):
        res = check_invariant_preservation("len >= 0", "len = 0;\n")
        assert res.outcome == "preserved"

    def test_no_mutation_sites_is_vacuously_preserved(self):
        res = check_invariant_preservation(
            "len <= size", "return len + size;\n",
        )
        assert res.outcome == "preserved"
        assert "no mutation sites" in res.reason

    def test_sizeof_bound_preserved(self):
        src = "n = min(n, sizeof(snp));\n"
        res = check_invariant_preservation("n <= sizeof(snp)", src)
        assert res.outcome == "preserved", res.to_dict()

    def test_out_of_scope_rhs_is_inconclusive_not_guessed(self):
        # Pointer dereference in the RHS: heap reasoning is declared
        # out of scope rather than approximated.
        src = "len = *ptr;\n"
        res = check_invariant_preservation("len <= size", src)
        assert res.outcome == "inconclusive"
        assert any(s.verdict == "out_of_scope" for s in res.sites)
        assert res.reason

    def test_unparseable_invariant_is_inconclusive(self):
        res = check_invariant_preservation(
            "buf[i] < end", "i = 0;\n",
        )
        assert res.outcome == "inconclusive"
        assert "linear fragment" in res.reason

    def test_degrades_without_z3(self, monkeypatch):
        import core.audit.invariant_smt as mod

        monkeypatch.setattr(mod, "_z3_available", lambda: False)
        res = check_invariant_preservation("len <= size", "len += 1;\n")
        assert res.outcome == "inconclusive"
        assert "z3 unavailable" in res.reason


class TestDispatchWiring:
    def test_chain_builder_emits_invariant_step(self):
        from core.audit.orchestrator import _hypothesis_to_tool_chain

        chain = _hypothesis_to_tool_chain(
            "write stays in bounds because obuf_len <= obuf_size is "
            "maintained by every mutation",
            "crypto/bio/bf_lbuf.c",
        )
        steps = [e for e in chain if e["type"] == "smt_invariant"]
        assert steps, "invariant-shaped hypotheses must dispatch the harness"
        assert steps[0]["config"]["invariant"] == "obuf_len <= obuf_size"

    def test_tool_chain_confirms_violable_invariant(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            TierCounters,
            _run_tool_chain,
        )

        counters = {"smt_invariant": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "smt_invariant",
              "config": {"invariant": "len <= size"}}],
            config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
            file_path="a.c",
            function_name="f",
            source="len += n;\n",
            hypothesis="len can exceed size",
            tier_counters=counters,
        )
        assert confirmed == ["smt:invariant-preservation"]
        assert counters["smt_invariant"].confirmed == 1

    def test_tool_chain_refutes_preserved_invariant(self, tmp_path):
        from core.audit.orchestrator import (
            OrchestratorConfig,
            TierCounters,
            _run_tool_chain,
        )

        counters = {"smt_invariant": TierCounters()}
        confirmed = _run_tool_chain(
            [{"type": "smt_invariant",
              "config": {"invariant": "len <= size"}}],
            config=OrchestratorConfig(target_path=tmp_path, out_dir=None),
            file_path="a.c",
            function_name="f",
            source="len = min(n, size);\n",
            hypothesis="len can exceed size",
            tier_counters=counters,
        )
        assert confirmed == []
        assert counters["smt_invariant"].refuted == 1

    def test_confirmation_is_detection_role(self):
        from core.audit.orchestrator import _is_detection_only

        assert _is_detection_only("smt:invariant-preservation"), (
            "a single-site violability model must not promote without "
            "LLM agreement (graduated rule roles)"
        )

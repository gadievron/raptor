"""Protocol-state channel tests (design §4.7) — hermetic. The honesty
gate is the point: only study-receipted invariants with a peer-write
witness confirm at registry grade; everything else is detection-grade
or an enumerated inconclusive."""

from __future__ import annotations

import sys

import pytest

from core.audit.protocol_state import (
    DEAD_STATE_LEAD_CWE,
    INCONCLUSIVE_REASONS,
    PROTOCOL_STATE_CWES,
    REASON_AUTHORITY_UNRESOLVED,
    REASON_CENSUS_DEGRADED,
    REASON_HYPOTHESIS_UNBINDABLE,
    REASON_INVARIANT_OUT_OF_SCOPE,
    REASON_INVARIANT_UNSTATED,
    REASON_Z3_UNAVAILABLE,
    RULE_DEAD_STATE,
    RULE_INVARIANT_UNRECEIPTED,
    RULE_INVARIANT_VIOLATED,
    RULE_PEER_WRITE,
    build_state_field_index,
    classify_protocol_state_hypothesis,
    is_detection_rule_id,
    is_protocol_state_hypothesis,
    learned_state_fields,
    protocol_state_applicable,
    run_protocol_state_check,
    run_protocol_state_prepass,
)

pytest.importorskip("tree_sitter_c", reason="CFG guard leg needs tree-sitter")
pytest.importorskip("z3", reason="leg 3 needs z3")

INVARIANT = "largest_acked_pkt <= highest_sent"
HYP_INVARIANT = (
    "the protocol invariant largest_acked_pkt <= highest_sent can be "
    "violated: the peer can acknowledge packets never sent"
)
HYP_WRITE_ONLY = (
    "`largest_acked_pkt` is assigned straight from the decoded ACK "
    "frame with no validation"
)

# ACK-of-unsent shape (harness class anchor CVE-2019-11477 — TCP SACK
# state-invariant violation): peer-decoded write with no sibling-field
# guard; highest_sent written twice, read never.
ACKM = """\
void ackm_on_pkt_sent(struct ackm *st, uint64_t pkt)
{
    st->highest_sent = pkt;
}

void ackm_note_resent(struct ackm *st, uint64_t pkt)
{
    st->highest_sent = pkt;
}

void ackm_on_ack(struct ackm *st, const unsigned char *frame)
{
    uint64_t v = decode_ack_largest(frame);
    st->largest_acked_pkt = v;
}

uint64_t ackm_get_largest(struct ackm *st)
{
    return st->largest_acked_pkt;
}
"""

# Twin: every write validated against the sibling field.
ACKM_TWIN = """\
void ackm_on_pkt_sent(struct ackm *st, uint64_t pkt)
{
    if (pkt >= st->highest_sent)
        st->highest_sent = pkt;
}

void ackm_on_ack(struct ackm *st, const unsigned char *frame)
{
    uint64_t v = decode_ack_largest(frame);
    if (v <= st->highest_sent)
        st->largest_acked_pkt = v;
}

uint64_t ackm_get_largest(struct ackm *st)
{
    return st->largest_acked_pkt;
}
"""

NONLINEAR_SRC = """\
void update_rate(struct st *st, int r)
{
    st->x_state = r;
}
"""

RECEIPTED_DM = {
    "invariants": [{
        "id": "inv-ack-window",
        "statement": "largest_acked_pkt <= highest_sent",
        "negation": "largest_acked_pkt > highest_sent",
        "provenance": "verbatim",
        "receipt": {"file": "rfc-notes.md", "quote": "an endpoint MUST "
                    "NOT acknowledge packets it never received"},
    }],
}

LLM_STATED_DM = {
    "invariants": [{
        "id": "inv-ack-window",
        "statement": "largest_acked_pkt <= highest_sent",
        "negation": "largest_acked_pkt > highest_sent",
        "provenance": "llm_prior",
        "receipt": None,
    }],
}

TEXTS = {"src/ackm.c": ACKM}
TWIN_TEXTS = {"src/ackm.c": ACKM_TWIN}


class TestClassifier:
    def test_prose_shapes(self):
        for text in (
            "the peer controls the congestion state counter",
            "acknowledges packets never sent",
            "protocol invariant violation in the ACK handler",
            "sequence number accepted out of window",
        ):
            assert is_protocol_state_hypothesis(text), text

    def test_state_field_invariant_routes_here(self):
        fires, inv = classify_protocol_state_hypothesis(HYP_INVARIANT)
        assert fires
        assert inv == INVARIANT

    def test_local_buffer_invariant_does_not_route_here(self):
        # §4.7 precedence pair: plain local invariant stays with the
        # single-function smt_invariant chain.
        fires, inv = classify_protocol_state_hypothesis(
            "the buffer maintains obuf_len <= obuf_size at all times",
        )
        assert inv is None
        assert not fires

    def test_negative_dispatch(self):
        assert not is_protocol_state_hypothesis(
            "unchecked memcpy overflow of `dst`",
        )
        assert not is_protocol_state_hypothesis(
            "the session list grows without limit",
        )

    def test_cwe(self):
        assert PROTOCOL_STATE_CWES == {"CWE-372"}
        assert protocol_state_applicable("CWE-372")
        assert not protocol_state_applicable("CWE-563")  # lead-only

    def test_detection_rule_ids(self):
        assert is_detection_rule_id(RULE_DEAD_STATE)
        assert is_detection_rule_id(RULE_PEER_WRITE)
        assert is_detection_rule_id(RULE_INVARIANT_UNRECEIPTED)
        assert not is_detection_rule_id(RULE_INVARIANT_VIOLATED)


class TestFieldIndex:
    def test_write_read_split_and_rhs_provenance(self):
        index = build_state_field_index(TEXTS)
        fields = index["fields"]
        hs = fields["highest_sent"]
        assert len(hs["writes"]) == 2
        assert hs["reads"] == []
        la = fields["largest_acked_pkt"]
        assert len(la["writes"]) == 1
        assert len(la["reads"]) == 1
        assert la["writes"][0]["rhs_class"] == "from_local:v"
        assert la["writes"][0]["function"] == "ackm_on_ack"

    def test_multi_level_chain_write_censused_on_terminal_field(self):
        # `conn->pktns->largest_acked = ...` writes the TERMINAL field;
        # a pairwise scan saw only `conn->pktns` and censused the write
        # as a read of the middle segment, leaving the written field
        # with zero write sites.
        src = (
            "void on_ack(struct conn *conn, uint64_t v)\n"
            "{\n"
            "    conn->pktns->largest_acked = v;\n"
            "}\n"
        )
        fields = build_state_field_index({"src/c.c": src})["fields"]
        la = fields["largest_acked"]
        assert len(la["writes"]) == 1
        assert la["writes"][0]["base"] == "pktns"
        assert la["reads"] == []
        # The middle segment is dereferenced — a read, never a write.
        pk = fields["pktns"]
        assert pk["writes"] == []
        assert len(pk["reads"]) == 1

    def test_multiplicative_compound_assignments_are_writes(self):
        src = (
            "void adjust(struct cc *cc)\n"
            "{\n"
            "    cc->cwnd *= 2;\n"
            "    cc->rate /= 4;\n"
            "    cc->slot %= 8;\n"
            "}\n"
        )
        fields = build_state_field_index({"src/cc.c": src})["fields"]
        for name in ("cwnd", "rate", "slot"):
            bucket = fields[name]
            assert len(bucket["writes"]) == 1, name
            # Compound assignment reads the field too.
            assert len(bucket["reads"]) == 1, name

    def test_prefix_and_postfix_incdec_are_writes(self):
        src = (
            "void bump(struct s *st)\n"
            "{\n"
            "    ++st->pkt_count;\n"
            "    st->ack_count++;\n"
            "    --st->window;\n"
            "}\n"
        )
        fields = build_state_field_index({"src/s.c": src})["fields"]
        for name in ("pkt_count", "ack_count", "window"):
            bucket = fields[name]
            assert len(bucket["writes"]) == 1, name
            assert bucket["writes"][0]["rhs_class"] == "unknown"
            assert len(bucket["reads"]) == 1, name

    def test_comparisons_are_not_writes(self):
        src = (
            "int chk(struct s *st, uint64_t v)\n"
            "{\n"
            "    if (st->limit != v) return 0;\n"
            "    return st->limit <= v && st->limit >= 1;\n"
            "}\n"
        )
        fields = build_state_field_index({"src/s.c": src})["fields"]
        assert fields["limit"]["writes"] == []

    def test_state_fields_vocab_excludes_llm_prior(self):
        dm = {"state_fields": [
            {"field": "highest_sent", "authority": "local",
             "provenance": "mechanical"},
            {"field": "bad", "authority": "peer",
             "provenance": "llm_prior"},
        ]}
        vocab = learned_state_fields(dm)
        assert set(vocab) == {"highest_sent"}


class TestLeads:
    def test_ack_of_unsent_both_leads_with_receipts(self, tmp_path):
        out = run_protocol_state_prepass(TEXTS, out_dir=tmp_path)
        by_rule = {}
        for lead in out["leads"]:
            by_rule.setdefault(lead["rule_id"], []).append(lead)
        dead = by_rule[RULE_DEAD_STATE]
        assert any(ld["field"] == "highest_sent" for ld in dead)
        assert dead[0]["cwe"] == DEAD_STATE_LEAD_CWE
        assert "read nowhere" in dead[0]["description"]
        peer = by_rule[RULE_PEER_WRITE]
        assert peer[0]["field"] == "largest_acked_pkt"
        receipts = peer[0]["receipts"]
        assert "decode_ack_largest" in receipts["source_chain"]
        assert receipts["guard_conjunction"] == []
        assert "highest_sent" in receipts["sibling_fields"]
        # The lead exists to make the LLM form the hypothesis.
        assert "protocol invariant" in peer[0]["mechanism"]
        assert (tmp_path / "protocol-state.json").is_file()

    def test_twin_produces_no_leads(self, tmp_path):
        out = run_protocol_state_prepass(TWIN_TEXTS, out_dir=tmp_path)
        assert out["leads"] == []

    def test_lead_legs_share_one_namespace_firewall(self):
        # Two protocol_state leads can never satisfy the two-
        # independent-namespaces aggregation rule by themselves.
        from core.audit.orchestrator import (
            _aggregate_channel_confirmations,
        )
        channels, _mean = _aggregate_channel_confirmations(
            [RULE_DEAD_STATE, RULE_PEER_WRITE],
        )
        assert channels == []


class TestBranchGuards:
    def test_fall_through_join_records_no_guard(self):
        # The write site is a JOIN reached both around the branch and
        # through it — the branch edge's polarity constrains nothing
        # there.  Recording the negated condition as a dominating
        # guard let a vacuously-guarded preservation proof refute the
        # flagship ACK-of-unsent shape.
        from core.audit.protocol_state import _branch_guards
        src = (
            "void f(struct s *st, uint64_t v)\n"
            "{\n"
            "    if (st->mode > 0) {\n"
            "        st->aux = v;\n"
            "    }\n"
            "    st->largest_acked_pkt = v;\n"
            "}\n"
        )
        assert _branch_guards(src, "f", 6) == []

    def test_dominating_guard_still_recorded(self):
        # Control: a write genuinely inside the guarded branch keeps
        # its condition.
        from core.audit.protocol_state import _branch_guards
        src = (
            "void g(struct s *st, uint64_t v)\n"
            "{\n"
            "    if (v >= st->highest_sent) {\n"
            "        st->largest_acked_pkt = v;\n"
            "    }\n"
            "}\n"
        )
        guards = _branch_guards(src, "g", 4)
        assert guards and any("highest_sent" in g for g in guards)


class TestTruncatedCensus:
    def test_all_sites_skipped_on_budget_is_not_preserved(self):
        # With every site skipped on budget, per_site is empty and the
        # vacuous "all 0 sites preserve" read became an authoritative
        # refutation.  A truncated census must degrade.
        from core.audit.protocol_state import (
            build_state_field_index,
            check_invariant_multi_site,
        )
        index = build_state_field_index(TWIN_TEXTS)
        multi = check_invariant_multi_site(
            INVARIANT, index, TWIN_TEXTS, budget_s=0.0,
        )
        assert multi["outcome"] == "inconclusive"
        assert "partial census" in multi["reason"]

    def test_site_cap_truncation_is_not_preserved(self):
        # Every CHECKED site preserves, but the cap left sites
        # unchecked — bounded evidence, not a preservation proof.
        from core.audit.protocol_state import (
            build_state_field_index,
            check_invariant_multi_site,
        )
        index = build_state_field_index(TWIN_TEXTS)
        multi = check_invariant_multi_site(
            INVARIANT, index, TWIN_TEXTS, max_sites=1,
        )
        assert multi["outcome"] == "inconclusive"
        assert "partial census" in multi["reason"]

    def test_full_census_still_preserves(self):
        # Control: the untruncated twin keeps its preservation proof.
        from core.audit.protocol_state import (
            build_state_field_index,
            check_invariant_multi_site,
        )
        index = build_state_field_index(TWIN_TEXTS)
        multi = check_invariant_multi_site(INVARIANT, index, TWIN_TEXTS)
        assert multi["outcome"] == "preserved"


class TestVacuousCensus:
    def test_vacuous_preserved_is_inconclusive_not_refuted(self):
        # Zero census write sites for the invariant's variables is
        # bounded negative evidence (the regex census can be blind) —
        # it must degrade to inconclusive, never mint an authoritative
        # refutation.
        src = (
            "uint64_t get_foo(struct s *st)\n"
            "{\n"
            "    return st->foo_state;\n"
            "}\n"
        )
        res = run_protocol_state_check(
            ".", "src/v.c", "get_foo", "state invariant broken",
            invariant="foo_state <= bar_sent",
            source_texts={"src/v.c": src},
        )
        assert res.outcome == "inconclusive"
        assert REASON_CENSUS_DEGRADED in res.reason


class TestInvariantHarness:
    def test_receipted_violable_registry_confirm_with_model(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_INVARIANT,
            domain_model=RECEIPTED_DM, source_texts=TEXTS,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_INVARIANT_VIOLATED
        assert not is_detection_rule_id(res.rule_id)
        inv = res.invariant
        assert inv["provenance"] == "verbatim"
        assert inv["receipt"]["quote"].startswith("an endpoint")
        violable = [s for s in inv["per_site"]
                    if s["verdict"] == "violable"]
        assert violable and violable[0]["model"]
        assert res.peer_write is not None
        assert "decode_ack_largest" in res.peer_write["source_chain"]

    def test_preserved_twin_refuted_per_site(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_INVARIANT,
            domain_model=RECEIPTED_DM, source_texts=TWIN_TEXTS,
        )
        assert res.outcome == "refuted"
        sites = res.invariant["per_site"]
        assert sites
        assert all(
            s["verdict"] in ("preserved", "preserved_nonneg")
            for s in sites
        )
        # The dominating guards were encoded, not assumed away.
        assert any(s["guards_applied"] for s in sites)

    def test_llm_stated_invariant_is_unreceipted_variant(self):
        # THE honesty gate: same violable arithmetic, but the premise
        # is an uncorroborated LLM claim — detection variant only.
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_INVARIANT,
            domain_model=LLM_STATED_DM, source_texts=TEXTS,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_INVARIANT_UNRECEIPTED
        assert is_detection_rule_id(res.rule_id)
        assert "LLM-stated" in res.reason
        assert res.invariant["provenance"] == "llm_stated"
        assert res.invariant["receipt"] is None

    def test_nonlinear_invariant_out_of_scope(self):
        res = run_protocol_state_check(
            ".", "src/st.c", "update_rate", "state invariant broken",
            invariant="x_state * y_state <= z_sent",
            source_texts={"src/st.c": NONLINEAR_SRC},
        )
        assert res.outcome == "inconclusive"
        assert REASON_INVARIANT_OUT_OF_SCOPE in res.reason

    def test_missing_z3_degrades(self, monkeypatch):
        monkeypatch.setitem(sys.modules, "z3", None)
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_INVARIANT,
            domain_model=RECEIPTED_DM, source_texts=TEXTS,
        )
        assert res.outcome == "inconclusive"
        assert REASON_Z3_UNAVAILABLE in res.reason


class TestWriteOnlyHypothesis:
    def test_peer_write_confirms_detection_grade(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_WRITE_ONLY,
            source_texts=TEXTS,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_PEER_WRITE
        assert is_detection_rule_id(res.rule_id)

    def test_dead_state_confirms_detection_grade(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_pkt_sent",
            "`highest_sent` is tracked but never used for validation",
            source_texts=TEXTS,
        )
        assert res.outcome == "confirmed"
        assert res.rule_id == RULE_DEAD_STATE
        assert res.dead_state["reads"] == 0
        assert len(res.dead_state["writes"]) == 2

    def test_validated_twin_refutes(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "ackm_on_ack", HYP_WRITE_ONLY,
            source_texts=TWIN_TEXTS,
        )
        assert res.outcome == "refuted"
        assert "highest_sent" in res.peer_write["validating_guard"]

    def test_authority_unresolved(self):
        src = """\
void set_mode(struct st *st, int m)
{
    st->mode_state = m;
    use(st->mode_state);
}
"""
        res = run_protocol_state_check(
            ".", "src/m.c", "set_mode",
            "`mode_state` is peer controlled state",
            source_texts={"src/m.c": src},
        )
        assert res.outcome == "inconclusive"
        assert REASON_AUTHORITY_UNRESOLVED in res.reason

    def test_hypothesis_unbindable(self):
        res = run_protocol_state_check(
            ".", "src/ackm.c", "f", "peer controls the state counter",
            source_texts={"src/ackm.c": "int f(void) { return 0; }\n"},
        )
        assert res.outcome == "inconclusive"
        assert res.reason.startswith(REASON_HYPOTHESIS_UNBINDABLE)

    def test_all_reasons_enumerated(self):
        assert len(INCONCLUSIVE_REASONS) == 6
        assert REASON_INVARIANT_UNSTATED in INCONCLUSIVE_REASONS
        assert REASON_CENSUS_DEGRADED in INCONCLUSIVE_REASONS


class TestPrepassInvariants:
    def test_receipted_invariant_adjudicated_standing(self, tmp_path):
        out = run_protocol_state_prepass(
            TEXTS, out_dir=tmp_path, domain_model=RECEIPTED_DM,
        )
        tele = out["telemetry"]
        assert tele["invariants_checked"] == 1
        assert tele["confirmed"] == 1
        finding = out["findings"][0]
        assert finding["rule_id"] == RULE_INVARIANT_VIOLATED
        assert finding["cwe"] == "CWE-372"
        assert finding["detection_grade"] is False
        # Registry-grade but reachability unknown ⇒ suspicious.
        assert finding["status"] == "suspicious"

    def test_llm_stated_invariant_not_adjudicated_standing(
        self, tmp_path,
    ):
        # The standing prepass only promotes study-receipted premises;
        # LLM-stated invariants stay hypothesis-driven.
        out = run_protocol_state_prepass(
            TEXTS, out_dir=tmp_path, domain_model=LLM_STATED_DM,
        )
        assert out["telemetry"]["invariants_checked"] == 0
        assert out["findings"] == []


class TestInvariantReceiptBoundaries:
    """Substring containment handed an unrelated entry's provenance
    and receipt grade to a different variable's invariant ('x <= 10'
    receipted by 'max_x <= 100')."""

    def _dm(self, statement):
        return {"invariants": [{
            "statement": statement,
            "provenance": "study_receipt",
            "receipt": {"file": "notes.md", "quote": statement},
        }]}

    def test_embedded_identifier_does_not_receipt(self):
        from core.audit.protocol_state import _invariant_receipt

        assert _invariant_receipt(self._dm("max_x <= 100"), "x <= 10") \
            is None

    def test_exact_statement_still_receipts(self):
        from core.audit.protocol_state import _invariant_receipt

        entry = _invariant_receipt(self._dm("x <= 10"), "x <= 10")
        assert entry is not None

    def test_bounded_containment_still_receipts(self):
        # A statement that carries the comparison as its own token
        # run ("invariant: x <= 10 (from spec)") still matches.
        from core.audit.protocol_state import _invariant_receipt

        entry = _invariant_receipt(
            self._dm("invariant: x <= 10 (from spec)"), "x <= 10",
        )
        assert entry is not None

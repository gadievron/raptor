"""Provenance gate on the domain-model guard role.

``_domain_model_role`` grants ``grade=registry`` — promote-capable
evidence. Registry grade demands the DomainVocabulary provenance rule
(receipt present, provenance != llm_prior) shared with protocol_state
and the invariant gate: a derived threat-frame invariant (llm_prior,
receipt-less by construction) is a review HINT, and an LLM guess must
never bind a guard role that can promote another LLM's hypothesis.
"""

from __future__ import annotations

import json

from core.audit.fail_open_roles import RoleContext, _domain_model_role


def _write_model(tmp_path, invariants):
    (tmp_path / "domain-model.json").write_text(json.dumps({
        "concepts": [], "contracts": [], "invariants": invariants,
    }))


def _inv(**over):
    base = {
        "id": "tf_token-check",
        "statement": "Payloads reaching consume_msg must be checked "
                     "by verify_token before use.",
        "negation": "Unverified payloads reach the parser.",
        "provenance": "llm_prior",
        "receipt": None,
    }
    base.update(over)
    return base


class TestDomainModelGuardRoleProvenance:
    def test_derived_llm_prior_invariant_binds_nothing(self, tmp_path):
        _write_model(tmp_path, [_inv()])
        ev = _domain_model_role(
            ["verify_token"], "src/msg.c", RoleContext(out_dir=tmp_path),
        )
        assert ev is None

    def test_receiptless_invariant_binds_nothing(self, tmp_path):
        _write_model(tmp_path, [_inv(provenance="llm_summarized")])
        ev = _domain_model_role(
            ["verify_token"], "src/msg.c", RoleContext(out_dir=tmp_path),
        )
        assert ev is None

    def test_receipt_backed_invariant_still_binds(self, tmp_path):
        _write_model(tmp_path, [_inv(
            provenance="verbatim",
            receipt={
                "file": "src/msg.c", "line": 10,
                "quote": "must be checked by verify_token",
                "verified": True, "tier": "verbatim",
            },
        )])
        ev = _domain_model_role(
            ["verify_token"], "src/msg.c", RoleContext(out_dir=tmp_path),
        )
        assert ev is not None
        assert ev.kind == "guard"
        assert ev.source == "domain_model"

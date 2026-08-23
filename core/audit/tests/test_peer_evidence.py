"""PeerEvidence receipt type + the consistency namespace policy.

Covers the self-corroboration firewall (design §4.2): two consistency
majority statistics can never jointly promote — one namespace,
deliberately — and a ``-majority``-only stamp is a statistical prior,
not tool evidence (the promotion alarm fires on it).
"""

from __future__ import annotations

from types import SimpleNamespace

from core.audit.evidence_grade import is_tool_evidence
from core.audit.peer_evidence import (
    CONSISTENCY_NAMESPACE,
    MAX_EXHIBITS,
    PeerEvidence,
    PeerExhibit,
    is_detection_rule_id,
    rule_id,
)


def _pe(contract_source: str) -> PeerEvidence:
    return PeerEvidence(
        dimension="return-check",
        formation="same_callee",
        group_key="do_auth",
        n=10,
        conforming=9,
        ratio=0.9,
        deviant=PeerExhibit("src/a.c", 44, "do_auth();"),
        exhibits=[
            PeerExhibit("src/b.c", 120, "if (do_auth() != 0)"),
            PeerExhibit("src/c.c", 88, "if (do_auth() != 0)"),
        ],
        contract_source=contract_source,
        provenance="wur:harvested" if contract_source == "wur" else contract_source,
    )


class TestReceiptShape:
    def test_registry_contract_selects_verification_rule_id(self):
        pe = _pe("wur")
        assert pe.registry_grade
        assert pe.rule_id == "consistency:return-check"

    def test_majority_contract_selects_detection_rule_id(self):
        pe = _pe("majority")
        assert not pe.registry_grade
        assert pe.rule_id == "consistency:return-check-majority"

    def test_to_dict_carries_all_receipt_fields(self):
        d = _pe("wur").to_dict()
        assert d["kind"] == "peer_evidence"
        assert d["n"] == 10
        assert d["conforming"] == 9
        assert d["ratio"] == 0.9
        assert d["deviant"]["line"] == 44
        assert len(d["exhibits"]) == 2
        assert d["contract_source"] == "wur"
        assert d["rule_id"] == "consistency:return-check"

    def test_exhibits_capped(self):
        pe = PeerEvidence(
            dimension="flag-mode",
            formation="same_callee",
            group_key="open",
            exhibits=[
                PeerExhibit("f.c", i, "open(...)") for i in range(7)
            ],
        )
        assert len(pe.exhibits) == MAX_EXHIBITS

    def test_rule_id_helper(self):
        assert rule_id("cleanup", detection=False) == "consistency:cleanup"
        assert rule_id("cleanup", detection=True) == \
            "consistency:cleanup-majority"
        assert is_detection_rule_id("consistency:cleanup-majority")
        assert not is_detection_rule_id("consistency:cleanup")
        assert not is_detection_rule_id("fail_open:ignored-return")


class TestSelfCorroborationFirewall:
    """Two majority statistics can never self-corroborate to promotion."""

    def test_two_majority_confirmations_share_one_namespace(self):
        from core.audit.orchestrator import _aggregate_channel_confirmations

        channels, _mean = _aggregate_channel_confirmations([
            "consistency:return-check-majority",
            "consistency:flag-mode-majority",
        ])
        assert channels == []

    def test_majority_plus_second_namespace_aggregates(self):
        from core.audit.orchestrator import _aggregate_channel_confirmations

        channels, mean = _aggregate_channel_confirmations([
            "consistency:return-check-majority",
            "compiler:-Wunused-result",
        ])
        assert channels == ["compiler", CONSISTENCY_NAMESPACE]
        assert mean > 0.7

    def test_detection_variants_are_detection_only(self):
        from core.audit.orchestrator import _is_detection_only

        assert _is_detection_only("consistency:return-check-majority")
        assert not _is_detection_only("consistency:return-check")


class TestEvidenceGradeFirewall:
    def test_registry_stamp_is_tool_evidence(self):
        assert is_tool_evidence("consistency:return-check")
        assert is_tool_evidence("consistency:flag-mode")

    def test_majority_stamp_alone_is_not_tool_evidence(self):
        assert not is_tool_evidence("consistency:return-check-majority")

    def test_majority_stamp_qualifies_only_in_composite(self):
        assert is_tool_evidence(
            "consistency:return-check-majority+compiler",
        )
        assert not is_tool_evidence(
            "consistency:return-check-majority"
            "+consistency:flag-mode-majority",
        )
        # A composite smuggling an LLM claim still fails outright.
        assert not is_tool_evidence("semgrep+llm-claimed:manual")

    def test_existing_stamps_unchanged(self):
        assert is_tool_evidence("semgrep")
        assert is_tool_evidence("semgrep+joern")
        # Detection-grade by fail_open's own is_detection_rule_id —
        # corroboration only, never full tool evidence alone.
        assert not is_tool_evidence("fail_open:ignored-return-naming")
        assert is_tool_evidence("fail_open:ignored-return")
        assert not is_tool_evidence("")
        assert not is_tool_evidence("none")
        assert not is_tool_evidence("llm-claimed:manual")


class TestPromotionAlarm:
    def _outcome(self, evidence_tool: str) -> SimpleNamespace:
        return SimpleNamespace(
            file="src/a.c",
            function="caller_9",
            status="finding",
            evidence_tool=evidence_tool,
            review_result={},
            hypothesis="return of do_auth() is discarded",
        )

    def test_registry_promotion_does_not_trip_alarm(self, tmp_path):
        from core.audit.promotion_alarm import check_and_emit, load_alarms

        rec = check_and_emit(
            tmp_path, self._outcome("consistency:return-check"),
            stage="consistency_prepass",
        )
        assert rec is None
        assert load_alarms(tmp_path) == []

    def test_majority_only_promotion_trips_alarm(self, tmp_path):
        from core.audit.promotion_alarm import check_and_emit, load_alarms

        rec = check_and_emit(
            tmp_path, self._outcome("consistency:return-check-majority"),
            stage="consistency_prepass",
        )
        assert rec is not None
        alarms = load_alarms(tmp_path)
        assert len(alarms) == 1
        assert alarms[0]["evidence_tool"] == \
            "consistency:return-check-majority"

    def test_receipt_map_covers_dimension_rule_ids(self):
        from core.audit.evidence_grade import _RECEIPT_MAP

        for rid in ("consistency:return-check", "consistency:flag-mode",
                    "consistency:cleanup", "consistency"):
            assert rid in _RECEIPT_MAP

"""Tests for core.audit.attacker_synthesis."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.audit.attacker_synthesis import (
    _COMPOSABLE_PAIRS,
    _STEP_OUTPUT_INPUT,
    AttackChain,
    AttackPrimitive,
    _check_chain_constraints,
    classify_primitive,
    format_chains_summary,
    group_by_reachability,
    synthesize_chains,
    write_attack_chains,
)


@dataclass
class FakeOutcome:
    file: str = "a.c"
    function: str = "f"
    status: str = "finding"
    hypothesis: str = ""
    review_result: Optional[Dict[str, Any]] = None


class TestClassifyPrimitive:
    def test_cwe_120_buffer_overflow(self):
        o = FakeOutcome(review_result={"cwe_class": "CWE-120"})
        p = classify_primitive(o)
        assert p.kind == "write"

    def test_cwe_78_command_injection(self):
        o = FakeOutcome(review_result={"cwe_class": "CWE-78"})
        p = classify_primitive(o)
        assert p.kind == "execute"

    def test_cwe_200_info_disclosure(self):
        o = FakeOutcome(review_result={"cwe_class": "CWE-200"})
        p = classify_primitive(o)
        assert p.kind == "info_leak"

    def test_cwe_306_missing_auth(self):
        o = FakeOutcome(review_result={"cwe_class": "CWE-306"})
        p = classify_primitive(o)
        assert p.kind == "auth_bypass"

    def test_hypothesis_fallback(self):
        o = FakeOutcome(
            hypothesis="buffer overflow via unchecked memcpy",
            review_result={},
        )
        p = classify_primitive(o)
        assert p.kind == "write"

    def test_hypothesis_info_leak(self):
        o = FakeOutcome(
            hypothesis="information disclosure of stack memory",
            review_result={},
        )
        p = classify_primitive(o)
        assert p.kind == "info_leak"

    def test_hypothesis_auth_bypass(self):
        o = FakeOutcome(
            hypothesis="authentication bypass via missing check",
            review_result={},
        )
        p = classify_primitive(o)
        assert p.kind == "auth_bypass"

    def test_unknown_when_no_signals(self):
        o = FakeOutcome(review_result={})
        p = classify_primitive(o)
        assert p.kind == "unknown"

    def test_constraints_from_preconditions(self):
        o = FakeOutcome(
            review_result={
                "cwe_class": "CWE-120",
                "preconditions": [
                    {"assumption": "requires local access only"},
                ],
            },
        )
        p = classify_primitive(o)
        assert len(p.constraints) == 1
        assert "local" in p.constraints[0]

    def test_cwe_with_spaces(self):
        o = FakeOutcome(review_result={"cwe_class": "CWE-416"})
        p = classify_primitive(o)
        assert p.kind == "write"


class TestGroupByReachability:
    def test_single_finding(self):
        outcomes = [FakeOutcome(status="finding")]
        groups = group_by_reachability(outcomes)
        assert len(groups) == 1
        assert groups[0] == [0]

    def test_no_findings(self):
        outcomes = [FakeOutcome(status="clean")]
        assert group_by_reachability(outcomes) == []

    def test_groups_by_file(self):
        outcomes = [
            FakeOutcome(file="a.c", function="f1", status="finding"),
            FakeOutcome(file="a.c", function="f2", status="finding"),
            FakeOutcome(file="b.c", function="f3", status="finding"),
        ]
        groups = group_by_reachability(outcomes)
        a_group = [g for g in groups if 0 in g and 1 in g]
        assert len(a_group) == 1

    def test_groups_by_entry_point(self):
        context_map = {
            "entry_points": [
                {"file": "main.c", "name": "handle_request"},
            ],
            "call_edges": {
                "main.c:handle_request": ["a.c:parse", "a.c:validate"],
            },
        }
        outcomes = [
            FakeOutcome(file="a.c", function="parse", status="finding"),
            FakeOutcome(file="a.c", function="validate", status="finding"),
        ]
        groups = group_by_reachability(outcomes, context_map)
        assert any(0 in g and 1 in g for g in groups)

    def test_ungrouped_get_own_group(self):
        outcomes = [
            FakeOutcome(file="a.c", function="f1", status="finding"),
            FakeOutcome(file="b.c", function="f2", status="finding"),
        ]
        groups = group_by_reachability(outcomes)
        assert any(0 in g for g in groups)
        assert any(1 in g for g in groups)


class TestSynthesizeChains:
    def test_composable_pair(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="leak",
                status="finding",
                review_result={"cwe_class": "CWE-200"},
            ),
            FakeOutcome(
                file="a.c", function="overflow",
                status="finding",
                review_result={"cwe_class": "CWE-120"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) >= 1
        chain = chains[0]
        assert "ASLR" in chain.combined_impact or "memory" in chain.combined_impact
        assert chain.severity in ("critical", "high")
        assert chain.chain_status == "confirmed"

    def test_auth_bypass_plus_execute(self):
        outcomes = [
            FakeOutcome(
                file="api.py", function="check_auth",
                status="finding",
                review_result={"cwe_class": "CWE-306"},
            ),
            FakeOutcome(
                file="api.py", function="run_cmd",
                status="finding",
                review_result={"cwe_class": "CWE-78"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) >= 1
        assert "pre-auth" in chains[0].combined_impact.lower()

    def test_non_composable_pair(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="f1",
                status="finding",
                review_result={"cwe_class": "CWE-476"},
            ),
            FakeOutcome(
                file="a.c", function="f2",
                status="finding",
                review_result={"cwe_class": "CWE-476"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) == 0

    def test_no_findings(self):
        outcomes = [FakeOutcome(status="clean")]
        chains = synthesize_chains(outcomes)
        assert chains == []

    def test_constraint_failure_marks_hypothetical(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="leak",
                status="finding",
                review_result={
                    "cwe_class": "CWE-200",
                    "preconditions": [
                        {"assumption": "requires local access only"},
                    ],
                },
            ),
            FakeOutcome(
                file="a.c", function="overflow",
                status="finding",
                review_result={"cwe_class": "CWE-120"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) >= 1
        constrained = [c for c in chains if c.chain_status == "hypothetical"]
        assert len(constrained) >= 1

    def test_chain_narrative(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="leak",
                status="finding",
                hypothesis="info leak via uninitialized stack",
                review_result={"cwe_class": "CWE-200"},
            ),
            FakeOutcome(
                file="a.c", function="overflow",
                status="finding",
                hypothesis="heap overflow in parse_header",
                review_result={"cwe_class": "CWE-122"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert "leak" in chains[0].narrative
        assert "overflow" in chains[0].narrative

    def test_single_finding_no_chain(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="f",
                status="finding",
                review_result={"cwe_class": "CWE-120"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert chains == []


class TestSecondPrimitiveConstraints:
    """Access constraints on the SECOND primitive also block a chain."""

    def test_blocking_constraint_on_second_primitive_fails_chain(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="leak",
                review_result={"cwe_class": "CWE-200"},
            ),
            FakeOutcome(
                file="a.c", function="overflow",
                review_result={
                    "cwe_class": "CWE-120",
                    "preconditions": [
                        {"assumption": "requires local access only"},
                    ],
                },
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) >= 1
        assert all(c.chain_status == "hypothetical" for c in chains)
        failures = [f for c in chains for f in c.constraint_failures]
        assert any("local access" in f for f in failures)
        assert any("Finding B" in f for f in failures)

    def test_auth_constraint_on_second_primitive_fails_chain(self):
        prim_a = AttackPrimitive(kind="info_leak", description="leak")
        prim_b = AttackPrimitive(
            kind="write", description="write",
            constraints=["authentication required for this endpoint"],
        )
        failures = _check_chain_constraints(
            FakeOutcome(), FakeOutcome(), prim_a, prim_b,
        )
        assert any("Finding B requires authentication" in f for f in failures)

    def test_auth_constraint_waived_by_auth_bypass_partner(self):
        prim_a = AttackPrimitive(kind="auth_bypass", description="bypass")
        prim_b = AttackPrimitive(
            kind="execute", description="exec",
            constraints=["authentication required"],
        )
        failures = _check_chain_constraints(
            FakeOutcome(), FakeOutcome(), prim_a, prim_b,
        )
        assert failures == []

    def test_first_primitive_constraints_still_checked(self):
        prim_a = AttackPrimitive(
            kind="info_leak", description="leak",
            constraints=["local access only"],
        )
        prim_b = AttackPrimitive(kind="write", description="write")
        failures = _check_chain_constraints(
            FakeOutcome(), FakeOutcome(), prim_a, prim_b,
        )
        assert any("Finding A" in f and "local access" in f for f in failures)


class TestDirectionNormalisation:
    """Reverse-ordered composable pairs are normalised to the forward
    direction — no contradictory verdicts, truthful narrative order."""

    def test_reverse_ordered_pair_normalised_to_forward(self):
        # write appears before info_leak; only (info_leak, write) is a
        # forward transition, so the chain must be reordered.
        outcomes = [
            FakeOutcome(
                file="a.c", function="overflow",
                review_result={"cwe_class": "CWE-120"},
            ),
            FakeOutcome(
                file="a.c", function="leak",
                review_result={"cwe_class": "CWE-200"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) == 1
        chain = chains[0]
        assert chain.chain_status == "confirmed"
        assert chain.constraint_failures == []
        assert chain.finding_keys == ["a.c:leak", "a.c:overflow"]
        assert chain.primitives[0].kind == "info_leak"
        assert chain.primitives[1].kind == "write"
        assert "Step 1: info_leak" in chain.narrative
        assert "Step 2: write" in chain.narrative

    def test_forward_ordered_pair_unchanged(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="leak",
                review_result={"cwe_class": "CWE-200"},
            ),
            FakeOutcome(
                file="a.c", function="overflow",
                review_result={"cwe_class": "CWE-120"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        assert len(chains) == 1
        assert chains[0].finding_keys == ["a.c:leak", "a.c:overflow"]
        assert chains[0].chain_status == "confirmed"

    def test_multi_step_no_spurious_type_mismatch_from_reverse_seed(self):
        # write listed before info_leak: the pairwise seed used to be
        # built as write -> info_leak, so the multi-step extension
        # write -> info_leak -> execute reported a spurious type
        # mismatch while the symmetric pairwise check cleared it.
        outcomes = [
            FakeOutcome(
                file="a.c", function="overflow",
                review_result={"cwe_class": "CWE-120"},
            ),
            FakeOutcome(
                file="a.c", function="leak",
                review_result={"cwe_class": "CWE-200"},
            ),
            FakeOutcome(
                file="a.c", function="runner",
                review_result={"cwe_class": "CWE-78"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        multi = [c for c in chains if len(c.finding_keys) > 2]
        assert multi, "expected at least one multi-step chain"
        for c in chains:
            assert not any(
                "type mismatch" in f for f in c.constraint_failures
            ), f"{c.chain_id} carries a spurious type mismatch"
        assert all(c.chain_status == "confirmed" for c in chains)
        # The normalised 3-step chain follows the forward direction.
        three_step = [c for c in multi if len(c.finding_keys) == 3]
        assert any(
            [p.kind for p in c.primitives] == ["info_leak", "write", "execute"]
            for c in three_step
        )

    def test_pairwise_and_multistep_verdicts_agree(self):
        outcomes = [
            FakeOutcome(
                file="a.c", function="overflow",
                review_result={"cwe_class": "CWE-120"},
            ),
            FakeOutcome(
                file="a.c", function="leak",
                review_result={"cwe_class": "CWE-200"},
            ),
        ]
        chains = synthesize_chains(outcomes)
        statuses = {c.chain_status for c in chains}
        assert statuses == {"confirmed"}


class TestDeadDosEntryRemoved:
    def test_dos_race_entry_gone(self):
        assert ("dos", "race") not in _STEP_OUTPUT_INPUT

    def test_no_dos_output_kind_remains(self):
        # dos is never produced as a chain step output: pairs come from
        # _COMPOSABLE_PAIRS and extension appends in_kind primitives.
        assert not any(out == "dos" for out, _ in _STEP_OUTPUT_INPUT)
        assert not any("dos" in pair for pair in _COMPOSABLE_PAIRS)


class TestAttackChainToDict:
    def test_serialization(self):
        chain = AttackChain(
            chain_id="CHAIN-001",
            finding_keys=["a.c:f1", "a.c:f2"],
            primitives=[
                AttackPrimitive(kind="info_leak", description="stack leak"),
                AttackPrimitive(kind="write", description="overflow"),
            ],
            combined_impact="ASLR bypass + memory corruption",
            severity="critical",
            narrative="Step 1 then step 2",
        )
        d = chain.to_dict()
        assert d["chain_id"] == "CHAIN-001"
        assert len(d["primitives"]) == 2
        assert d["primitives"][0]["kind"] == "info_leak"
        assert d["severity"] == "critical"


class TestWriteAttackChains:
    def test_writes_json(self, tmp_path):
        chains = [
            AttackChain(
                chain_id="CHAIN-001",
                finding_keys=["a.c:f"],
                primitives=[AttackPrimitive("write", "overflow")],
                combined_impact="test",
                severity="high",
                narrative="test narrative",
            ),
        ]
        path = write_attack_chains(chains, tmp_path)
        assert path.exists()
        data = json.loads(path.read_text())
        assert data["summary"]["total"] == 1
        assert len(data["chains"]) == 1


class TestFormatChainsSummary:
    def test_no_chains(self):
        text = format_chains_summary([])
        assert "No attack chains" in text

    def test_confirmed_and_hypothetical(self):
        chains = [
            AttackChain(
                chain_id="CHAIN-001",
                finding_keys=["a.c:f"],
                primitives=[],
                combined_impact="pre-auth RCE",
                severity="critical",
                narrative="test",
                chain_status="confirmed",
            ),
            AttackChain(
                chain_id="CHAIN-002",
                finding_keys=["b.c:g"],
                primitives=[],
                combined_impact="data exfil",
                severity="high",
                narrative="test",
                chain_status="hypothetical",
                constraint_failures=["auth required"],
            ),
        ]
        text = format_chains_summary(chains)
        assert "Confirmed (1)" in text
        assert "Hypothetical (1)" in text
        assert "CHAIN-001" in text
        assert "CHAIN-002" in text
        assert "auth required" in text

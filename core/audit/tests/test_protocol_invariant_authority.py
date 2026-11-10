import pytest

@pytest.mark.slow
def test_nonempty_preservation_does_not_clear_entry_claim(tmp_path):
    pytest.importorskip("tree_sitter_c")
    from core.audit.orchestrator import OrchestratorConfig, _run_tool_chain
    source = "struct S { int largest_acked_pkt; int highest_sent; };\nvoid Keep(struct S *st) {\n st->largest_acked_pkt = st->largest_acked_pkt;\n}\n"
    (tmp_path / "unit.c").write_text(source)
    scope = dict(file="unit.c", function="Keep", line_start=2,
                 hypothesis="the protocol invariant largest_acked_pkt <= highest_sent can be violated at function entry")
    result = _run_tool_chain([dict(type="protocol_state", config=dict(invariant="largest_acked_pkt <= highest_sent"))],
        config=OrchestratorConfig(target_path=tmp_path, out_dir=None, integer_abi="lp64"),
        file_path="unit.c", function_name="Keep", source=source, hypothesis=scope["hypothesis"], line_start=2)
    assert result.source_identity is not None
    receipt = result.refutation(**scope)
    matches = bool(receipt and receipt.matches(**scope, source_identity=result.source_identity))
    assert not matches, "conditional nonempty transition cleared a claim true at entry"


@pytest.mark.parametrize("tool", ["protocol_state", "legacy-alias"])
@pytest.mark.parametrize("rule", ["protocol_state:invariant-violated", "protocol_state:invariant-violated-unreceipted"])
def test_cached_conditional_invariant_receipt_cannot_refute(tool, rule):
    from core.audit.verification_results import ClaimRefutation, ProbeOutcome, ToolChainResult
    from core.audit.refutation_source import SourceIdentity
    scope = dict(file="unit.c", function="Keep", line_start=2, hypothesis="invariant may fail at entry")
    identity = SourceIdentity("source", (1, 2, 3))
    receipt = ClaimRefutation(**scope, source_identity=identity, checks=(ProbeOutcome(tool, "refuted", rule),))
    assert not receipt.matches(**scope, source_identity=identity)
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe(tool, "refuted", rule)
    assert chain.refutation(**scope) is None


def test_peer_write_refutation_retains_its_distinct_role():
    from core.audit.verification_results import ToolChainResult
    from core.audit.refutation_source import SourceIdentity
    scope = dict(file="unit.c", function="Keep", line_start=2, hypothesis="write lacks a sibling validation guard")
    identity = SourceIdentity("source", (1, 2, 3))
    chain = ToolChainResult(**scope, source_identity=identity)
    chain.observe("protocol_state", "refuted", "protocol_state:unvalidated-peer-write")
    receipt = chain.refutation(**scope)
    assert receipt is not None and receipt.matches(**scope, source_identity=identity)

"""Binary classification hints cannot substitute for an occurrence-bound join."""
from copy import deepcopy

from core.audit.orchestrator import (
    OrchestratorConfig, ReviewOutcome, _apply_reachability_gate,
    _binary_absent_gap_keys, _binary_absent_verdict,
)


def test_unbound_absence_map_cannot_skip_or_demote_a_source_namesake(tmp_path):
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out")
    config.binary_verdicts = {"f": "absent"}
    original = deepcopy(config.binary_verdicts)
    gap = {"file": "live.c", "name": "f", "line_start": 12}
    assert _binary_absent_gap_keys([gap], None, config, None) == set()
    assert _binary_absent_verdict(config, "live.c", "f", 12) is False
    outcome = ReviewOutcome(file="live.c", function="f", status="finding",
                            body="A source concern", hypothesis="A source concern")
    outcome.line = 12
    ctx = {"source": "int f(void) { return 1; }", "role_context": {
        "role": "internal", "is_on_flow_path": False, "has_caller_data": True},
        "callers": [{"name": "caller"}]}
    selected = _apply_reachability_gate(outcome, ctx, set(), config)
    assert selected is outcome and selected.status == "finding"
    assert config.binary_verdicts == original


def test_full_tier_classification_without_correspondence_cannot_clear_a_finding(tmp_path):
    from core.analysis.reachability import binary_oracle_absent
    from core.audit.orchestrator import OrchestratorResult, _demote_absent_promotions
    inventory = {"binary_oracle": {"build_id": "fixture-build"}, "files": [{
        "path": "live.c", "language": "c", "items": [{"name": "f", "kind": "function",
            "line_start": 10, "line_end": 20, "metadata": {"binary_oracle": {
                "classification": "absent", "binaries": [{"tier": "full", "suppression_grade": True}],
            }}}],
    }]}
    original = deepcopy(inventory)
    config = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path / "out", inventory=inventory)
    # Consumer fixture: this is a recorded classifier observation, not an
    # executed binary or a source/build correspondence contract.
    assert binary_oracle_absent(inventory, "live.c", "f", 12) is True
    gap = {"file": "live.c", "name": "f", "line_start": 12}
    assert _binary_absent_gap_keys([gap], None, config, None) == set()
    assert _binary_absent_verdict(config, "live.c", "f", 12) is False
    outcome = ReviewOutcome(file="live.c", function="f", status="finding",
        body="[sweep promoted via semgrep:fixture]\n\nA source concern", evidence_tool="semgrep:fixture")
    outcome.line = 12
    result = OrchestratorResult(outcomes=[outcome], findings=1)
    assert _demote_absent_promotions(result, config) == 0
    assert result.outcomes == [outcome] and result.outcomes[0] is outcome
    assert (result.findings, result.dormant, outcome.status) == (1, 0, "finding")
    assert not (config.out_dir / "suppressions.jsonl").exists()
    assert inventory == original

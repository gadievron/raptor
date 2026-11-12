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

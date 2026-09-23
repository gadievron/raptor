"""Review-time binary-oracle gates use the file+line join, not the flat map.

config.binary_verdicts is a flat {name: verdict} map — it collapses
same-named static functions across translation units, so the G7
dead-code gate and _apply_reachability_gate could demote a LIVE
function because a dead namesake in another TU carried the "absent"
verdict. When the enriched inventory exists, both gates route through
core.analysis.reachability.binary_oracle_absent (path + line
disambiguated, full-tier gated); the flat map stays as the
no-inventory fallback.
"""

from __future__ import annotations

from pathlib import Path

from core.audit.orchestrator import (
    OrchestratorConfig,
    ReviewOutcome,
    _apply_reachability_gate,
    _binary_absent_verdict,
)


def _inventory() -> dict:
    def item(name, absent):
        meta = {}
        if absent:
            meta = {"binary_oracle": {
                "classification": "absent",
                "binaries": [{"tier": "full"}],
            }}
        else:
            meta = {"binary_oracle": {
                "classification": "symbol_present",
                "binaries": [{"tier": "full"}],
            }}
        return {"name": name, "kind": "function", "line_start": 10,
                "line_end": 30, "metadata": meta}

    return {
        "binary_oracle": {"build_id": "x"},
        "files": [
            {"path": "a.c", "items": [item("f", absent=True)]},
            {"path": "b.c", "items": [item("f", absent=False)]},
        ],
    }


def _config(tmp_path: Path, with_inventory: bool) -> OrchestratorConfig:
    cfg = OrchestratorConfig(target_path=tmp_path, out_dir=tmp_path)
    cfg.binary_verdicts = {"f": "absent"}  # flat map: name collision
    if with_inventory:
        cfg.inventory = _inventory()
    return cfg


class TestBinaryAbsentVerdictJoin:
    def test_live_namesake_not_absent_with_inventory(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=True)
        assert _binary_absent_verdict(cfg, "b.c", "f", 12) is False
        assert _binary_absent_verdict(cfg, "a.c", "f", 12) is True

    def test_flat_map_remains_no_inventory_fallback(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=False)
        assert _binary_absent_verdict(cfg, "b.c", "f", 12) is True


class TestReachabilityGateJoin:
    def _outcome(self, file):
        oc = ReviewOutcome(file=file, function="f", status="finding",
                           body="b", hypothesis="h")
        oc.line = 12
        return oc

    def _ctx(self):
        return {"source": "int f(void){}", "role_context": {
            "role": "internal", "is_on_flow_path": False,
            "has_caller_data": True,
        }, "callers": [{"name": "g"}]}

    def test_live_tu_finding_survives(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=True)
        out = _apply_reachability_gate(
            self._outcome("b.c"), self._ctx(), set(), cfg,
        )
        assert out.status == "finding"

    def test_dead_tu_finding_still_demotes(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=True)
        out = _apply_reachability_gate(
            self._outcome("a.c"), self._ctx(), set(), cfg,
        )
        assert out.status == "dormant"

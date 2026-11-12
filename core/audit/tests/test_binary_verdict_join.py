"""Binary classification joins remain observations without suppression authority.

Enriched inventories distinguish same-named source occurrences. That join and
full debug coverage still do not establish complete source/build correspondence;
neither enriched classification nor a flat name map clears a source finding.
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
        from core.analysis.reachability import binary_oracle_absent
        # The underlying occurrence join keeps the two observations distinct.
        assert binary_oracle_absent(cfg.inventory, "b.c", "f", 12) is False
        assert binary_oracle_absent(cfg.inventory, "a.c", "f", 12) is True
        assert _binary_absent_verdict(cfg, "b.c", "f", 12) is False
        assert _binary_absent_verdict(cfg, "a.c", "f", 12) is False

    def test_flat_map_without_inventory_cannot_suppress(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=False)
        assert _binary_absent_verdict(cfg, "b.c", "f", 12) is False


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

    def test_classified_absent_tu_finding_survives_without_correspondence(self, tmp_path):
        cfg = _config(tmp_path, with_inventory=True)
        original = self._outcome("a.c")
        out = _apply_reachability_gate(
            original, self._ctx(), set(), cfg,
        )
        assert out is original and out.status == "finding"
        assert cfg.inventory == _inventory()

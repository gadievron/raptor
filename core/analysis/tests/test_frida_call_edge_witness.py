"""Tests for the FRIDA_CALL_EDGE reachability witness: accessor truth
table, classify precedence, verdict registration, and the enrichment
round trip from a synthetic call-edges run."""

from __future__ import annotations

import json
from pathlib import Path

from core.analysis import reach_audit
from core.analysis.reach_witness import (
    VERDICTS,
    Reachability,
    Soundness,
    WitnessKind,
)
from core.analysis.reachability import frida_call_edge_present


def _inventory(meta: dict | None) -> dict:
    item: dict = {"name": "hidden_target", "kind": "function", "line": 10}
    if meta is not None:
        item["metadata"] = meta
    return {"files": [{"path": "src/lib.c", "language": "c",
                       "items": [item]}]}


class TestAccessor:
    def test_observed_edge_is_present(self):
        inv = _inventory({"frida_call_edge": {"observed": True,
                                              "call_count": 3}})
        assert frida_call_edge_present(inv, "src/lib.c", "hidden_target")

    def test_absent_metadata_is_not_present(self):
        assert not frida_call_edge_present(
            _inventory(None), "src/lib.c", "hidden_target")
        assert not frida_call_edge_present(
            _inventory({"frida_call_edge": {"observed": False}}),
            "src/lib.c", "hidden_target")

    def test_wrong_name_or_file(self):
        inv = _inventory({"frida_call_edge": {"observed": True}})
        assert not frida_call_edge_present(inv, "src/lib.c", "other_fn")
        assert not frida_call_edge_present(inv, "src/other.c",
                                           "hidden_target")


class TestWitnessRegistration:
    def test_verdict_spec(self):
        spec = VERDICTS["frida_call_edge"]
        assert spec.status is Reachability.REACHABLE
        assert spec.kind is WitnessKind.FRIDA_CALL_EDGE
        assert spec.soundness is Soundness.SOUND
        assert spec.earns_suppression is False

    def test_precedence_rescues_before_oracle_absent(self):
        names = [s.__name__ for s in reach_audit.PRECEDENCE]
        edge_idx = names.index("_stage_frida_call_edge")
        oracle_idx = names.index("_stage_binary_oracle_absent")
        assert edge_idx < oracle_idx

    def test_live_verdict_membership(self):
        assert "frida_call_edge" in reach_audit._LIVE_VERDICTS

    def test_classify_returns_edge_verdict(self):
        inv = _inventory({"frida_call_edge": {"observed": True}})
        verdict = reach_audit.classify_reachability(
            inv, "src/lib.c", "hidden_target", 10, "src/lib.c")
        assert verdict == "frida_call_edge"


class TestEnrichment:
    def _run_dir(self, tmp_path: Path, events: list[dict],
                 binary: Path) -> Path:
        run = tmp_path / "frida_run"
        run.mkdir()
        (run / "metadata.json").write_text(json.dumps({
            "ok": True,
            "target": {"raw": str(binary), "kind": "binary",
                       "binary": str(binary)},
            "script_origin": "template:call-edges",
        }), encoding="utf-8")
        lines = [json.dumps({"ts": 1.0, "type": "send", "payload": e})
                 for e in events]
        (run / "events.jsonl").write_text("\n".join(lines) + "\n",
                                          encoding="utf-8")
        return run

    def test_owned_callee_annotates_checklist_and_inventory(self, tmp_path):
        from core.orchestration.reachability_enrichment import (
            enrich_with_frida_call_edges,
        )

        binary = tmp_path / "srv"
        self._run_dir(tmp_path, [
            {"category": "call_edge", "fn": "hidden_target",
             "callee_module": "srv",
             "callee_module_path": str(binary),
             "caller": "main", "count": 3, "tid": 0},
            # Foreign callee must be ignored even if the template
            # misfires — ownership is enforced host-side too.
            {"category": "call_edge", "fn": "memcpy",
             "callee_module": "libc.so.6",
             "callee_module_path": "/usr/lib/libc.so.6",
             "caller": "main", "count": 5, "tid": 0},
        ], binary)

        checklist = _inventory(None)
        inventory = _inventory(None)
        annotated = enrich_with_frida_call_edges(
            checklist, binary, search_dirs=[tmp_path],
            inventory=inventory)
        assert annotated == 1
        for tree in (checklist, inventory):
            meta = tree["files"][0]["items"][0]["metadata"]
            assert meta["frida_call_edge"]["observed"] is True
            assert meta["frida_call_edge"]["call_count"] == 3
            assert meta["frida_call_edge"]["callers"] == ["main"]

    def test_call_edge_events_never_become_runtime_evidence(self, tmp_path):
        # Aggregated edge counts must not double-dip into per-call
        # runtime evidence (proximity floors).
        from core.orchestration.frida_validation_bridge import (
            collect_runtime_evidence,
        )

        binary = tmp_path / "srv"
        self._run_dir(tmp_path, [
            {"category": "call_edge", "fn": "hidden_target",
             "callee_module": "srv", "caller_module": "srv",
             "callee_module_path": str(binary), "count": 3, "tid": 0},
        ], binary)
        assert collect_runtime_evidence([tmp_path]) == {}


class TestNameOnlyMatchDiscount:
    """Ambiguous bare-name joins do not witness reachability.

    The enrichment marks ``name_only_match`` when the same name is
    defined in more than one TU and no callsite resolved into the
    item's file — the observation may belong to the twin, so the
    SOUND promotion claim does not hold for it.
    """

    def test_name_only_call_edge_does_not_witness(self):
        inv = _inventory({"frida_call_edge": {
            "observed": True, "call_count": 3, "name_only_match": True}})
        assert not frida_call_edge_present(
            inv, "src/lib.c", "hidden_target")

    def test_name_only_runtime_trace_does_not_witness(self):
        from core.analysis.reachability import frida_runtime_trace_present
        inv = _inventory({"frida_runtime_trace": {
            "observed": True, "call_count": 1, "name_only_match": True}})
        assert not frida_runtime_trace_present(
            inv, "src/lib.c", "hidden_target")

    def test_unambiguous_joins_still_witness(self):
        from core.analysis.reachability import frida_runtime_trace_present
        assert frida_call_edge_present(
            _inventory({"frida_call_edge": {"observed": True}}),
            "src/lib.c", "hidden_target")
        assert frida_runtime_trace_present(
            _inventory({"frida_runtime_trace": {"observed": True}}),
            "src/lib.c", "hidden_target")

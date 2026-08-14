"""Tests for core.orchestration.context_map_taint."""

from __future__ import annotations

from core.orchestration.context_map_taint import (
    build_taint_pairs,
    enrich_with_taint_flows,
)


class FakeServer:
    """Records taint-exists queries; answers from a canned verdict map."""

    def __init__(self, verdicts=None, error=False):
        self.verdicts = verdicts or {}
        self.error = error
        self.queries = []

    def run_taint_exists_query(self, source_method, sink_call, **kwargs):
        self.queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        return self.verdicts.get((source_method, sink_call), False)


def _context_map():
    return {
        "sources": [
            {
                "type": "file_read",
                "entry": "fread into buf @ entry.c:70",
                "trust_level": "attacker_controlled",
            },
        ],
        "sinks": [
            {"type": "buffer_write", "location": "entry.c:25"},
            {"type": "buffer_write", "location": "entry.c:38"},
        ],
        "entry_points": [
            {
                "id": "EP-001",
                "name": "main",
                "file": "entry.c",
                "line": 70,
            },
        ],
        "sink_details": [
            {
                "id": "SINK-001",
                "name": "parse_alpha",
                "operation": "memcpy(out, buf + 1, claimed)",
                "file": "entry.c",
                "line": 25,
            },
            {
                "id": "SINK-002",
                "name": "parse_bravo",
                "operation": "strcpy(name, buf)",
                "file": "entry.c",
                "line": 38,
            },
        ],
    }


def _checklist():
    return {
        "target_path": "/tmp/target",
        "files": [
            {
                "path": "entry.c",
                "call_graph": {
                    "calls": [
                        {"caller": "parse_alpha", "chain": ["memcpy"], "line": 25},
                    ],
                },
            },
        ],
    }


class TestBuildTaintPairs:
    def test_call_index_resolves_sink_call(self):
        pairs = build_taint_pairs(_context_map(), _checklist())
        assert ("main", "memcpy") in [(p[2], p[3]) for p in pairs]

    def test_operation_regex_fallback(self):
        # SINK-002's line is absent from the call graph; the callee
        # name falls back to parsing the operation string.
        pairs = build_taint_pairs(_context_map(), _checklist())
        assert ("main", "strcpy") in [(p[2], p[3]) for p in pairs]

    def test_skips_entry_points_without_name(self):
        ctx = _context_map()
        del ctx["entry_points"][0]["name"]
        assert build_taint_pairs(ctx, _checklist()) == []

    def test_skips_sinks_without_resolvable_call(self):
        ctx = _context_map()
        ctx["sink_details"] = [
            {"id": "SINK-003", "operation": "???", "file": "entry.c", "line": 99},
        ]
        assert build_taint_pairs(ctx, _checklist()) == []


class TestEnrichWithTaintFlows:
    def test_confirmed_flow_annotates_all_layers(self):
        ctx = _context_map()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enriched = enrich_with_taint_flows(ctx, srv, _checklist())

        ep = ctx["entry_points"][0]
        assert ep["has_taint_flow"] is True
        assert ep["taint_reaches_sinks"] == ["SINK-001"]
        assert ctx["sink_details"][0]["taint_reached_from"] == ["EP-001"]
        # mirrored onto the attack-surface-schema arrays
        assert ctx["sources"][0]["has_taint_flow"] is True
        assert ctx["sinks"][0]["taint_reached_from"] == ["EP-001"]
        # unconfirmed sink untouched
        assert "taint_reached_from" not in ctx["sink_details"][1]
        assert enriched == 2

    def test_taint_summary_written(self):
        ctx = _context_map()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_with_taint_flows(ctx, srv, _checklist())
        summary = ctx["taint_summary"]
        assert summary["flows_confirmed"] == 1
        assert summary["pairs_checked"] == 2
        assert summary["entry_points_confirmed"] == ["EP-001"]
        assert summary["sinks_confirmed"] == ["SINK-001"]

    def test_no_flows_still_writes_summary(self):
        ctx = _context_map()
        enrich_with_taint_flows(ctx, FakeServer(), _checklist())
        assert ctx["taint_summary"]["flows_confirmed"] == 0
        assert "has_taint_flow" not in ctx["entry_points"][0]

    def test_query_errors_degrade_to_unconfirmed(self):
        ctx = _context_map()
        enriched = enrich_with_taint_flows(
            ctx, FakeServer(error=True), _checklist())
        assert enriched == 0
        assert ctx["taint_summary"]["flows_confirmed"] == 0

    def test_unique_query_pairs_deduplicated(self):
        ctx = _context_map()
        # Second entry point with the same host function name — the
        # (main, memcpy) query must still run only once.
        ctx["entry_points"].append(
            {"id": "EP-002", "name": "main", "file": "entry.c", "line": 64})
        srv = FakeServer()
        enrich_with_taint_flows(ctx, srv, _checklist())
        assert srv.queries.count(("main", "memcpy")) == 1

    def test_pair_cap_records_dropped(self):
        ctx = _context_map()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_with_taint_flows(ctx, srv, _checklist(), max_pairs=1)
        assert ctx["taint_summary"]["pairs_checked"] == 1
        assert ctx["taint_summary"]["pairs_dropped_over_cap"] == 1

    def test_idempotent_rerun_clears_stale_annotations(self):
        ctx = _context_map()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_with_taint_flows(ctx, srv, _checklist())
        # Re-run with the flow no longer confirmed — stale marks must go.
        enrich_with_taint_flows(ctx, FakeServer(), _checklist())
        assert "has_taint_flow" not in ctx["entry_points"][0]
        assert "taint_reached_from" not in ctx["sink_details"][0]
        assert "has_taint_flow" not in ctx["sources"][0]
        assert ctx["taint_summary"]["flows_confirmed"] == 0

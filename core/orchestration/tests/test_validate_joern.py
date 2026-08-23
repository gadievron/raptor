"""Tests for core.orchestration.validate_joern."""

from __future__ import annotations

from core.orchestration.validate_joern import (
    confirm_finding_flow,
    enrich_attack_surface_with_taint,
)


class FakeFlow:
    def __init__(self, steps):
        self.steps = steps


class FakeServer:
    def __init__(self, verdicts=None, flows=None, error=False):
        self.verdicts = verdicts or {}
        self.flows = flows or {}
        self.error = error
        self.exists_queries = []
        self.flow_queries = []

    def run_taint_exists_query(self, source_method, sink_call, **kwargs):
        self.exists_queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        return self.verdicts.get((source_method, sink_call), False)

    def run_taint_query(self, source_method, sink_call, **kwargs):
        self.flow_queries.append((source_method, sink_call))
        if self.error:
            raise RuntimeError("joern down")
        return self.flows.get((source_method, sink_call), [])


def _attack_surface():
    return {
        "sources": [
            {
                "type": "file_read",
                "entry": "fread into buf @ entry.c:70",
                "trust_level": "attacker_controlled",
            },
        ],
        "sinks": [
            {"type": "buffer_write",
             "location": "entry.c:25 — memcpy(out, buf + 1, claimed)"},
            {"type": "buffer_write", "location": "entry.c:38"},
        ],
        "trust_boundaries": [],
    }


def _checklist():
    return {
        "target_path": "/tmp/target",
        "files": [
            {
                "path": "entry.c",
                "items": [
                    {"name": "main", "kind": "function",
                     "line_start": 60, "line_end": 95},
                    {"name": "parse_alpha", "kind": "function",
                     "line_start": 20, "line_end": 30},
                ],
                "call_graph": {
                    "calls": [
                        {"caller": "parse_alpha", "chain": ["memcpy"],
                         "line": 25},
                        {"caller": "parse_bravo", "chain": ["strcpy"],
                         "line": 38},
                    ],
                },
            },
        ],
    }


class TestEnrichAttackSurfaceWithTaint:
    def test_confirmed_flow_annotates_source_and_sink(self):
        surface = _attack_surface()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enriched = enrich_attack_surface_with_taint(surface, srv, _checklist())

        source = surface["sources"][0]
        assert source["has_taint_flow"] is True
        assert source["taint_reaches_sinks"] == [
            "entry.c:25 — memcpy(out, buf + 1, claimed)"]
        assert surface["sinks"][0]["taint_reached_from"] == [
            "fread into buf @ entry.c:70"]
        assert "taint_reached_from" not in surface["sinks"][1]
        assert enriched == 2

    def test_source_method_resolved_from_line_spans(self):
        surface = _attack_surface()
        srv = FakeServer()
        enrich_attack_surface_with_taint(surface, srv, _checklist())
        # entry.c:70 sits inside main's 60-95 span.
        assert ("main", "memcpy") in srv.exists_queries
        assert ("main", "strcpy") in srv.exists_queries

    def test_taint_summary_written(self):
        surface = _attack_surface()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_attack_surface_with_taint(surface, srv, _checklist())
        summary = surface["taint_summary"]
        assert summary["flows_confirmed"] == 1
        assert summary["pairs_checked"] == 2
        assert summary["sources_confirmed"] == ["fread into buf @ entry.c:70"]
        assert summary["sinks_confirmed"] == [
            "entry.c:25 — memcpy(out, buf + 1, claimed)"]

    def test_no_flows_still_writes_summary(self):
        surface = _attack_surface()
        enrich_attack_surface_with_taint(surface, FakeServer(), _checklist())
        assert surface["taint_summary"]["flows_confirmed"] == 0
        assert "has_taint_flow" not in surface["sources"][0]

    def test_query_errors_degrade_to_unconfirmed(self):
        surface = _attack_surface()
        enriched = enrich_attack_surface_with_taint(
            surface, FakeServer(error=True), _checklist())
        assert enriched == 0
        assert surface["taint_summary"]["flows_confirmed"] == 0

    def test_unique_query_pairs_deduplicated(self):
        surface = _attack_surface()
        surface["sources"].append({
            "type": "env", "entry": "getenv @ entry.c:64",
        })
        srv = FakeServer()
        enrich_attack_surface_with_taint(surface, srv, _checklist())
        # Both sources sit in main's span — one query per unique pair.
        assert srv.exists_queries.count(("main", "memcpy")) == 1

    def test_pair_cap_records_dropped(self):
        surface = _attack_surface()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_attack_surface_with_taint(
            surface, srv, _checklist(), max_pairs=1)
        assert surface["taint_summary"]["pairs_checked"] == 1
        assert surface["taint_summary"]["pairs_dropped_over_cap"] == 1

    def test_idempotent_rerun_clears_stale_annotations(self):
        surface = _attack_surface()
        srv = FakeServer(verdicts={("main", "memcpy"): True})
        enrich_attack_surface_with_taint(surface, srv, _checklist())
        enrich_attack_surface_with_taint(surface, FakeServer(), _checklist())
        assert "has_taint_flow" not in surface["sources"][0]
        assert "taint_reached_from" not in surface["sinks"][0]
        assert surface["taint_summary"]["flows_confirmed"] == 0

    def test_no_checklist_skips_unresolvable_sources(self):
        surface = _attack_surface()
        srv = FakeServer()
        enrich_attack_surface_with_taint(surface, srv, None)
        assert srv.exists_queries == []
        assert surface["taint_summary"]["pairs_checked"] == 0


def _finding():
    return {
        "id": "FIND-0001",
        "file": "entry.c",
        "function": "parse_alpha",
        "line": 25,
        "vuln_type": "buffer_overflow",
        "status": "not_disproven",
        "proof": {"sink": "memcpy(out, buf + 1, claimed)"},
    }


def _flow():
    return FakeFlow(steps=[
        {"file": "entry.c", "line": 21, "code": "parse_alpha(buf, len)",
         "function": "parse_alpha"},
        {"file": "entry.c", "line": 25, "code": "memcpy(out, buf + 1, n)",
         "function": "parse_alpha"},
    ])


class TestConfirmFindingFlow:
    def test_confirmed_flow_returns_steps_and_proximity_floor(self):
        finding = _finding()
        srv = FakeServer(flows={("parse_alpha", "memcpy"): [_flow()]})
        result = confirm_finding_flow(finding, srv, _checklist())

        assert result["confirmed"] is True
        assert result["flow_count"] == 1
        assert result["proximity_floor"] == 2
        assert result["steps"][-1]["line"] == 25
        assert finding["joern_flow_confirmation"] is result

    def test_no_flow_is_unconfirmed_without_proximity_floor(self):
        result = confirm_finding_flow(_finding(), FakeServer(), _checklist())
        assert result["confirmed"] is False
        assert result["proximity_floor"] is None
        assert result["steps"] == []

    def test_sink_falls_back_to_call_graph(self):
        finding = _finding()
        del finding["proof"]
        finding["line"] = 38
        srv = FakeServer()
        confirm_finding_flow(finding, srv, _checklist())
        assert srv.flow_queries == [("parse_alpha", "strcpy")]

    def test_unresolvable_sink_skips(self):
        finding = _finding()
        del finding["proof"]
        finding["line"] = 99
        result = confirm_finding_flow(finding, FakeServer(), _checklist())
        assert result["confirmed"] is None
        assert "skipped" in result

    def test_query_error_skips(self):
        result = confirm_finding_flow(
            _finding(), FakeServer(error=True), _checklist())
        assert result["confirmed"] is None
        assert "skipped" in result


class TestIdentifierFullmatch:
    def test_trailing_newline_rejected(self):
        # fullmatch: a $-anchored match() admits "main\n".
        from core.orchestration.validate_joern import _is_identifier
        assert _is_identifier("parse_alpha") is True
        assert _is_identifier("parse_alpha\n") is False

    def test_trailing_newline_function_skips_confirmation(self):
        finding = {
            "function": "parse_alpha\n",
            "file": "entry.c",
            "line": 25,
            "proof": {"sink": "memcpy(out, buf, n)"},
        }
        srv = FakeServer()
        confirmation = confirm_finding_flow(finding, srv, _checklist())
        assert confirmation["confirmed"] is None
        assert "source method" in confirmation["skipped"]
        assert srv.flow_queries == []


class TestIrisSurfaceMerge:
    def _iris_store(self, tmp_path):
        from core.iris.specs import TaintSpec
        from core.iris.store import save_specs

        run_dir = tmp_path / "project" / "validate_1"
        run_dir.mkdir(parents=True)
        save_specs(run_dir, [
            TaintSpec(function="read_config", file="cfg.c", role="source"),
            TaintSpec(function="safe_copy", file="util.c", role="sink"),
        ])
        return run_dir

    def test_iris_entries_join_surface_with_provenance(self, tmp_path):
        run_dir = self._iris_store(tmp_path)
        surface = _attack_surface()
        srv = FakeServer()
        enrich_attack_surface_with_taint(
            surface, srv, _checklist(), iris_dir=run_dir,
        )
        iris_sources = [
            s for s in surface["sources"]
            if s.get("source_provenance") == "iris"
        ]
        iris_sinks = [
            s for s in surface["sinks"] if s.get("source") == "iris"
        ]
        assert len(iris_sources) == 1
        assert iris_sources[0]["function"] == "read_config"
        assert len(iris_sinks) == 1
        assert iris_sinks[0]["location"] == "iris:safe_copy"
        summary = surface["taint_summary"]
        assert summary["iris_sources_loaded"] == 1
        assert summary["iris_sinks_loaded"] == 1
        # The IRIS source/sink participate in pair enumeration.
        assert ("read_config", "safe_copy") in srv.exists_queries

    def test_iris_confirmed_flow_annotates(self, tmp_path):
        run_dir = self._iris_store(tmp_path)
        surface = _attack_surface()
        srv = FakeServer(verdicts={("read_config", "safe_copy"): True})
        enrich_attack_surface_with_taint(
            surface, srv, _checklist(), iris_dir=run_dir,
        )
        iris_source = next(
            s for s in surface["sources"]
            if s.get("source_provenance") == "iris"
        )
        assert iris_source["has_taint_flow"] is True
        assert "iris:safe_copy" in iris_source["taint_reaches_sinks"]

    def test_idempotent_no_duplicate_entries(self, tmp_path):
        run_dir = self._iris_store(tmp_path)
        surface = _attack_surface()
        enrich_attack_surface_with_taint(
            surface, FakeServer(), _checklist(), iris_dir=run_dir,
        )
        n_sources = len(surface["sources"])
        n_sinks = len(surface["sinks"])
        enrich_attack_surface_with_taint(
            surface, FakeServer(), _checklist(), iris_dir=run_dir,
        )
        assert len(surface["sources"]) == n_sources
        assert len(surface["sinks"]) == n_sinks

    def test_without_iris_dir_unchanged(self):
        surface = _attack_surface()
        enrich_attack_surface_with_taint(surface, FakeServer(), _checklist())
        assert surface["taint_summary"]["iris_sources_loaded"] == 0
        assert all(
            s.get("source_provenance") != "iris" for s in surface["sources"]
        )

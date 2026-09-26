"""Store-backed call-edge consumers: the orchestrator prep seam and
the precondition reachability gate.

Both consumers resolve the context map's ``call_edges_store`` marker
against the graph store's verdict-feeding view with the
store-absent → inconclusive floor: no store / no marker / no verified
lane changes nothing, a COMPLETE verified mechanical set lifts the
in-artifact truncation, and an INCOMPLETE one (tampered, deleted, or
llm-tier rows) forces truncation semantics. The load-bearing property
pinned here: an llm-tier or MAC-failing edge row NEVER flips a
reachable function to unreachable — every degraded shape lands on
inconclusive, not on a contradicted/supported unreachability verdict.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.audit import precondition_check as pc
from core.audit.orchestrator import _load_call_edges_from_store
from core.understand_graph.ingest import ingest_call_edges

_EDGES = [
    {"caller_file": "a.c", "caller": "main", "callee": "helper",
     "callee_file": "a.c"},
    {"caller_file": "a.c", "caller": "helper", "callee": "f",
     "callee_file": "a.c"},
    {"caller_file": "b.c", "caller": "orphan", "callee": "iso",
     "callee_file": "b.c"},
]


@pytest.fixture(autouse=True)
def _hermetic_ambient_state(tmp_path, monkeypatch):
    """Pin every ambient state root (real ProjectManager registry,
    XDG-keyed MAC key) to the test's tmp dir, and clear the
    precondition store-lane memo between tests."""
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))

    import core.project.project as project_mod
    import core.project.sessions as sessions_mod

    monkeypatch.setattr(
        project_mod, "PROJECTS_DIR", tmp_path / "projects-registry")
    monkeypatch.setattr(
        sessions_mod, "SESSIONS_DIR", tmp_path / "sessions.d")
    from core.audit import orchestrator as orch_mod

    orch_mod._GRAPH_STORE_MEMO.clear()
    pc._STORE_LANE_MEMO.clear()
    yield
    orch_mod._GRAPH_STORE_MEMO.clear()
    pc._STORE_LANE_MEMO.clear()


def _seed_store(tmp_path: Path, target: str = "/target"):
    out_dir = tmp_path / "out"
    out_dir.mkdir(exist_ok=True)
    graph = out_dir / "graph" / "raptor.graph.sqlite"
    result = ingest_call_edges(
        out_dir, target, list(_EDGES), graph_path=graph)
    assert result is not None
    return out_dir, graph, result


def _map_with_marker(result, *, shed: bool = True) -> dict:
    cm: dict = {
        "entry_points": [{"name": "main", "file": "a.c"}],
        "call_edges": [],
        "call_edges_store": {
            "snapshot": result["snapshot"], "edges": result["edges"],
        },
    }
    if shed:
        cm["call_edges_shed"] = "shed by the context-map size budget"
        cm["call_edges_truncated"] = True
    return cm


def _tamper_one_edge(graph: Path) -> None:
    raw = sqlite3.connect(graph)
    raw.execute("UPDATE nodes SET name='evil' WHERE name='f'")
    raw.commit()
    raw.close()


class TestOrchestratorSeam:
    def _config(self, out_dir: Path, target: str = "/target"):
        return SimpleNamespace(out_dir=out_dir, target_path=target)

    def test_complete_lane_replaces_edges_and_lifts_markers(self, tmp_path):
        out_dir, _graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        assert _load_call_edges_from_store(cm, self._config(out_dir)) is True
        assert len(cm["call_edges"]) == 3
        assert "call_edges_truncated" not in cm
        assert "call_edges_shed" not in cm

    def test_incomplete_lane_keeps_truncation(self, tmp_path):
        out_dir, graph, result = _seed_store(tmp_path)
        _tamper_one_edge(graph)
        cm = _map_with_marker(result)
        assert _load_call_edges_from_store(cm, self._config(out_dir)) is True
        assert len(cm["call_edges"]) == 2
        assert cm["call_edges_truncated"] is True

    def test_incomplete_lane_unions_with_map_edges(self, tmp_path):
        """Union, never replace: an incomplete verified subset must
        not drop the map's own hint-tier edges."""
        out_dir, graph, result = _seed_store(tmp_path)
        _tamper_one_edge(graph)
        cm = _map_with_marker(result)
        hint = {"caller_file": "c.c", "caller": "x", "callee": "y",
                "callee_file": "c.c"}
        cm["call_edges"] = [hint]
        assert _load_call_edges_from_store(cm, self._config(out_dir)) is True
        assert hint in cm["call_edges"]
        assert len(cm["call_edges"]) == 3  # 1 hint + 2 verified
        assert cm["call_edges_truncated"] is True

    def test_incomplete_lane_runs_bootstrap_then_unions(self, tmp_path):
        """An incomplete lane must not COST the hint coverage today's
        shed-map path derives: the caller's checklist bootstrap runs
        first (when the map still needs one), the verified subset
        unions in, and the store marker survives the rebuild."""
        out_dir, graph, result = _seed_store(tmp_path)
        _tamper_one_edge(graph)
        cm = _map_with_marker(result)  # shed shape: needs bootstrap
        marker = dict(cm["call_edges_store"])
        hint = {"caller_file": "c.c", "caller": "x", "callee": "y",
                "callee_file": "c.c"}

        def bootstrap():
            # Mimic enrich_with_call_edges: rebuild the array, clear
            # the stale markers (including the routing marker).
            cm["call_edges"] = [hint]
            cm.pop("call_edges_shed", None)
            cm.pop("call_edges_truncated", None)
            cm.pop("call_edges_store", None)

        assert _load_call_edges_from_store(
            cm, self._config(out_dir), bootstrap=bootstrap) is True
        assert hint in cm["call_edges"]
        assert len(cm["call_edges"]) == 3  # 1 bootstrap hint + 2 verified
        assert cm["call_edges_truncated"] is True
        assert cm["call_edges_store"] == marker  # restored after rebuild

    def test_no_marker_is_floor(self, tmp_path):
        out_dir, _graph, _result = _seed_store(tmp_path)
        cm = {"call_edges": [], "call_edges_shed": "shed"}
        assert _load_call_edges_from_store(cm, self._config(out_dir)) is False
        assert cm["call_edges"] == []

    def test_absent_store_is_floor(self, tmp_path):
        out_dir, graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        graph.unlink()
        for sidecar in ("-wal", "-shm"):
            p = graph.with_name(graph.name + sidecar)
            if p.exists():
                p.unlink()
        assert _load_call_edges_from_store(cm, self._config(out_dir)) is False
        assert cm["call_edges"] == []
        assert cm["call_edges_truncated"] is True

    def test_foreign_target_is_floor(self, tmp_path):
        out_dir, _graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        config = self._config(out_dir, target="/other-target")
        assert _load_call_edges_from_store(cm, config) is False
        assert cm["call_edges"] == []


class TestPreconditionStoreLane:
    """``_check_attacker_control`` with the store lane. ``f`` is
    reachable (main -> helper -> f); ``iso`` is named by an edge but
    unreachable from entry points."""

    def _check(self, graph: Path, cm: dict, func: str,
               *, expect_absent: bool, target: str | None = "/target"):
        return pc._check_attacker_control(
            "", "a.c", func, "", expect_absent, cm, graph, target)

    def test_complete_lane_walks_store_edges(self, tmp_path):
        _out, graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        # Claim: attacker does NOT control f. f IS reachable through
        # the store's verified edges (the map itself is shed/empty).
        res = self._check(graph, cm, "f", expect_absent=True)
        assert res.verdict == "contradicted"

    def test_complete_lane_allows_negative_conclusion(self, tmp_path):
        _out, graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        # iso is named by the graph but unreachable: with the full
        # verified set present, the unreachability claim is supported.
        res = self._check(graph, cm, "iso", expect_absent=True)
        assert res.verdict == "supported"
        assert res.grade == pc.GRADE_CONTEXT_MAP

    def test_mac_failing_row_never_flips_to_unreachable(self, tmp_path):
        """Tampering the edge that carries f's reachability must land
        on inconclusive — never a contradicted/supported
        unreachability verdict."""
        _out, graph, result = _seed_store(tmp_path)
        _tamper_one_edge(graph)
        cm = _map_with_marker(result)
        # Claim: attacker DOES control f (true before tampering).
        res = self._check(graph, cm, "f", expect_absent=False)
        assert res.verdict == "inconclusive"
        # Claim: attacker does NOT control f — tampering must not
        # mint the unreachability receipt either.
        pc._STORE_LANE_MEMO.clear()
        res = self._check(graph, cm, "f", expect_absent=True)
        assert res.verdict == "inconclusive"

    def test_llm_tier_row_never_flips_to_unreachable(self, tmp_path):
        """A function whose only path rides an llm-tier CALLS row:
        the row never enters the verified lane, and its exclusion
        lands on inconclusive (graph-incompleteness gate), not on an
        unreachability verdict."""
        _out, graph, result = _seed_store(tmp_path)
        from core.understand_graph import integrity

        conn = sqlite3.connect(graph)
        conn.row_factory = sqlite3.Row
        src = conn.execute(
            "SELECT id FROM nodes WHERE name='main'").fetchone()["id"]
        conn.execute(
            "INSERT INTO nodes (id, kind, stable_key, name, file, "
            "snapshot_id) VALUES ('n-llm', 'function', "
            "'function://a.c::g', 'g', 'a.c', ?)", (result["snapshot"],))
        token = integrity.edge_stamper(graph).mint(integrity.edge_payload(
            result["snapshot"], "a.c", "main", "a.c", "g")) or ""
        conn.execute(
            "INSERT INTO edges (id, src_id, dst_id, kind, snapshot_id, "
            "provenance, integrity) VALUES ('e-llm', ?, 'n-llm', 'CALLS', "
            "?, 'llm', ?)", (src, result["snapshot"], token))
        conn.commit()
        conn.close()
        cm = _map_with_marker(result)
        res = self._check(graph, cm, "g", expect_absent=False)
        assert res.verdict == "inconclusive"
        pc._STORE_LANE_MEMO.clear()
        res = self._check(graph, cm, "g", expect_absent=True)
        assert res.verdict == "inconclusive"

    def test_foreign_target_snapshot_is_floor(self, tmp_path):
        """The marker is artifact-writable; a snapshot recorded for
        ANOTHER target in a shared store never feeds this target's
        walk — the lane drops and today's semantics apply."""
        _out, graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        res = self._check(
            graph, cm, "f", expect_absent=True, target="/other-target")
        assert res.verdict == "inconclusive"

    def test_absent_store_preserves_todays_semantics(self, tmp_path):
        """No store: the truncated map degrades to inconclusive
        exactly as before the lane existed."""
        _out, graph, result = _seed_store(tmp_path)
        cm = _map_with_marker(result)
        missing = tmp_path / "nowhere" / "raptor.graph.sqlite"
        res = pc._check_attacker_control(
            "", "a.c", "f", "", False, cm, missing, "/target")
        assert res.verdict == "inconclusive"
        # And with no graph_store at all (today's call shape).
        res = pc._check_attacker_control("", "a.c", "f", "", False, cm)
        assert res.verdict == "inconclusive"

    def test_verify_preconditions_threads_graph_store(self, tmp_path):
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int f(char *s) { return s[0]; }\n")
        # Snapshot target must be the run's target: the gate scopes
        # the lane to verify_preconditions' own target_path.
        _out, graph, result = _seed_store(tmp_path, target=str(target))
        cm = _map_with_marker(result)
        verdict = pc.verify_preconditions(
            [{
                "check_type": "attacker_controls_input",
                "assumption": "f input is not attacker controlled",
                "location": {"file": "a.c", "function": "f"},
                "expect_absent": True,
            }],
            target_path=target,
            context_map=cm,
            graph_store=graph,
        )
        assert verdict.checks[0].verdict == "contradicted"


class TestBootstrapRoutesToStore:
    """The audit's in-memory bootstrap was the one call-edge producer
    that never ingested — an audit-built map could never grow the
    store lane, so kernel-scale runs carried the capped 26% forever.
    Pins: both prep-seam enrich calls pass the store args, and a
    routing bootstrap's fresh marker gets the complete lane replay."""

    def test_prep_seam_enrich_calls_carry_store_args(self):
        import inspect
        import core.audit.orchestrator as orch
        src = inspect.getsource(orch._prep_call_edges)
        # Both the store-lane bootstrap and the storeless fallback
        # must route: an unrouted call re-creates the never-ingests
        # producer. And the trailing consult must exist AFTER both
        # (order is behavior — see the helper docstring).
        assert src.count("graph_store=") >= 2
        assert src.count("run_dir=config.out_dir") >= 2
        assert "target_path=str(config.target_path" in src

    def test_marker_after_routing_bootstrap_triggers_complete_replay(
            self, tmp_path):
        # Shape pin on the trailing consult: a map whose bootstrap
        # just ingested (marker present) but which still carries the
        # capped list + truncation flag gets the complete verified
        # lane on the follow-up _load_call_edges_from_store call.
        out_dir, graph, result = _seed_store(tmp_path)
        cmap = {
            "call_edges": [dict(_EDGES[0])],  # capped subset
            "call_edges_truncated": True,
            "call_edges_store": {
                "snapshot": result["snapshot"], "edges": len(_EDGES)},
        }
        config = SimpleNamespace(
            out_dir=out_dir, target_path=Path("/target"))
        assert _load_call_edges_from_store(cmap, config) is True
        assert len(cmap["call_edges"]) == len(_EDGES)
        assert not cmap.get("call_edges_truncated")

    def test_fresh_map_end_to_end_gets_the_full_graph(
            self, tmp_path, monkeypatch):
        # THE motivating scenario, driven through the real seam: a
        # fresh audit-built map (no marker, no edges) over a
        # checklist whose graph exceeds the in-artifact cap must end
        # with the COMPLETE verified set in memory and truncation
        # lifted — in-run, not just at the next resume.
        import core.audit.orchestrator as orch
        import core.orchestration.context_map_callgraph as cmc
        monkeypatch.setattr(cmc, "_MAX_CALL_EDGES", 2)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        checklist = {
            "target_path": "/target",
            "files": [{
                "path": "a.c",
                "call_graph": {"calls": [
                    {"caller": "main", "chain": ["helper"]},
                    {"caller": "helper", "chain": ["f"]},
                    {"caller": "orphan", "chain": ["iso"]},
                ]},
                "items": [],
            }],
        }
        cmap: dict = {}
        config = SimpleNamespace(
            out_dir=out_dir, target_path=Path("/target"))
        orch._prep_call_edges(cmap, config, checklist)
        assert cmap.get("call_edges_store"), "bootstrap must ingest"
        assert len(cmap["call_edges"]) == 3  # full graph, not the cap
        assert not cmap.get("call_edges_truncated")

    def test_incomplete_lane_union_is_deduplicated(self, tmp_path):
        # A repeated consult over an incomplete lane must not double
        # the verified rows (kernel scale: ~2x lean dicts for the
        # whole run).
        out_dir, graph, result = _seed_store(tmp_path)
        _tamper_one_edge(graph)
        cmap = {
            "call_edges": [dict(_EDGES[0])],
            "call_edges_truncated": True,
            "call_edges_store": {
                "snapshot": result["snapshot"], "edges": len(_EDGES)},
        }
        config = SimpleNamespace(
            out_dir=out_dir, target_path=Path("/target"))
        _load_call_edges_from_store(cmap, config)
        n_first = len(cmap["call_edges"])
        _load_call_edges_from_store(cmap, config)
        assert len(cmap["call_edges"]) == n_first  # no duplicates
        assert cmap.get("call_edges_truncated") is True


class TestTruncatedProvenanceNeverTrustedOnly:
    """A truncated edge list cannot support the NEGATIVE conclusion
    'reachable only from trusted entry points' — a dropped
    untrusted-entry path reads as trusted-only and suppresses the
    finding. The sentinel makes both consumers fail toward keeping
    it."""

    @staticmethod
    def _cmap(truncated: bool):
        return {
            "entry_points": [{
                "id": "EP-1", "name": "admin_cli", "type": "cli",
                "function": "main", "file": "a.c",
                "trust": "trusted",
            }],
            "call_edges": [{
                "caller_file": "a.c", "caller": "main",
                "callee": "f", "callee_file": "a.c",
            }],
            "call_edges_truncated": truncated,
        }

    def test_untruncated_map_still_concludes_trusted_only(self):
        from core.audit.mechanical_gates import build_provenance_map
        prov = build_provenance_map(self._cmap(False))
        for reaching in prov.values():
            assert all(e.get("trust") == "trusted" for e in reaching)

    def test_truncated_map_never_reads_all_trusted(self):
        from core.audit.mechanical_gates import (
            build_provenance_map,
            format_provenance_for_context,
        )
        prov = build_provenance_map(self._cmap(True))
        assert prov  # positive tags survive
        for reaching in prov.values():
            # The orchestrator's provenance_all_trusted condition
            # (all trusted) must fail...
            assert not all(
                e.get("trust", "") == "trusted" for e in reaching)
            # ...and the prompt block must not render 'Do not flag'.
            block = format_provenance_for_context(reaching)
            assert "Do not flag" not in block

"""Edge-obligation scoping pass (core.audit.edge_obligations).

Synthetic fixtures shaped like the validation bar: a boundary-incident
edge (tier 1), an interior on-path edge — the CopyFail shape, where
both endpoints share a trust domain and only the source→sink scope
obligates the edge (tier 2) — plus dispatch/indirection blind spots.
"""

from __future__ import annotations

from core.audit.edge_obligations import (
    EDGE_OBLIGATIONS_FILENAME,
    build_and_write,
    build_edge_obligations,
)

# entry.c: handle_input (entry point + trust-boundary check inside it)
#   calls process() at line 10.
# mid.c: process calls page_op() at line 15 and helper() at line 16.
# sink.c: page_op is the sink. helper.c: helper reaches no sink.
_CHECKLIST = {
    "files": [
        {"path": "entry.c",
         "items": [{"name": "handle_input", "line_start": 1, "line_end": 20}],
         "call_graph": {"calls": [
             {"line": 10, "chain": ["process"], "caller": "handle_input"},
         ], "indirection": [], "getattr_targets": []}},
        {"path": "mid.c",
         "items": [{"name": "process", "line_start": 1, "line_end": 30}],
         "call_graph": {"calls": [
             {"line": 15, "chain": ["page_op"], "caller": "process"},
             {"line": 16, "chain": ["helper"], "caller": "process"},
         ], "indirection": ["fn_ptr_dispatch"], "getattr_targets": []}},
        {"path": "sink.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 9}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
        {"path": "helper.c",
         "items": [{"name": "helper", "line_start": 1, "line_end": 9}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ],
}

_CONTEXT_MAP = {
    "entry_points": [{"id": "EP-001", "file": "entry.c", "line": 2}],
    "sinks": [{"type": "memory", "location": "sink.c:5"}],
    "trust_boundaries": [
        {"boundary": "input gate", "check": "entry.c:3"},
    ],
}


def _keys(records):
    return {(r["caller"], r["callee"]) for r in records}


def test_boundary_incident_edge_is_tier1():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert ("handle_input", "process") in _keys(payload["tier1"])
    t1 = next(r for r in payload["tier1"] if r["caller"] == "handle_input")
    assert t1["reason"] == "boundary:input gate"
    assert t1["call_line"] == 10


def test_interior_on_path_edge_is_tier2_copyfail_shape():
    # process→page_op crosses no boundary; only the source→sink scope
    # obligates it. This is the assertion-1 shape from the validation
    # plan: the known-bad interior edge MUST be in the obligation set.
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert ("process", "page_op") in _keys(payload["tier2"])
    assert ("process", "page_op") not in _keys(payload["tier1"])


def test_off_path_edge_not_obligated():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    all_obligated = _keys(payload["tier1"]) | _keys(payload["tier2"])
    assert ("process", "helper") not in all_obligated


def test_deterministic_and_touched_never_satisfies():
    # Assertion-2 shape: re-running reproduces the set, and a touched
    # (traced) edge stays an obligation — touched is extent, not review.
    touched = [{"caller_file": "mid.c", "caller": "process",
                "callee_file": "sink.c", "callee": "page_op",
                "call_line": 15, "source": "flow-trace-1.json"}]
    a = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP, touched=touched)
    b = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP, touched=touched)
    assert a == b
    rec = next(r for r in a["tier2"] if r["callee"] == "page_op")
    assert rec["touched"] is True


def test_ambiguous_callee_is_one_blind_spot_not_fanout():
    checklist = {"files": [
        dict(_CHECKLIST["files"][0]),
        dict(_CHECKLIST["files"][1]),
        {"path": "impl_a.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 5}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
        {"path": "impl_b.c",
         "items": [{"name": "page_op", "line_start": 1, "line_end": 5}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ]}
    cm = {
        "entry_points": [{"id": "EP-001", "file": "entry.c", "line": 2}],
        "sinks": [{"type": "memory", "location": "impl_a.c:2"}],
        "trust_boundaries": [],
    }
    payload = build_edge_obligations(checklist, cm)
    # No phantom obligations for either candidate definition.
    assert not any(r["callee"] == "page_op"
                   for r in payload["tier1"] + payload["tier2"])
    assert payload["stats"]["ambiguous"] >= 1
    # On-path caller → surfaced as a single ambiguous_callee blind spot.
    spots = [b for b in payload["blind_spots"]
             if b["kind"] == "ambiguous_callee" and b["name"] == "page_op"]
    assert len(spots) == 1


def test_indirection_on_attack_path_is_blind_spot():
    payload = build_edge_obligations(_CHECKLIST, _CONTEXT_MAP)
    assert {"file": "mid.c", "caller": None, "kind": "indirection",
            "name": "fn_ptr_dispatch"} in payload["blind_spots"]


def test_caller_falls_back_to_containing_item():
    checklist = {"files": [
        {"path": "entry.c",
         "items": [{"name": "handle_input", "line_start": 1,
                    "line_end": 20}],
         # extractor didn't capture ``caller`` — resolve by line.
         "call_graph": {"calls": [{"line": 10, "chain": ["process"]}],
                        "indirection": [], "getattr_targets": []}},
        {"path": "mid.c",
         "items": [{"name": "process", "line_start": 1, "line_end": 30}],
         "call_graph": {"calls": [], "indirection": [],
                        "getattr_targets": []}},
    ]}
    payload = build_edge_obligations(checklist, _CONTEXT_MAP)
    assert ("handle_input", "process") in _keys(payload["tier1"])


def test_degrades_honestly_without_context_map():
    payload = build_edge_obligations(_CHECKLIST, None)
    assert payload["tier1"] == [] and payload["tier2"] == []
    assert "no-context-map" in payload["stats"]["degraded"]


def test_degrades_honestly_without_anchors():
    payload = build_edge_obligations(_CHECKLIST, {"entry_points": []})
    assert "no-boundary-anchors" in payload["stats"]["degraded"]
    assert "no-path-anchors" in payload["stats"]["degraded"]


def test_build_and_write_persists(tmp_path):
    import json
    payload = build_and_write(tmp_path, _CHECKLIST, _CONTEXT_MAP)
    on_disk = json.loads(
        (tmp_path / EDGE_OBLIGATIONS_FILENAME).read_text(encoding="utf-8"))
    assert on_disk == payload
    assert on_disk["schema_version"] == 1


class TestKnowledgeDegradation:
    def test_extra_degraded_lands_in_stats(self, tmp_path):
        from core.audit.edge_obligations import build_and_write
        checklist = {"target_path": str(tmp_path), "files": []}
        payload = build_and_write(
            tmp_path, checklist, None,
            extra_degraded=["no-domain-model"])
        assert "no-domain-model" in payload["stats"]["degraded"]
        import json
        on_disk = json.loads(
            (tmp_path / "edge-obligations.json").read_text())
        assert "no-domain-model" in on_disk["stats"]["degraded"]

    def test_no_duplicate_degradation_entries(self, tmp_path):
        from core.audit.edge_obligations import build_and_write
        checklist = {"target_path": str(tmp_path), "files": []}
        payload = build_and_write(
            tmp_path, checklist, None,
            extra_degraded=["no-context-map"])
        assert payload["stats"]["degraded"].count("no-context-map") == 1


class TestDispatchResolution:
    """CHA-ambiguous callees resolve to tier-1 via mechanical witnesses."""

    def _checklist(self, tmp_path, extra_item_a=None, call_extra=None):
        (tmp_path / "a.py").write_text("class Foo:\n    def run(self): pass\n")
        (tmp_path / "b.py").write_text("def run(): pass\n")
        (tmp_path / "ep.py").write_text("def handler(): run()\n")
        item_a = {"name": "run", "kind": "method",
                  "line_start": 2, "line_end": 2}
        if extra_item_a:
            item_a.update(extra_item_a)
        call = {"line": 1, "chain": ["run"], "caller": "handler"}
        if call_extra:
            call.update(call_extra)
        return {
            "target_path": str(tmp_path),
            "files": [
                {"path": "a.py", "items": [
                    {"name": "Foo", "kind": "class",
                     "line_start": 1, "line_end": 2},
                    item_a,
                ], "call_graph": {"calls": []}},
                {"path": "b.py", "items": [
                    {"name": "run", "kind": "function",
                     "line_start": 1, "line_end": 1},
                ], "call_graph": {"calls": []}},
                {"path": "ep.py", "items": [
                    {"name": "handler", "kind": "function",
                     "line_start": 1, "line_end": 1},
                ], "call_graph": {"calls": [call]}},
            ],
        }

    # The resolved callee is sink-bearing so the promoted edge is
    # ON-PATH — promotion requires attack-path membership, not mere
    # entry-reachability (cost scoping per the 2026-05-29 design).
    _CM = {"entry_points": [{"file": "ep.py", "line": 1, "name": "handler"}],
           "sinks": [{"type": "x", "location": "a.py:2"}]}
    _CM_NO_SINK = {"entry_points":
                   [{"file": "ep.py", "line": 1, "name": "handler"}],
                   "sinks": []}

    def test_typed_receiver_resolves_to_tier1(self, tmp_path):
        from core.audit.edge_obligations import build_edge_obligations
        ck = self._checklist(tmp_path, call_extra={"receiver_type": "Foo"})
        ob = build_edge_obligations(ck, self._CM)
        t1 = [(e["callee_file"], e["reason"]) for e in ob["tier1"]]
        assert ("a.py", "dispatch:typed") in t1
        assert not any(b["kind"] == "ambiguous_callee"
                       for b in ob["blind_spots"])
        assert ob["stats"]["dispatch_resolved"] == 1

    def test_binary_edge_witness_resolves_to_tier1(self, tmp_path):
        from core.audit.edge_obligations import build_edge_obligations
        ck = self._checklist(tmp_path, extra_item_a={
            "metadata": {"binary_oracle_edges": [
                {"caller": "handler", "binary_path": "build/app"}]},
        })
        ob = build_edge_obligations(ck, self._CM)
        t1 = [(e["callee_file"], e["reason"]) for e in ob["tier1"]]
        assert ("a.py", "dispatch:binary") in t1

    def test_resolved_but_off_path_carries_no_obligation(self, tmp_path):
        # Resolution always improves the adjacency; the PAID dedicated
        # unit exists only on the attack path. Off-path resolved sites
        # are neither obligations nor blind spots.
        from core.audit.edge_obligations import build_edge_obligations
        ck = self._checklist(tmp_path, call_extra={"receiver_type": "Foo"})
        ob = build_edge_obligations(ck, self._CM_NO_SINK)
        assert not ob["tier1"]
        assert not any(b["kind"] == "ambiguous_callee"
                       for b in ob["blind_spots"])
        assert ob["stats"]["dispatch_resolved"] == 1

    def test_unwitnessed_ambiguity_stays_blind_spot(self, tmp_path):
        from core.audit.edge_obligations import build_edge_obligations
        ck = self._checklist(tmp_path)
        ob = build_edge_obligations(ck, self._CM)
        assert not ob["tier1"]
        assert any(b["kind"] == "ambiguous_callee" and b["name"] == "run"
                   for b in ob["blind_spots"])
        assert ob["stats"]["dispatch_resolved"] == 0

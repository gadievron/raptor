"""Tests for the producer-side context-map size budget."""

from __future__ import annotations

import copy
import json
from pathlib import Path
from typing import Any

from core.artifacts import context_map_budget as cmb
from core.json import dumps_artifact, load_json


def _llm_entry(i: int) -> dict[str, Any]:
    return {
        "id": f"EP-{i:03d}",
        "name": f"handler_{i}",
        "file": "app.py",
        "line": 10 + i,
        "notes": "LLM-authored narrative " + "n" * 200,
        "ast_view": {"signature": f"handler_{i}()", "calls": ["a", "b"]},
        "forward_reachable": {
            "host": f"app.handler_{i}",
            "internal_count": 2,
            "external_count": 1,
            "internal_names": ["app.x", "app.y"],
            "external_names": ["os.read"],
            "truncated": False,
        },
    }


def _synth_entry(i: int) -> dict[str, Any]:
    return {
        "id": f"EP-LIB-{i:03d}",
        "type": "library_api",
        "name": f"export_{i}",
        "file": "lib.c",
        "line": i,
        "origin": "inventory-entry",
        "ast_view": {"signature": f"export_{i}()", "body": "x" * 2000},
        "forward_reachable": {
            "host": f"lib.export_{i}",
            "internal_count": 50,
            "external_count": 50,
            "internal_names": [f"lib.fn_{j}" for j in range(50)],
            "external_names": [f"ext.fn_{j}" for j in range(50)],
            "truncated": False,
        },
    }


def _context_map(n_llm: int = 2, n_synth: int = 6) -> dict[str, Any]:
    return {
        "target_kind": "library",
        "entry_points": (
            [_llm_entry(i) for i in range(n_llm)]
            + [_synth_entry(i) for i in range(n_synth)]
        ),
        "sink_details": [{"id": "SINK-001", "file": "app.py", "line": 5}],
    }


def _synth_eps(m: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in m["entry_points"]
            if e.get("origin") == "inventory-entry"]


def _llm_eps(m: dict[str, Any]) -> list[dict[str, Any]]:
    return [e for e in m["entry_points"]
            if e.get("origin") != "inventory-entry"]


def test_within_budget_is_untouched():
    m = _context_map()
    before = copy.deepcopy(m)
    applied = cmb.enforce_context_map_budget(
        m, budget_bytes=cmb._serialized_size(m) + 1)
    assert applied == []
    assert m == before


def test_non_dict_is_noop():
    assert cmb.enforce_context_map_budget([1, 2]) == []  # type: ignore[arg-type]


def test_step1_drops_only_synth_ast_views():
    m = _context_map()
    # Budget = exactly what step 1 alone achieves.
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 1
    assert applied[0].startswith("dropped ast_view")
    assert all("ast_view" not in e for e in _synth_eps(m))
    # LLM-authored entries keep every payload.
    for e in _llm_eps(m):
        assert "ast_view" in e
        assert e["forward_reachable"]["internal_names"]
    # Step 2 did not run.
    for e in _synth_eps(m):
        assert e["forward_reachable"]["internal_names"]
    assert cmb._serialized_size(m) <= budget


def test_step2_drops_name_lists_keeps_counts():
    m = _context_map()
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    cmb._drop_synth_reachable_names(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 2
    assert applied[1].startswith("dropped forward_reachable")
    for e in _synth_eps(m):
        fr = e["forward_reachable"]
        assert fr["internal_names"] == []
        assert fr["external_names"] == []
        assert fr["internal_count"] == 50
        assert fr["truncated"] is True
    # LLM-authored closures survive with names.
    for e in _llm_eps(m):
        assert e["forward_reachable"]["internal_names"] == ["app.x", "app.y"]
        assert e["forward_reachable"]["truncated"] is False
    assert len(_synth_eps(m)) == 6  # step 3 did not run


def test_step3_caps_synth_entries_never_llm():
    m = _context_map()
    # Budget = the map with ALL synthesized entries gone: forces the cap.
    sim = copy.deepcopy(m)
    sim["entry_points"] = _llm_eps(sim)
    budget = cmb._serialized_size(sim)

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert len(applied) == 3
    assert applied[2].startswith("capped synthesized entry points")
    assert len(_llm_eps(m)) == 2          # untouched
    assert _synth_eps(m) == []            # all shed
    assert cmb._serialized_size(m) <= budget


def test_step3_partial_cap_keeps_prefix():
    m = _context_map()
    original_synth_ids = [e["id"] for e in _synth_eps(m)]
    # Budget between "steps 1+2" and "everything gone": some synthesized
    # entries must survive, shed from the tail.
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    cmb._drop_synth_reachable_names(sim)
    sim_eps = sim["entry_points"]
    del sim_eps[-2:]                      # drop last two synthesized
    budget = cmb._serialized_size(sim)

    cmb.enforce_context_map_budget(m, budget_bytes=budget)
    kept_ids = [e["id"] for e in _synth_eps(m)]
    assert kept_ids                       # not everything shed
    assert kept_ids == original_synth_ids[: len(kept_ids)]  # prefix, tail-first
    assert len(_llm_eps(m)) == 2
    assert cmb._serialized_size(m) <= budget


def test_llm_only_overage_is_never_degraded():
    m = {"entry_points": [_llm_entry(i) for i in range(4)]}
    before = copy.deepcopy(m)
    applied = cmb.enforce_context_map_budget(m, budget_bytes=64)
    assert applied == []
    assert m == before


def test_producer_budget_below_consumer_cap():
    assert (cmb.CONTEXT_MAP_PRODUCER_BUDGET_BYTES
            < cmb.CONTEXT_MAP_CONSUMER_MAX_BYTES)


def _machine_sink(i: int, source: str = "mechanical") -> dict[str, Any]:
    return {
        "id": f"SINK-{i:04d}",
        "type": "dangerous_call",
        "file": "lib.c",
        "line": i,
        "source": source,
        "description": "machine-discovered sink " + "s" * 500,
    }


def _llm_sink(i: int) -> dict[str, Any]:
    return {
        "id": f"SINK-N-{i:03d}",
        "type": "shell_exec",
        "file": "app.py",
        "line": i,
        "notes": "LLM-authored sink narrative " + "n" * 100,
    }


def test_machine_sinks_capped_before_synth_entry_points():
    m = _context_map(n_llm=1, n_synth=2)
    m["sink_details"] = [_llm_sink(1)] + [
        _machine_sink(i, "mechanical" if i % 2 else "heuristic")
        for i in range(400)
    ]
    budget = cmb._serialized_size(_context_map(n_llm=1, n_synth=2)) + 2_000
    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert any("machine-generated sink" in a for a in applied)
    # LLM-authored sink survives every step.
    assert any(s.get("id") == "SINK-N-001" for s in m["sink_details"])
    # Synthesized entry points are the LAST resort — with the sink cap
    # able to shed enough, they must survive.
    assert len(_synth_eps(m)) == 2
    assert cmb._serialized_size(m) <= budget


def test_stamped_flat_sinks_are_capped():
    m = _context_map(n_llm=1, n_synth=0)
    m["sinks"] = [_llm_sink(0)] + [
        {"file": f"lib{i}.c", "function": f"f{i}", "target": "os.system",
         "direct": True, "source": "mechanical",
         "pad": "p" * 500}
        for i in range(300)
    ]
    budget = cmb._serialized_size(_context_map(n_llm=1, n_synth=0)) + 2_000
    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert any("machine-generated sink" in a for a in applied)
    assert any(s.get("id") == "SINK-N-000" for s in m["sinks"])
    assert cmb._serialized_size(m) <= budget


def _independent_sizes(m: dict[str, Any]) -> tuple[int, int]:
    """(compact, indented) byte sizes measured WITHOUT the module under
    test — stdlib json only — so the fixture shape cannot drift with
    the governor's own encoder choices."""
    compact = len(json.dumps(m, separators=(",", ":")).encode("utf-8"))
    indented = len(json.dumps(m, indent=2).encode("utf-8"))
    return compact, indented


def test_indented_overage_compact_fit_is_lossless() -> None:
    """Compact serialization is the first, lossless lever: a map whose
    INDENTED serialization exceeds the budget must not be degraded when
    its compact encoding fits — the compact form is what reaches disk."""
    m = _context_map(n_llm=2, n_synth=40)
    compact, indented = _independent_sizes(m)
    budget = (compact + indented) // 2
    assert compact <= budget < indented  # the defect's shape

    before = copy.deepcopy(m)
    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert applied == []
    assert m == before


def test_save_context_map_round_trip(tmp_path: Path) -> None:
    """The written artifact is compact, consumer-loadable under the
    read cap, and parses back to exactly the enforced data."""
    m = _context_map()
    path = tmp_path / "context-map.json"
    applied = cmb.save_context_map(path, m)
    assert applied == []

    raw = path.read_text(encoding="utf-8")
    assert raw == dumps_artifact(m, indent=None) + "\n"
    assert "\n" not in raw.rstrip("\n")  # single compact line

    loaded = load_json(path, max_bytes=cmb.CONTEXT_MAP_CONSUMER_MAX_BYTES)
    assert loaded == m


def test_save_context_map_within_indented_overage(tmp_path: Path) -> None:
    """End-to-end defect shape: indented size over budget, compact
    fits — nothing dropped, on-disk size within budget, loadable."""
    m = _context_map(n_llm=2, n_synth=40)
    compact, indented = _independent_sizes(m)
    budget = (compact + indented) // 2
    before = copy.deepcopy(m)

    path = tmp_path / "context-map.json"
    applied = cmb.save_context_map(path, m, budget_bytes=budget)
    assert applied == []
    assert m == before
    # +1 for the trailing newline; the producer budget carries far
    # more headroom below the consumer cap than that.
    assert path.stat().st_size <= budget + 1
    assert load_json(path, max_bytes=budget + 1) == before


def test_save_context_map_degrades_when_compact_over(tmp_path: Path) -> None:
    """When even the compact encoding exceeds the budget, lossy
    degradation proceeds as before and the result is written."""
    m = _context_map(n_llm=2, n_synth=6)
    sim = copy.deepcopy(m)
    cmb._drop_synth_ast_views(sim)
    budget = cmb._serialized_size(sim)

    path = tmp_path / "context-map.json"
    applied = cmb.save_context_map(path, m, budget_bytes=budget)
    assert len(applied) == 1
    assert applied[0].startswith("dropped ast_view")
    assert path.stat().st_size <= budget + 1
    assert load_json(path, max_bytes=budget + 1) == m  # enforced in place


def test_save_context_map_sort_keys(tmp_path: Path) -> None:
    m = {"z": 1, "a": {"c": 2, "b": 3}}
    path = tmp_path / "context-map.json"
    cmb.save_context_map(path, m, sort_keys=True)
    raw = path.read_text(encoding="utf-8")
    assert raw.index('"a"') < raw.index('"z"')
    assert load_json(path) == m


def test_llm_sinks_never_dropped():
    m = _context_map(n_llm=1, n_synth=0)
    m["sink_details"] = [_llm_sink(i) for i in range(50)]
    m["sinks"] = [_llm_sink(i) for i in range(50)]
    tiny = 1_000
    before = copy.deepcopy(m["sink_details"])
    cmb.enforce_context_map_budget(m, budget_bytes=tiny)
    assert m["sink_details"] == before
    assert len(m["sinks"]) == 50


# ---------------------------------------------------------------------------
# whole regenerable enricher payloads (call_edges / transitive_reach)
# ---------------------------------------------------------------------------


def _bulk_map(n_edges: int = 200, n_reach: int = 400,
              n_llm: int = 2) -> dict[str, Any]:
    """LLM narrative entries + the two unstamped mechanical bulk keys."""
    return {
        "entry_points": [_llm_entry(i) for i in range(n_llm)],
        "call_edges": [
            {"caller_file": "src/a.c", "caller": f"fn_{i}",
             "callee": f"callee_{i}", "callee_file": "src/b.c"}
            for i in range(n_edges)
        ],
        "sink_discovery": {
            "direct_sinks": [],
            "transitive_reach": [
                {"file": "src/a.c", "function": f"fn_{i}", "distance": 2,
                 "reachable_sinks": ["memcpy", "system"]}
                for i in range(n_reach)
            ],
        },
    }


def _size_without_bulk(m: dict[str, Any]) -> int:
    hollow = copy.deepcopy(m)
    hollow["call_edges"] = []
    hollow["sink_discovery"]["transitive_reach"] = []
    return cmb._serialized_size(hollow)


def test_sheds_mechanical_bulk_never_narrative():
    m = _bulk_map()
    narrative_before = copy.deepcopy(m["entry_points"])
    # Budget fits the map once BOTH bulk payloads are shed (plus room
    # for the markers), but not before.
    budget = _size_without_bulk(m) + 1_000
    assert cmb._serialized_size(m) > budget

    applied = cmb.enforce_context_map_budget(m, budget_bytes=budget)

    assert cmb._serialized_size(m) <= budget
    # Mechanical keys shed, markers name the regeneration commands.
    assert m["call_edges"] == []
    assert "raptor-enrich-context-map-callgraph" in m["call_edges_shed"]
    assert m["call_edges_truncated"] is True
    sd = m["sink_discovery"]
    assert sd["transitive_reach"] == []
    assert "raptor-enrich-context-map-sinks" in sd["transitive_reach_shed"]
    # Narrative entries byte-identical.
    assert m["entry_points"] == narrative_before
    # Applied descriptions surface the loss and the remedy.
    assert any("call_edges" in a and "raptor-enrich-context-map-callgraph"
               in a for a in applied)
    assert any("transitive_reach" in a and "raptor-enrich-context-map-sinks"
               in a for a in applied)


def test_sheds_largest_payload_first_and_stops_when_fitting():
    # transitive_reach is by far the larger payload; a budget that fits
    # once it alone is shed must leave call_edges intact.
    m = _bulk_map(n_edges=20, n_reach=2_000)
    edges_before = copy.deepcopy(m["call_edges"])
    hollow = copy.deepcopy(m)
    hollow["sink_discovery"]["transitive_reach"] = []
    budget = cmb._serialized_size(hollow) + 1_000
    assert cmb._serialized_size(m) > budget

    cmb.enforce_context_map_budget(m, budget_bytes=budget)

    assert cmb._serialized_size(m) <= budget
    assert m["sink_discovery"]["transitive_reach"] == []
    assert "transitive_reach_shed" in m["sink_discovery"]
    assert m["call_edges"] == edges_before
    assert "call_edges_shed" not in m
    assert "call_edges_truncated" not in m


def test_shed_is_idempotent():
    m = _bulk_map()
    budget = _size_without_bulk(m) + 1_000
    cmb.enforce_context_map_budget(m, budget_bytes=budget)
    after_first = copy.deepcopy(m)
    applied_again = cmb.enforce_context_map_budget(m, budget_bytes=budget)
    assert applied_again == []
    assert m == after_first


def test_still_over_budget_warning_states_consumer_consequence(caplog):
    # Pure LLM narrative overage: nothing degradable — the warning must
    # say what the consumer side does with the artifact.
    m = {"entry_points": [_llm_entry(i) for i in range(20)]}
    with caplog.at_level("WARNING", logger="core.artifacts.context_map_budget"):
        cmb.enforce_context_map_budget(m, budget_bytes=100)
    messages = [r.getMessage() for r in caplog.records]
    assert any("refuse the WHOLE artifact" in msg for msg in messages)
    assert any("proceeds mapless" in msg for msg in messages)

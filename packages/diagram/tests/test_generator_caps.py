"""Element-cap discipline across generators (shared caps helper).

flow_trace landed the cap+loud-marker pattern; these tests pin its
adoption in the generators that rendered unbounded — attack_paths,
hypotheses, attack_tree, context_map — plus the attack-paths markdown
byte budget (that generator self-fences, so the renderer's last-hop
_fence budget never applies to it). Two directions per cap: content
under the cap renders in full with no marker; content over the cap is
bounded AND announced.
"""

from __future__ import annotations

from packages.diagram import (
    attack_paths,
    attack_tree,
    context_map,
    hypotheses,
)

_MARKER = "⚠ Diagram truncated"


# ---------------------------------------------------------------------
# attack_paths
# ---------------------------------------------------------------------


def _path(i: int, n_steps: int = 2) -> dict:
    return {
        "id": f"PATH-{i}",
        "name": f"path {i}",
        "proximity": 3,
        "status": "uncertain",
        "steps": [
            {"type": "call", "description": f"step {j}"}
            for j in range(n_steps)
        ],
    }


def test_attack_paths_step_cap_is_loud():
    out = attack_paths.generate([_path(1, n_steps=100_000)])
    assert len(out) < 300_000
    assert _MARKER in out
    assert "additional steps not shown" in out


def test_attack_paths_under_cap_untouched():
    out = attack_paths.generate([_path(1, n_steps=5)])
    assert _MARKER not in out
    assert "section truncated" not in out


def test_attack_paths_path_cap_is_loud():
    out = attack_paths.generate([_path(i) for i in range(300)])
    assert out.count("#### ") <= attack_paths._MAX_PATHS
    assert "Attack-paths section truncated" in out


def test_attack_paths_blocker_cap_is_loud():
    p = _path(1)
    p["blockers"] = [f"blocker {i}" for i in range(500)]
    out = attack_paths.generate([p])
    assert _MARKER in out
    assert "additional blockers not shown" in out


def test_attack_paths_byte_budget_cuts_at_block_boundary():
    # Big-but-under-path-cap input that exceeds the byte budget: the
    # output must stay bounded, end with the loud truncation note and
    # carry balanced fences (no mid-fence cut).
    paths = [_path(i, n_steps=200) for i in range(40)]
    out = attack_paths.generate(paths)
    assert len(out) < attack_paths._MAX_SECTION_BYTES + 10_000
    assert "Attack-paths section truncated" in out
    assert out.count("```") % 2 == 0


# ---------------------------------------------------------------------
# hypotheses
# ---------------------------------------------------------------------


def _hyp(i: int, n_preds: int = 1) -> dict:
    return {
        "id": f"H-{i}",
        "claim": f"claim {i}",
        "status": "testing",
        "predictions": [
            {"id": f"P-{i}-{j}", "prediction": "p", "status": "testing"}
            for j in range(n_preds)
        ],
    }


def test_hypotheses_cap_is_loud():
    out = hypotheses.generate([_hyp(i) for i in range(5_000)])
    assert len(out) < 2_000_000
    assert _MARKER in out
    assert "additional hypotheses not shown" in out


def test_hypotheses_prediction_cap_is_loud():
    out = hypotheses.generate([_hyp(1, n_preds=10_000)])
    assert len(out) < 500_000
    assert "additional predictions not shown" in out


def test_hypotheses_under_cap_untouched():
    out = hypotheses.generate([_hyp(i, n_preds=3) for i in range(10)])
    assert _MARKER not in out


# ---------------------------------------------------------------------
# attack_tree
# ---------------------------------------------------------------------


def _tree(n: int) -> dict:
    return {
        "root": "N0",
        "nodes": [
            {"id": f"N{i}", "goal": f"g{i}", "technique": "t",
             "status": "unexplored", "leads_to": ""}
            for i in range(n)
        ],
    }


def test_attack_tree_node_cap_is_loud():
    out = attack_tree.generate(_tree(50_000))
    assert len(out) < 2_000_000
    assert _MARKER in out
    assert "additional nodes not shown" in out


def test_attack_tree_under_cap_untouched():
    out = attack_tree.generate(_tree(10))
    assert _MARKER not in out


# ---------------------------------------------------------------------
# context_map
# ---------------------------------------------------------------------


def test_context_map_sink_cap_is_loud():
    data = {
        "entry_points": [
            {"id": "EP-1", "path": "/x", "file": "a.py", "line": 1},
        ],
        "boundary_details": [],
        "sink_details": [
            {"id": f"SINK-{i}", "operation": f"op{i}",
             "file": "b.py", "line": i}
            for i in range(5_000)
        ],
        "unchecked_flows": [],
    }
    out = context_map.generate(data)
    assert len(out) < 2_000_000
    assert _MARKER in out
    assert "additional sinks not shown" in out


def test_context_map_under_cap_untouched():
    data = {
        "entry_points": [
            {"id": "EP-1", "path": "/x", "file": "a.py", "line": 1},
        ],
        "boundary_details": [
            {"id": "TB-1", "boundary": "auth", "covers": "EP-1"},
        ],
        "sink_details": [
            {"id": "SINK-1", "operation": "op", "reaches_from": "EP-1"},
        ],
        "unchecked_flows": [],
    }
    out = context_map.generate(data)
    assert _MARKER not in out
    # The EP→TB index preserves the join semantics: the covered entry
    # reaches its sink THROUGH the boundary.
    assert "TB-1 --> SINK-1" in out


def test_forward_reachable_names_capped_with_disclosure():
    data = {
        "entry_points": [{
            "id": "EP-1", "path": "/x",
            "forward_reachable": {
                "host": "handler",
                "internal_names": [f"fn{i}" for i in range(10_000)],
                "external_names": [],
                "truncated": False,
            },
        }],
    }
    blocks = context_map.generate_forward_reachable_blocks(data)
    assert len(blocks) == 1
    _title, diagram = blocks[0]
    assert len(diagram) < 100_000
    assert "%% Showing" in diagram

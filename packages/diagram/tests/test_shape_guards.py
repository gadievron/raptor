"""Malformed-element shape guards across generators.

flow_trace's steps ingestion landed the discipline — "malformed
elements drop, the rest still renders" — and the sibling generators
kept crashing whole sections on one bad element (the renderer's
per-section try/except turns any raise into 'Could not render', so a
single junk entry in a big artifact lost the entire diagram). These
tests apply the same oracle everywhere: one malformed element, the
good elements still render.
"""

from __future__ import annotations

from packages.diagram import (
    attack_tree,
    edge_obligations,
    flow_trace,
    graph_memory,
    hypotheses,
)


def test_hypotheses_string_predictions_dropped():
    out = hypotheses.generate([
        {"id": "H-1", "claim": "c", "status": "testing",
         "predictions": "not-a-list"},
        {"id": "H-2", "claim": "c2", "status": "confirmed",
         "predictions": [
             {"id": "P-1", "prediction": "p", "status": "confirmed"},
             "junk",
         ]},
    ])
    assert "H-1" in out
    assert "P-1" in out


def test_hypotheses_non_dict_element_dropped():
    out = hypotheses.generate([
        "junk",
        {"id": "H-1", "claim": "c", "status": "testing"},
    ])
    assert "H-1" in out


def test_edge_obligations_non_dict_recs_dropped():
    out = edge_obligations.generate({
        "tier1": [
            "junk",
            {"caller_file": "a.c", "caller": "f",
             "callee_file": "b.c", "callee": "g", "reason": "r"},
        ],
        "tier2": "not-a-list",
        "blind_spots": [],
        "stats": "not-a-dict",
    })
    assert out.startswith("flowchart LR")
    assert '"f"' in out


def test_graph_memory_string_path_dropped():
    out = graph_memory.generate_priority_paths([
        "junk",
        {"id": "GP-1", "entry": {"label": "main"},
         "sink": {"label": "exec"}},
    ])
    assert "GP-1_ENTRY" in out


def test_attack_tree_dict_claim_hypothesis_does_not_crash():
    """The confirmed member: _build_hypothesis_index sliced ``claim``
    before any string coercion — a dict claim raised KeyError(slice)
    and the whole Attack Tree section was lost."""
    tree = {
        "root": "R",
        "nodes": [
            {"id": "R", "goal": "g", "technique": "t",
             "status": "exploring", "leads_to": "F1"},
            {"id": "F1", "goal": "f", "technique": "t",
             "status": "confirmed", "leads_to": ""},
        ],
    }
    out = attack_tree.generate(tree, hypotheses=[
        {"finding": "F1", "status": "testing",
         "claim": {"nested": "dict"}},
        "junk",
    ])
    assert "flowchart TD" in out
    assert "F1" in out


def test_attack_tree_non_dict_node_dropped():
    out = attack_tree.generate({
        "root": "R",
        "nodes": [
            {"id": "R", "goal": "g", "technique": "t",
             "status": "exploring", "leads_to": ""},
            "not-a-dict",
        ],
    })
    assert "flowchart TD" in out
    assert "R" in out


def test_attack_tree_non_dict_companions_dropped():
    tree = {
        "root": "R",
        "nodes": [{"id": "R", "goal": "g", "technique": "t",
                   "status": "confirmed", "leads_to": ""}],
    }
    out = attack_tree.generate(
        tree,
        attack_paths=["junk", {"finding": "R", "proximity": 5}],
        disproven=["junk"],
        hypotheses=["junk"],
    )
    assert "proximity 5/10" in out


def test_flow_trace_string_branch_dropped():
    out = flow_trace.generate({
        "id": "T-1", "name": "t",
        "steps": [{"step": 1, "type": "entry", "description": "d"}],
        "branches": [
            "junk",
            {"branch_point": "a.py:1", "condition": "x", "outcome": "y"},
        ],
    })
    assert "flowchart TD" in out
    assert "BR1" in out

"""Renderer-side node-ID collision warnings (wires detect_id_collisions).

The helper landed with its stated consumer — "renderer call sites can
detect and log them" — never wired: two raw attack-tree ids that
differ only in sanitized characters (``foo!`` / ``foo?``) rendered as
one Mermaid node with nothing surfacing the collapse.
"""

from __future__ import annotations

import json

from packages.diagram.renderer import render_directory

_COLLIDING_TREE = {
    "root": "ROOT",
    "nodes": [
        {"id": "ROOT", "goal": "g", "technique": "t",
         "status": "exploring", "leads_to": "foo!, foo?"},
        {"id": "foo!", "goal": "direct", "technique": "t1",
         "status": "confirmed", "leads_to": ""},
        {"id": "foo?", "goal": "indirect", "technique": "t2",
         "status": "disproven", "leads_to": ""},
    ],
}

_CLEAN_TREE = {
    "root": "ROOT",
    "nodes": [
        {"id": "ROOT", "goal": "g", "technique": "t",
         "status": "exploring", "leads_to": "N1"},
        {"id": "N1", "goal": "direct", "technique": "t1",
         "status": "confirmed", "leads_to": ""},
    ],
}


def _render(tmp_path, tree) -> str:
    (tmp_path / "attack-tree.json").write_text(
        json.dumps(tree), encoding="utf-8",
    )
    return render_directory(tmp_path)


class TestIdCollisionWarning:
    def test_colliding_ids_surface_a_warning(self, tmp_path):
        out = _render(tmp_path, _COLLIDING_TREE)
        assert "node-ID collision" in out
        assert "foo!" in out
        assert "foo?" in out
        assert "foo_" in out
        assert "attack-tree.json" in out

    def test_clean_tree_has_no_warning(self, tmp_path):
        out = _render(tmp_path, _CLEAN_TREE)
        assert "node-ID collision" not in out
        assert "Attack Tree" in out

    def test_diagram_still_rendered_alongside_warning(self, tmp_path):
        out = _render(tmp_path, _COLLIDING_TREE)
        assert "```mermaid" in out
        assert "flowchart TD" in out

    def test_malformed_nodes_do_not_break_render(self, tmp_path):
        tree = {"root": "R", "nodes": [
            {"id": "R", "goal": "g", "technique": "t",
             "status": "exploring", "leads_to": ""},
            "not-a-dict",
        ]}
        out = _render(tmp_path, tree)
        assert "Attack Tree" in out

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


_INJECTION_ID_A = "x`![y](http://evil.example)!"
_INJECTION_ID_B = "x`![y](http://evil.example)?"


class TestIdCollisionWarningInjection:
    """The warning line shows RAW node ids (LLM-derived, untrusted by
    the helper's own docstring) inside single-backtick spans. An
    embedded backtick closed the span and the tail rendered as live
    markdown — including image autofetch beacons."""

    def _warning(self, tmp_path) -> str:
        tree = {
            "root": "ROOT",
            "nodes": [
                {"id": "ROOT", "goal": "g", "technique": "t",
                 "status": "exploring",
                 "leads_to": f"{_INJECTION_ID_A}, {_INJECTION_ID_B}"},
                {"id": _INJECTION_ID_A, "goal": "a", "technique": "t1",
                 "status": "confirmed", "leads_to": ""},
                {"id": _INJECTION_ID_B, "goal": "b", "technique": "t2",
                 "status": "disproven", "leads_to": ""},
            ],
        }
        out = _render(tmp_path, tree)
        assert "node-ID collision" in out
        # Scope the oracle to the warning line — mermaid fence content
        # is a different (inert) context.
        return next(ln for ln in out.splitlines()
                    if "node-ID collision" in ln)

    def test_no_live_image_markup_in_warning(self, tmp_path):
        warning = self._warning(tmp_path)
        assert "![y](http://evil.example)" not in warning

    def test_no_raw_backtick_from_ids_in_warning(self, tmp_path):
        warning = self._warning(tmp_path)
        # The only raw backticks left are the wrapping spans the
        # warning itself emits (always paired); embedded ones arrive
        # entity-escaped, so no span can close early.
        assert "x`!" not in warning
        assert warning.count("`") % 2 == 0


class TestSectionHeadingInjection:
    """Flow-trace and attack-path section headings render raw artifact
    values on markdown heading lines — same autofetch channel."""

    def test_flow_trace_heading_strips_autofetch(self, tmp_path):
        (tmp_path / "flow-trace-001.json").write_text(json.dumps({
            "id": "TRACE-1`![y](http://evil.example)",
            "name": "demo`![z](http://evil.example)",
            "steps": [{"step": 1, "type": "entry", "description": "d"}],
        }), encoding="utf-8")
        out = render_directory(tmp_path)
        heading_lines = [ln for ln in out.splitlines()
                         if ln.lstrip().startswith("#")]
        assert heading_lines
        assert not any("![" in ln for ln in heading_lines)

    def test_attack_path_heading_strips_autofetch(self, tmp_path):
        (tmp_path / "attack-paths.json").write_text(json.dumps([{
            "id": "P1",
            "name": "pwn`![y](http://evil.example)",
            "proximity": 3,
            "status": "uncertain",
            "steps": [{"type": "call", "description": "d"}],
        }]), encoding="utf-8")
        out = render_directory(tmp_path)
        heading_lines = [ln for ln in out.splitlines()
                         if ln.lstrip().startswith("#")]
        assert not any("![" in ln for ln in heading_lines)

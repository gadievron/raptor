"""List-envelope unwrapping across the diagram loaders.

Regression coverage for the positional-fallback divergence: the
attack-paths renderer section and the two ``generate_from_file``
entry points unwrapped dict envelopes with a bare
``next(iter(data.values()))`` — an envelope whose FIRST value was a
metadata array rendered garbage while ``_load_optional_list`` (the
hardened sibling) behaved correctly. All loaders now share
``envelope.unwrap_list``.
"""

import json
from pathlib import Path

from ..attack_paths import generate_from_file as attack_paths_from_file
from ..envelope import unwrap_list
from ..hypotheses import generate_from_file as hypotheses_from_file
from ..renderer import render_directory


class TestUnwrapList:
    def test_bare_list_passes_through(self):
        assert unwrap_list([1, 2], keys=("paths",)) == [1, 2]

    def test_known_key_wins_over_earlier_metadata_list(self):
        data = {"provenance": ["meta"], "paths": [{"id": "P1"}]}
        assert unwrap_list(data, keys=("paths",)) == [{"id": "P1"}]

    def test_single_unrecognised_list_falls_back(self):
        assert unwrap_list({"items": [1]}, keys=("paths",)) == [1]

    def test_multiple_unrecognised_lists_refuse(self):
        data = {"meta": ["m"], "items": [1]}
        assert unwrap_list(data, keys=("paths",)) is None

    def test_non_dict_non_list_refuses(self):
        assert unwrap_list("junk", keys=("paths",)) is None
        assert unwrap_list(None, keys=("paths",)) is None


class TestRemainingHandRolledLoaders:
    """envelope.py claims "every loader must route through here" — the
    renderer kept two hand-rolled unwraps (disproven.json and the
    graph-priority-paths ``or``-chain)."""

    def test_disproven_nonstandard_single_list_envelope_used(self, tmp_path):
        (tmp_path / "attack-tree.json").write_text(json.dumps({
            "root": "R",
            "nodes": [
                {"id": "R", "goal": "g", "technique": "t",
                 "status": "exploring", "leads_to": "F1"},
                {"id": "F1", "goal": "f", "technique": "t",
                 "status": "disproven", "leads_to": ""},
            ],
        }), encoding="utf-8")
        # Payload under a nonstandard key, single list in the dict —
        # the shared fallback finds it; the hand-rolled
        # data.get("disproven", []) silently dropped it.
        (tmp_path / "disproven.json").write_text(json.dumps({
            "entries": [{"finding": "F1", "why_wrong": "guard present"}],
        }), encoding="utf-8")
        out = render_directory(tmp_path)
        assert "ruled out: guard present" in out

    def test_graph_paths_non_list_paths_value_falls_through(self, tmp_path):
        # `paths` truthy but not a list: the or-chain accepted it,
        # failed the isinstance guard, and silently dropped the whole
        # section; unwrap_list tries the next known key.
        (tmp_path / "graph-priority-paths.json").write_text(json.dumps({
            "paths": {"not": "a list"},
            "graph_paths": [{"id": "GP-1",
                             "entry": {"label": "main"},
                             "sink": {"label": "exec"}}],
        }), encoding="utf-8")
        out = render_directory(tmp_path)
        assert "Graph Priority Paths" in out
        assert "GP-1_ENTRY" in out


class TestGenerateFromFileEnvelopes:
    def _write(self, tmp_path: Path, name: str, payload) -> Path:
        p = tmp_path / name
        p.write_text(json.dumps(payload), encoding="utf-8")
        return p

    def test_attack_paths_metadata_first_envelope(self, tmp_path):
        payload = {
            "generated_by": ["understand", "validate"],
            "paths": [{"id": "AP1", "name": "path one", "steps": []}],
        }
        out = attack_paths_from_file(self._write(tmp_path, "attack-paths.json", payload))
        assert "AP1" in out or "path one" in out
        assert "understand" not in out

    def test_hypotheses_metadata_first_envelope(self, tmp_path):
        payload = {
            "sources": ["stage-b"],
            "hypotheses": [{"id": "H1", "status": "exploring"}],
        }
        out = hypotheses_from_file(self._write(tmp_path, "hypotheses.json", payload))
        assert "H1" in out
        assert "stage" not in out

    def test_renderer_attack_paths_section_uses_known_key(self, tmp_path):
        payload = {
            "generated_by": ["metadata-only", "not-a-path"],
            "paths": [{"id": "AP7", "name": "renderer path", "steps": []}],
        }
        self._write(tmp_path, "attack-paths.json", payload)
        content = render_directory(tmp_path)
        assert "AP7" in content or "renderer path" in content
        assert "metadata-only" not in content

    def test_renderer_attack_paths_ambiguous_envelope_degrades(self, tmp_path):
        payload = {"meta": ["m1"], "other": ["m2"]}
        self._write(tmp_path, "attack-paths.json", payload)
        content = render_directory(tmp_path)
        # Two unrecognised lists: refuse to guess — no garbage section.
        assert "m1" not in content
        assert "m2" not in content


class TestFlowTraceMalformedSteps:
    def test_non_list_steps_renders_empty_not_crash(self):
        from ..flow_trace import generate

        out = generate({"id": "T1", "name": "trace", "steps": "junk"})
        assert "No steps" in out

    def test_non_dict_step_element_dropped(self):
        from ..flow_trace import generate

        out = generate({
            "id": "T2",
            "name": "trace",
            "steps": [
                {"step": 1, "function": "read_input"},
                "junk-entry",
                {"step": 2, "function": "parse"},
            ],
        })
        # Both dict steps render as nodes; the junk entry drops
        # instead of degrading the whole trace to "Could not render".
        assert 'S1["' in out
        assert 'S2["' in out


class TestSanitizeIdDashRuns:
    def test_dash_run_collapsed(self):
        from ..sanitize import sanitize_id

        # `A---B["label"]` parses as an EDGE between phantom nodes A
        # and B in flowchart context; runs must collapse to one dash.
        assert sanitize_id("A---B") == "A-B"
        assert sanitize_id("A--B") == "A-B"

    def test_single_dash_kept(self):
        from ..sanitize import sanitize_id

        assert sanitize_id("entry-point") == "entry-point"

    def test_all_dash_id_falls_back(self):
        from ..sanitize import sanitize_id

        assert sanitize_id("---") == "node"

    def test_stripped_chars_then_dash_run_still_collapsed(self):
        from ..sanitize import sanitize_id

        # Strip pass may not INTRODUCE runs (strips map to '_'), but a
        # pre-existing run around stripped chars must still collapse.
        assert "--" not in sanitize_id("x!--!y--z")

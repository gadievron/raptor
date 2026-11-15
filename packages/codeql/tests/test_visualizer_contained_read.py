"""HTML source reads stay under the analysed root after directory swaps."""
import json
import re
from pathlib import Path

from packages.codeql import dataflow_visualizer as module
from packages.codeql.dataflow_validator import DataflowPath, DataflowStep


def _flow(relative):
    return DataflowPath(
        source=DataflowStep(relative, 1, 1, "owned snippet", "source"),
        sink=DataflowStep(relative, 1, 1, "owned snippet", "sink"),
        intermediate_steps=[], sanitizers=[], rule_id="owned", message="owned",
    )


def _contexts(path):
    match = re.search(r"const nodes = (.*);", path.read_text(encoding="utf-8"))
    assert match is not None
    return [node["code_context"] for node in json.loads(match.group(1))]


def test_html_source_read_refuses_owned_intermediate_directory_swap(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    member = repo / "member"
    member.mkdir(parents=True)
    (member / "owned.c").write_text("int inside_marker;\n", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "owned.c").write_text("int outside_marker;\n", encoding="utf-8")
    (repo / "alias").symlink_to(member, target_is_directory=True)
    viewer = module.DataflowVisualizer(tmp_path / "reports")
    for index, relative in enumerate(("member/owned.c", "alias/owned.c")):
        contexts = _contexts(viewer.generate_html(_flow(relative), f"positive{index}", repo))
        assert all("inside_marker" in context for context in contexts)
    original = module.read_contained_text_capped
    calls = []

    def swapped_read(root, candidate, **kwargs):
        assert Path(root) == repo
        assert Path(candidate) == member / "owned.c"
        calls.append(candidate)
        if len(calls) == 1:
            member.rename(repo / "saved_member")
            member.symlink_to(outside, target_is_directory=True)
        return original(root, candidate, **kwargs)

    monkeypatch.setattr(module, "read_contained_text_capped", swapped_read)
    contexts = _contexts(viewer.generate_html(_flow("member/owned.c"), "swapped", repo))
    assert len(calls) == 1  # First open seam reached after the visualiser's checks.
    assert all("outside_marker" not in context for context in contexts)
    assert contexts[0].startswith("Error reading file:")
    assert contexts[1].startswith("Access denied:")

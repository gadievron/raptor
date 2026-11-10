"""Directory capture omits duplicate summary pies without losing rich graphs."""

import pytest

from packages.diagram.reporting import capture_directory_blocks


@pytest.mark.parametrize("position", [0, 1, 2])
def test_summary_pies_are_filtered_without_losing_neighboring_sections(tmp_path, monkeypatch, position):
    sections = [
        "## Context Map\nContext prose.\n```mermaid\nflowchart TD\nA --> B\n```\n",
        "## Additional evidence\nRetained prose.\n",
    ]
    summary = "## Findings Summary\nDuplicate summary.\n```mermaid\npie\n  \"duplicate\" : 1\n```\n"
    sections.insert(position, summary)
    # Repeated summary sections must also be omitted, including at EOF.
    sections.append(summary)
    monkeypatch.setattr("packages.diagram.renderer.render_directory", lambda *args, **kwargs: "".join(sections))
    blocks = capture_directory_blocks(tmp_path)
    assert [block.title for block in blocks] == ["Context Map", "Additional evidence"]
    assert blocks[0].extensions["mermaid"] == "flowchart TD\nA --> B"
    assert "Context prose." in blocks[0].text
    assert "Retained prose." in blocks[1].text
    assert not any("duplicate" in block.text.lower() for block in blocks)


def test_native_renderer_fence_protocol_is_lf_even_with_crlf_json(tmp_path):
    import json
    from packages.diagram.renderer import render_directory
    source = tmp_path / "context-map.json"
    payload = {"entry_points": [{"id": "EP-1", "name": "owned\r\nline", "type": "function", "file": "app.py", "line": 1}],
               "sink_details": [], "unchecked_flows": []}
    source.write_bytes(json.dumps(payload, indent=2).replace("\n", "\r\n").encode())
    assert b"\r\n" in source.read_bytes()
    rendered = render_directory(tmp_path)
    fences = [line for line in rendered.splitlines(keepends=True) if line.startswith("```")]
    assert fences == ["```mermaid\n", "```\n"]
    blocks = capture_directory_blocks(tmp_path)
    assert any(block.kind == "diagram" and "flowchart" in block.extensions["mermaid"] for block in blocks)

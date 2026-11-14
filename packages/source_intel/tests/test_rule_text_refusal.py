"""Rule-text refusal controls without rendering or executing rules."""

import importlib
from pathlib import Path

import pytest

from engine.coccinelle import api_pack_renderer

module = importlib.import_module("packages.source_intel.analyze")


def _forbidden(*args, **kwargs):
    raise AssertionError("rendering and staging forbidden")


@pytest.mark.parametrize("condition", ["utf8", "io", "valid"])
def test_rule_text_refusal_preserves_original_axis(tmp_path, monkeypatch, caplog, condition):
    axis = tmp_path / "axis"
    axis.mkdir()
    rule = axis / "owned.cocci"
    rule.write_bytes(b"\xff" if condition == "utf8" else b"// inert\n")
    original = Path.read_text

    def read(path, *args, **kwargs):
        if path == rule and condition == "io":
            raise PermissionError("owned rule read refusal")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(api_pack_renderer, "has_api_pack_marker", lambda text: False)
    monkeypatch.setattr(api_pack_renderer, "render_text", _forbidden)
    monkeypatch.setattr(module, "scratch_dir", _forbidden)
    with module._materialize_rules_dir(axis) as selected:
        assert selected == axis
    if condition != "valid":
        assert "running unrendered" in caplog.text
    else:
        assert "running unrendered" not in caplog.text

"""Owned materialization controls; rendered rules are never executed."""

from contextlib import contextmanager
import importlib
import shutil

import pytest

from engine.coccinelle import api_pack_renderer

module = importlib.import_module("packages.source_intel.analyze")


@pytest.mark.parametrize("refuse_copy", [True, False])
def test_staging_failure_falls_back_and_reclaims_partial_copy(tmp_path, monkeypatch, caplog, refuse_copy):
    axis = tmp_path / "axis"
    axis.mkdir()
    (axis / "a_slot.cocci").write_text("// owned slot\n")
    (axis / "b_plain.cocci").write_text("// owned plain\n")
    staged = tmp_path / "staged"

    @contextmanager
    def scratch(*args, **kwargs):
        staged.mkdir()
        try:
            yield staged
        finally:
            shutil.rmtree(staged)

    monkeypatch.setattr(module, "scratch_dir", scratch)
    monkeypatch.setattr(api_pack_renderer, "has_api_pack_marker", lambda text: "owned slot" in text)
    monkeypatch.setattr(api_pack_renderer, "render_text", lambda path: "// owned rendered\n")
    original = shutil.copyfile

    def copy(source, dest, *args, **kwargs):
        if refuse_copy:
            raise PermissionError("owned staging copy refusal")
        return original(source, dest, *args, **kwargs)

    monkeypatch.setattr(shutil, "copyfile", copy)
    with module._materialize_rules_dir(axis) as selected:
        if refuse_copy:
            assert selected == axis
            assert "running unrendered" in caplog.text
        else:
            assert selected == staged
            assert (selected / "a_slot.cocci").read_text() == "// owned rendered\n"
            assert (selected / "b_plain.cocci").read_text() == "// owned plain\n"
    assert not staged.exists()

    with pytest.raises(PermissionError, match="owned consumer refusal"):
        with module._materialize_rules_dir(axis):
            raise PermissionError("owned consumer refusal")
    assert not staged.exists()

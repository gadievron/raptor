"""Owned discovery refusals stop before source inventory or tool dispatch."""

import importlib
import os

import pytest

module = importlib.import_module("packages.source_intel.analyze")


def _forbidden(*args, **kwargs):
    raise AssertionError("source inventory or native execution forbidden")


@pytest.mark.parametrize("denied", ["root", "axis"])
def test_unreadable_rules_are_disclosed_before_analysis(tmp_path, monkeypatch, denied):
    from packages.coccinelle import runner

    root = tmp_path / "rules"
    axis = root / "attrs"
    axis.mkdir(parents=True)
    (axis / "owned.cocci").write_text("// inert, never executed\n")
    monkeypatch.setattr(runner, "is_available", lambda: True)
    monkeypatch.setattr(runner, "run_rules", _forbidden)
    monkeypatch.setattr(runner, "version", _forbidden)
    monkeypatch.setattr(module, "_has_c_cpp_source", lambda *args: True)
    monkeypatch.setattr(module, "_maybe_register_inventory", _forbidden)
    original = os.scandir
    blocked = root if denied == "root" else axis

    def scandir(path):
        if os.path.normpath(os.fspath(path)) == os.path.normpath(str(blocked)):
            raise PermissionError("owned rule discovery refusal")
        return original(path)

    monkeypatch.setattr(os, "scandir", scandir)
    result = module.analyze(tmp_path, rules_dir=root)
    assert result.is_skipped
    assert result.skipped_reason == "rules_discovery_failed"
    assert result.rules_executed == ()


def test_axis_selection_retains_glob_filename_contract(tmp_path):
    for index, name in enumerate(("a.cocci", ".hidden.cocci", ".cocci", "folder.cocci")):
        axis = tmp_path / f"axis{index}"
        axis.mkdir()
        child = axis / name
        child.mkdir() if name == "folder.cocci" else child.write_text("// inert\n")
    data = tmp_path / "data"
    data.mkdir()
    (data / "pack.json").write_text("{}")
    expected = sorted(path for path in tmp_path.iterdir() if any(path.glob("*.cocci")))
    assert module._axis_dirs(tmp_path) == expected

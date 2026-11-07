"""Linux cleanup keeps runtime functionality and refuses unfamiliar layouts."""
import importlib.util
import sys
from pathlib import Path

import pytest


from core.testing.module_bindings import patch_module_attribute


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prune_linux_extras", ROOT / ".devcontainer/prune-linux-extras.py")
tool = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(tool)
GUARD = ('if (process.platform === "darwin" || process.platform === "win32") {\n'
         'const { reflinkFileSync } = __require("@reflink/reflink");\n}')


def package(tmp_path):
    root = tmp_path / "pnpm"
    scope = root / "dist/node_modules/@reflink"
    scope.mkdir(parents=True)
    (scope / "reflink").mkdir()
    (scope / "reflink/index.js").write_text("platform implementation")
    for name in ("pnpm.mjs", "worker.js"):
        (root / "dist" / name).write_text(GUARD)
    return root, scope


def test_only_unused_scope_is_removed_and_cleanup_is_repeatable(tmp_path):
    root, scope = package(tmp_path)
    (root / "LICENSE").write_text("retain this notice")
    tool.prune_pnpm(root)
    tool.prune_pnpm(root)
    assert not scope.exists()
    assert (root / "LICENSE").read_text() == "retain this notice"
    assert (root / "dist/worker.js").read_text() == GUARD


@pytest.mark.parametrize("change", ["missing", "guard", "additional_use", "additional_file"])
def test_changed_consumers_are_retained_with_a_warning(tmp_path, capsys, change):
    root, scope = package(tmp_path)
    source = root / "dist/worker.js"
    if change == "missing":
        source.unlink()
    elif change == "guard":
        source.write_text(GUARD.replace('"darwin"', '"linux"'))
    elif change == "additional_use":
        source.write_text(GUARD + '\n__require("@reflink/reflink")')
    else:
        (root / "dist/new.js").write_text('require("@reflink/new")')
    tool.prune_pnpm(root)
    assert scope.is_dir()
    assert "WARNING" in capsys.readouterr().out


def test_scope_symlink_cannot_delete_an_external_directory(tmp_path):
    root, scope = package(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    marker = outside / "keep"
    marker.write_text("keep")
    import shutil
    shutil.rmtree(scope)
    scope.symlink_to(outside, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        tool.prune_pnpm(root)
    assert marker.read_text() == "keep"


def test_nvm_runtime_and_license_survive_fixture_removal(tmp_path):
    (tmp_path / "nvm.sh").write_text("runtime")
    (tmp_path / "LICENSE.md").write_text("license")
    (tmp_path / "test").mkdir()
    (tmp_path / "test/package.json").write_text("fixture")
    tool.prune_nvm_tests(tmp_path)
    tool.prune_nvm_tests(tmp_path)
    assert not (tmp_path / "test").exists()
    assert (tmp_path / "nvm.sh").read_text() == "runtime"
    assert (tmp_path / "LICENSE.md").read_text() == "license"


def test_unrecognized_nvm_layout_is_retained(tmp_path, capsys):
    (tmp_path / "test").mkdir()
    tool.prune_nvm_tests(tmp_path)
    assert (tmp_path / "test").is_dir()
    assert "WARNING" in capsys.readouterr().out


def test_non_linux_invocation_keeps_packages(tmp_path, monkeypatch):
    root, scope = package(tmp_path)
    patch_module_attribute(monkeypatch, tool, 'sys', "platform", "win32")
    monkeypatch.setattr(sys, "argv", ["prune-linux-extras.py", "--pnpm-root", str(root)])
    tool.main()
    assert scope.exists()

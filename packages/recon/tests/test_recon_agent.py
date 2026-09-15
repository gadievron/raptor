"""Tests for packages/recon/agent.py."""

import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.recon.agent import inventory, get_out_dir


# Session cwd anchor — the test file's parent's parent's parent
# is the repo root, doesn't depend on cwd to compute, so safe
# even when cwd has been invalidated by a prior test's tmp_path
# cleanup.
_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture(autouse=True)
def _restore_cwd():
    """Module-wide autouse fixture: ensure each test starts and
    ends with a valid cwd anchored at the repo root.

    Pre-fix the only protection was an inline `os.chdir(repo_root)`
    inside `test_defaults_to_out_subdirectory`. That test
    happened to be the canary for "previous test's tmp_path
    cleanup invalidated cwd" — the rest of the test class
    was equally vulnerable, just less likely to fail because
    they didn't try to introspect cwd. With pytest's
    randomised test ordering or a different test-ordering
    plugin, the bare bug could surface in any test.

    Capture cwd before the test, restore (or fall back to
    repo root) after — fires per-test so transient cwd
    changes can't leak across the file.
    """
    try:
        old = os.getcwd()
    except FileNotFoundError:
        old = str(_REPO_ROOT)
        os.chdir(old)
    try:
        yield
    finally:
        try:
            os.chdir(old)
        except FileNotFoundError:
            os.chdir(_REPO_ROOT)


# ---------------------------------------------------------------------------
# inventory()
# ---------------------------------------------------------------------------

class TestInventory:

    def test_empty_directory(self, tmp_path):
        result = inventory(tmp_path)
        assert result["file_count"] == 0
        assert result["ext_counts"] == {}
        assert result["language_counts"] == {}

    def test_single_python_file(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        result = inventory(tmp_path)
        assert result["file_count"] == 1
        assert result["ext_counts"][".py"] == 1
        assert result["language_counts"]["python"] == 1

    def test_multiple_extensions(self, tmp_path):
        (tmp_path / "a.py").write_text("")
        (tmp_path / "b.py").write_text("")
        (tmp_path / "c.js").write_text("")
        (tmp_path / "d.go").write_text("")
        result = inventory(tmp_path)
        assert result["file_count"] == 4
        assert result["ext_counts"][".py"] == 2
        assert result["ext_counts"][".js"] == 1
        assert result["ext_counts"][".go"] == 1
        assert result["language_counts"]["python"] == 2
        assert result["language_counts"]["javascript"] == 1
        assert result["language_counts"]["go"] == 1

    def test_java_and_kotlin(self, tmp_path):
        (tmp_path / "Main.java").write_text("")
        (tmp_path / "App.kt").write_text("")
        result = inventory(tmp_path)
        assert result["language_counts"]["java"] == 2

    def test_ruby_and_csharp(self, tmp_path):
        (tmp_path / "script.rb").write_text("")
        (tmp_path / "Program.cs").write_text("")
        result = inventory(tmp_path)
        assert result["language_counts"]["ruby"] == 1
        assert result["language_counts"]["csharp"] == 1

    def test_typescript_counted_as_javascript(self, tmp_path):
        (tmp_path / "app.ts").write_text("")
        result = inventory(tmp_path)
        assert result["language_counts"]["javascript"] == 1

    def test_unknown_extension_not_in_language_counts(self, tmp_path):
        (tmp_path / "data.csv").write_text("")
        result = inventory(tmp_path)
        assert result["file_count"] == 1
        assert result["ext_counts"][".csv"] == 1
        assert "csv" not in result["language_counts"]

    def test_nested_directories(self, tmp_path):
        sub = tmp_path / "src" / "utils"
        sub.mkdir(parents=True)
        (sub / "helper.py").write_text("")
        (tmp_path / "main.py").write_text("")
        result = inventory(tmp_path)
        assert result["file_count"] == 2
        assert result["ext_counts"][".py"] == 2

    def test_no_extension_file(self, tmp_path):
        (tmp_path / "Makefile").write_text("")
        result = inventory(tmp_path)
        assert result["file_count"] == 1
        assert "" in result["ext_counts"]

    def test_hidden_files_counted(self, tmp_path):
        (tmp_path / ".env").write_text("SECRET=123")
        result = inventory(tmp_path)
        assert result["file_count"] == 1


# ---------------------------------------------------------------------------
# get_out_dir()
# ---------------------------------------------------------------------------

class TestGetOutDir:

    def test_respects_raptor_out_dir(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            result = get_out_dir()
            assert result == tmp_path.resolve()

    def test_defaults_to_out_subdirectory(self, monkeypatch):
        # Repair a dangling CWD left by an earlier test that chdir'd into
        # a cleaned-up tmp_path. We can't use ``monkeypatch.chdir()`` for
        # this — its first action is ``os.getcwd()`` to remember the
        # current cwd for restoration, which fails when cwd is already
        # gone. Plain ``os.chdir()`` doesn't introspect the current cwd,
        # so it works regardless. ``Path(__file__).resolve()`` doesn't
        # depend on cwd, so we can safely derive the repo root here.
        repo_root = Path(__file__).resolve().parents[3]
        os.chdir(repo_root)
        monkeypatch.delenv("RAPTOR_OUT_DIR", raising=False)
        assert get_out_dir().name == "out"

    def test_returns_path_object(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            assert isinstance(get_out_dir(), Path)



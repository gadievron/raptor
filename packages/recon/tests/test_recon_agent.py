"""Tests for packages/recon/agent.py."""

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from packages.recon.agent import inventory, get_out_dir, safe_clone


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

    def test_defaults_to_out_subdirectory(self):
        env_without = {k: v for k, v in os.environ.items() if k != "RAPTOR_OUT_DIR"}
        with patch.dict(os.environ, env_without, clear=True):
            result = get_out_dir()
            assert result.name == "out"

    def test_returns_path_object(self, tmp_path):
        with patch.dict(os.environ, {"RAPTOR_OUT_DIR": str(tmp_path)}):
            assert isinstance(get_out_dir(), Path)


# ---------------------------------------------------------------------------
# safe_clone()
# ---------------------------------------------------------------------------

class TestSafeClone:

    @patch("packages.recon.agent.clone_repository")
    def test_returns_dest_path(self, mock_clone, tmp_path):
        mock_clone.return_value = True
        result = safe_clone("https://github.com/example/repo", tmp_path / "repo")
        assert result == tmp_path / "repo"

    @patch("packages.recon.agent.clone_repository")
    def test_delegates_to_core_clone(self, mock_clone, tmp_path):
        """safe_clone() must call core.git.clone_repository with depth=1."""
        mock_clone.return_value = True
        safe_clone("https://github.com/example/repo", tmp_path / "repo")
        mock_clone.assert_called_once_with(
            "https://github.com/example/repo",
            tmp_path / "repo",
            depth=1,
        )

    def test_invalid_url_raises(self, tmp_path):
        """Invalid URLs must be rejected by core.git.clone_repository."""
        with pytest.raises((ValueError, RuntimeError)):
            safe_clone("https://evil.com/bad/repo", tmp_path / "repo")

    @patch("packages.recon.agent.clone_repository")
    def test_clone_failure_propagates(self, mock_clone, tmp_path):
        mock_clone.side_effect = RuntimeError("git clone failed: not found")
        with pytest.raises(RuntimeError, match="git clone failed"):
            safe_clone("https://github.com/example/repo", tmp_path / "repo")

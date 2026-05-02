"""Tests for packages/static-analysis/scanner.py."""

import importlib.util
import json
import shutil
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

# static-analysis has a hyphen — load via importlib
_SCANNER_PATH = Path(__file__).parent.parent / "scanner.py"
_spec = importlib.util.spec_from_file_location("static_analysis_scanner", _SCANNER_PATH)
_scanner_mod = importlib.util.module_from_spec(_spec)
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))
_spec.loader.exec_module(_scanner_mod)

run_codeql = _scanner_mod.run_codeql


# ---------------------------------------------------------------------------
# run_codeql()
# ---------------------------------------------------------------------------

class TestRunCodeql:

    def test_returns_empty_list_when_codeql_not_installed(self, tmp_path):
        with patch("shutil.which", return_value=None):
            result = run_codeql(tmp_path, tmp_path / "out", ["python"])
        assert result == []

    @patch("shutil.which", return_value="/usr/bin/codeql")
    @patch.object(_scanner_mod, "run")
    def test_creates_output_dir(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = (1, "", "db create failed")
        out_dir = tmp_path / "codeql_out"
        run_codeql(tmp_path, out_dir, ["python"])
        assert out_dir.exists()

    @patch("shutil.which", return_value="/usr/bin/codeql")
    @patch.object(_scanner_mod, "run")
    def test_skips_language_if_db_create_fails(self, mock_run, mock_which, tmp_path):
        mock_run.return_value = (1, "", "database create error")
        result = run_codeql(tmp_path, tmp_path / "out", ["python", "java"])
        assert result == []

    @patch("shutil.which", return_value="/usr/bin/codeql")
    @patch.object(_scanner_mod, "run")
    def test_uses_list_based_args(self, mock_run, mock_which, tmp_path):
        """run() must be called with list args, never shell strings."""
        mock_run.return_value = (1, "", "")
        run_codeql(tmp_path, tmp_path / "out", ["python"])
        for c in mock_run.call_args_list:
            cmd_arg = c.args[0] if c.args else c.kwargs.get("cmd", [])
            assert isinstance(cmd_arg, list), "Command must be a list (no shell injection)"

    @patch("shutil.which", return_value="/usr/bin/codeql")
    @patch.object(_scanner_mod, "run")
    def test_empty_languages_returns_empty(self, mock_run, mock_which, tmp_path):
        result = run_codeql(tmp_path, tmp_path / "out", [])
        assert result == []
        mock_run.assert_not_called()


_compute_python_tool_paths = _scanner_mod._compute_python_tool_paths


class TestComputePythonToolPaths:
    """Tool-path inference for Python tools. Reads cmd[0]'s shebang to
    find the interpreter, then derives the stdlib dir from interp
    path + version. Used as tool_paths kwarg so mount-ns can engage
    for pip --user installed Python tools (semgrep is the original
    case). The result is speculative — context.py's speculative-C
    retry catches misses and falls back to Landlock-only."""

    def test_empty_cmd_returns_empty(self):
        assert _compute_python_tool_paths([]) == []

    def test_unreadable_path_still_includes_bin_dir(self, tmp_path):
        """Path doesn't exist as a file → no shebang, but the bin
        dir IS still added (absolute path is recoverable)."""
        bogus = tmp_path / "subdir" / "bogus-binary"
        result = _compute_python_tool_paths([str(bogus)])
        # Subdir is the bin dir.
        assert any(p == str(tmp_path / "subdir") for p in result), \
            f"expected bin dir in result, got {result!r}"

    def test_skips_system_paths(self):
        """Paths already in the mount-ns bind tree (/usr, /bin, etc.)
        should be skipped — no point asking for a redundant bind."""
        # /usr/bin/python3 → bin dir /usr/bin (skip), interp lib at
        # /usr/lib/python3.X (skip). Net: should be empty.
        result = _compute_python_tool_paths(["/usr/bin/python3"])
        for path in result:
            assert not path.startswith(("/usr/", "/lib/", "/lib64/")), \
                f"{path!r} should have been filtered out"

    def test_python_tool_with_shebang_returns_bin_and_stdlib(
            self, tmp_path):
        """A pip-style Python tool: bin/script with #!python shebang,
        interpreter in same bin dir, stdlib at ../lib/pythonX.Y.
        Synthesise this layout in tmp_path and verify both dirs
        come back."""
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()
        lib_dir = tmp_path / "lib" / "python3.13"
        lib_dir.mkdir(parents=True)
        # Synthesise a Python interpreter file (need not be runnable;
        # is_file() check is what the helper uses).
        py = bin_dir / "python3.13"
        py.write_text("#!/bin/sh\necho fake python\n")
        py.chmod(0o755)
        # Synthesise the script with shebang pointing at our fake.
        script = bin_dir / "myscript"
        script.write_text(f"#!{py}\nprint('hi')\n")
        script.chmod(0o755)
        result = _compute_python_tool_paths([str(script)])
        assert str(bin_dir) in result, \
            f"bin dir missing from {result!r}"
        assert str(lib_dir) in result, \
            f"stdlib dir missing from {result!r}"


"""Tests for core.sandbox.python_paths — Python runtime discovery for sandbox allowlists."""

from __future__ import annotations

from unittest.mock import patch

from core.sandbox.python_paths import python_runtime_tool_paths, _under_system_prefix


class TestUnderSystemPrefix:

    def test_usr_lib(self):
        assert _under_system_prefix("/usr/lib/python3.14") is True

    def test_usr_exact(self):
        assert _under_system_prefix("/usr") is True

    def test_lib64(self):
        assert _under_system_prefix("/lib64/x86_64-linux-gnu") is True

    def test_opt_homebrew(self):
        assert _under_system_prefix("/opt/homebrew/Frameworks") is False

    def test_home(self):
        assert _under_system_prefix("/home/user/.pyenv/versions/3.14") is False

    def test_nix(self):
        assert _under_system_prefix("/nix/store/abc-python3") is False


class TestPythonRuntimeToolPaths:

    def test_system_python_returns_empty(self, tmp_path):
        """A standard /usr/lib Python should produce no extra paths."""
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = "/usr"
            mock_sys.base_prefix = "/usr"
            mock_sys.exec_prefix = "/usr"
            mock_sys.base_exec_prefix = "/usr"
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert result == []

    def test_framework_install(self, tmp_path):
        """Homebrew/Xcode framework prefix outside /usr must be included."""
        fw = tmp_path / "Python.framework" / "Versions" / "3.14"
        fw.mkdir(parents=True)
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(fw)
            mock_sys.base_prefix = str(fw)
            mock_sys.exec_prefix = str(fw)
            mock_sys.base_exec_prefix = str(fw)
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert str(fw.resolve()) in result

    def test_virtualenv_both_prefixes(self, tmp_path):
        """Venv prefix and base_prefix should both appear when distinct."""
        venv = tmp_path / "venv"
        base = tmp_path / "base-python"
        venv.mkdir()
        base.mkdir()
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(venv)
            mock_sys.base_prefix = str(base)
            mock_sys.exec_prefix = str(venv)
            mock_sys.base_exec_prefix = str(base)
            mock_sys.executable = str(venv / "bin" / "python3")
            (venv / "bin").mkdir()
            result = python_runtime_tool_paths()
        resolved_venv = str(venv.resolve())
        resolved_base = str(base.resolve())
        assert resolved_venv in result
        assert resolved_base in result

    def test_exec_prefix_differs_from_prefix(self, tmp_path):
        """Debian multiarch: exec_prefix != prefix — both must appear."""
        prefix = tmp_path / "prefix"
        exec_prefix = tmp_path / "exec-prefix"
        prefix.mkdir()
        exec_prefix.mkdir()
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(prefix)
            mock_sys.base_prefix = str(prefix)
            mock_sys.exec_prefix = str(exec_prefix)
            mock_sys.base_exec_prefix = str(exec_prefix)
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert str(prefix.resolve()) in result
        assert str(exec_prefix.resolve()) in result

    def test_executable_parent_included(self, tmp_path):
        """The directory containing python3 must be included if outside /usr."""
        bindir = tmp_path / "opt" / "bin"
        bindir.mkdir(parents=True)
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = "/usr"
            mock_sys.base_prefix = "/usr"
            mock_sys.exec_prefix = "/usr"
            mock_sys.base_exec_prefix = "/usr"
            mock_sys.executable = str(bindir / "python3")
            result = python_runtime_tool_paths()
        assert str(bindir.resolve()) in result

    def test_deduplication(self, tmp_path):
        """Same resolved path from multiple attrs should appear once."""
        d = tmp_path / "python"
        d.mkdir()
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(d)
            mock_sys.base_prefix = str(d)
            mock_sys.exec_prefix = str(d)
            mock_sys.base_exec_prefix = str(d)
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert result.count(str(d.resolve())) == 1

    def test_nonexistent_prefix_skipped(self, tmp_path):
        """A prefix pointing to a nonexistent directory is silently dropped."""
        ghost = tmp_path / "does-not-exist"
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(ghost)
            mock_sys.base_prefix = "/usr"
            mock_sys.exec_prefix = "/usr"
            mock_sys.base_exec_prefix = "/usr"
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert str(ghost) not in result

    def test_missing_attrs_handled(self):
        """Gracefully handles a sys module missing expected attributes."""
        class BareModule:
            pass
        with patch("core.sandbox.python_paths.sys", BareModule()):
            result = python_runtime_tool_paths()
        assert result == []

    def test_symlink_resolved(self, tmp_path):
        """Symlinked prefix resolves to the real directory."""
        real = tmp_path / "real-python"
        real.mkdir()
        link = tmp_path / "link-python"
        link.symlink_to(real)
        with patch("core.sandbox.python_paths.sys") as mock_sys:
            mock_sys.prefix = str(link)
            mock_sys.base_prefix = str(link)
            mock_sys.exec_prefix = str(link)
            mock_sys.base_exec_prefix = str(link)
            mock_sys.executable = "/usr/bin/python3"
            result = python_runtime_tool_paths()
        assert str(real.resolve()) in result
        assert str(link) not in result

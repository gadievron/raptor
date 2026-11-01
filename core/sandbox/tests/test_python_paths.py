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


def test_selected_tool_home_rooted_venv_does_not_grant_home(tmp_path, monkeypatch):
    from core.sandbox.python_paths import python_tool_paths
    home = tmp_path / 'home'
    binary = home / 'bin'
    binary.mkdir(parents=True)
    base = tmp_path / 'base'
    (base / 'bin').mkdir(parents=True)
    python = base / 'bin/python3.14'
    python.write_text('#!/bin/sh\ntouch should-never-execute\n')
    python.chmod(0o755)
    (binary / 'python3').symlink_to(python)
    (home / 'pyvenv.cfg').write_text('home = ' + str(base / 'bin'))
    library = home / 'lib/python3.14'
    library.mkdir(parents=True)
    (base / 'lib/python3.14').mkdir(parents=True)
    (home / '.aws').mkdir()
    tool = binary / 'semgrep'
    tool.write_text('#!' + str(binary / 'python3') + '\n')
    tool.chmod(0o755)
    monkeypatch.setenv('HOME', str(home))
    paths = python_tool_paths(str(tool))
    assert str(binary) in paths
    assert str(library) in paths
    assert str(home / 'pyvenv.cfg') in paths
    assert str(base / 'lib/python3.14') in paths
    assert str(home) not in paths
    assert str(home / '.aws') not in paths
    assert not (tmp_path / 'should-never-execute').exists()


def test_selected_tool_env_shebang_and_symlink_launcher(tmp_path, monkeypatch):
    from core.sandbox.python_paths import python_tool_paths
    binary = tmp_path / 'venv/bin'
    binary.mkdir(parents=True)
    python = binary / 'python3.14'
    python.write_text('not executed')
    python.chmod(0o755)
    tool = binary / 'semgrep'
    tool.write_text('#!/usr/bin/env -S python3.14 -I\n')
    tool.chmod(0o755)
    links = tmp_path / 'links'
    links.mkdir()
    (links / 'semgrep').symlink_to(tool)
    library = tmp_path / 'venv/lib/python3.14'
    library.mkdir(parents=True)
    monkeypatch.setenv('PATH', str(binary))
    paths = python_tool_paths(str(links / 'semgrep'))
    assert str(links) in paths
    assert str(binary) in paths
    assert str(library) in paths


def test_selected_tool_does_not_read_non_regular_launcher(tmp_path):
    import os
    from core.sandbox.python_paths import python_tool_paths
    fifo = tmp_path / 'tool'
    os.mkfifo(fifo)
    assert python_tool_paths(str(fifo)) == [str(tmp_path)]


def test_selected_tool_library_alias_cannot_expose_home(tmp_path, monkeypatch):
    from core.sandbox.python_paths import python_tool_paths
    home = tmp_path / 'home'
    home.mkdir()
    monkeypatch.setenv('HOME', str(home))
    environment = tmp_path / 'venv'
    (environment / 'bin').mkdir(parents=True)
    (environment / 'lib').mkdir()
    (environment / 'lib/python3.14').symlink_to(home, target_is_directory=True)
    python = environment / 'bin/python3.14'
    python.write_text('not executed')
    python.chmod(0o755)
    paths = python_tool_paths(str(python))
    assert str(home) not in paths
    assert str(environment / 'lib/python3.14') not in paths


def test_running_home_rooted_python_never_grants_home(tmp_path, monkeypatch):
    import sysconfig
    home = tmp_path / 'home'
    (home / 'bin').mkdir(parents=True)
    library = home / 'lib' / ('python' + sysconfig.get_python_version())
    library.mkdir(parents=True)
    (home / 'pyvenv.cfg').write_text('home = /usr/bin')
    monkeypatch.setenv('HOME', str(home))
    with patch('core.sandbox.python_paths.sys') as runtime:
        runtime.prefix = runtime.exec_prefix = str(home)
        runtime.base_prefix = runtime.base_exec_prefix = '/usr'
        runtime.executable = str(home / 'bin/python3')
        paths = python_runtime_tool_paths()
    assert str(home) not in paths
    assert str(home / 'bin') in paths
    assert str(library) in paths
    assert str(home / 'pyvenv.cfg') in paths


def test_running_python_rejects_runtime_alias_to_home(tmp_path, monkeypatch):
    import sysconfig
    home = tmp_path / 'home'
    home.mkdir()
    (home / 'lib').mkdir()
    (home / 'lib' / ('python' + sysconfig.get_python_version())).symlink_to(home)
    monkeypatch.setenv('HOME', str(home))
    with patch('core.sandbox.python_paths.sys') as runtime:
        runtime.prefix = runtime.exec_prefix = str(home)
        runtime.base_prefix = runtime.base_exec_prefix = '/usr'
        runtime.executable = '/usr/bin/python3'
        assert str(home) not in python_runtime_tool_paths()


def test_home_override_does_not_expose_account_home_prefix(tmp_path, monkeypatch):
    import sysconfig
    from types import SimpleNamespace
    account = tmp_path / 'account'
    (account / 'bin').mkdir(parents=True)
    library = account / 'lib' / ('python' + sysconfig.get_python_version())
    library.mkdir(parents=True)
    configured = tmp_path / 'configured-home'
    configured.mkdir()
    monkeypatch.setenv('HOME', str(configured))
    with patch('pwd.getpwuid', return_value=SimpleNamespace(pw_dir=str(account))), \
            patch('core.sandbox.python_paths.sys') as runtime:
        runtime.prefix = runtime.exec_prefix = str(account)
        runtime.base_prefix = runtime.base_exec_prefix = '/usr'
        runtime.executable = str(account / 'bin/python3')
        paths = python_runtime_tool_paths()
    assert str(account) not in paths
    assert str(account / 'bin') in paths
    assert str(library) in paths

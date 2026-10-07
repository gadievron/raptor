"""joern_tool_paths — sandbox bind-tree declaration for the Joern install.

A user-local Joern install is outside the sandbox's mount-ns bind tree;
without a tool_paths declaration every sandboxed joern-parse/joern call
demotes to the mountless namespace backend. These tests pin the helper's
root derivation and that both runner spawn sites declare it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import packages.joern.prereqs as prereqs
from packages.joern.prereqs import joern_tool_paths
from packages.joern.runner import build_cpg, run_query
from packages.joern.models import JoernCPG


@pytest.fixture(autouse=True)
def _fresh_path_cache():
    prereqs.reset_path_cache()
    yield
    prereqs.reset_path_cache()


def _fake_install(root: Path, *, flat: bool = False) -> dict[str, str]:
    """Create a fake Joern install tree.

    Default (tarball) layout: ``joern-cli/bin/joern``, ``joern-cli/lib/``.
    ``flat=True``: launchers directly in ``joern-cli/`` with no ``bin/``
    subdir (e.g. coursier or manual unpack).
    """
    cli = root / "joern-install" / "joern-cli"
    if flat:
        cli.mkdir(parents=True)
        launcher_dir = cli
    else:
        bin_dir = cli / "bin"
        bin_dir.mkdir(parents=True)
        (cli / "lib").mkdir()
        launcher_dir = bin_dir
    launchers = {}
    for name in ("joern", "joern-parse"):
        p = launcher_dir / name
        p.write_text("#!/bin/sh\n")
        launchers[name] = str(p)
    return launchers


class TestJoernToolPaths:
    def test_returns_launcher_parent_deduplicated(self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        paths = joern_tool_paths()
        assert paths == [str(tmp_path / "joern-install" / "joern-cli")]

    def test_flat_install_returns_cli_dir(self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path, flat=True)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        paths = joern_tool_paths()
        assert paths == [str(tmp_path / "joern-install" / "joern-cli")]

    def test_flat_install_ignores_grandparent_lib(
            self, tmp_path, monkeypatch):
        # A flat Joern under /opt/joern-cli/ must not climb to /opt/
        # even when /opt/lib/ exists (unrelated system libraries).
        launchers = _fake_install(tmp_path, flat=True)
        (tmp_path / "joern-install" / "lib").mkdir()
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        paths = joern_tool_paths()
        assert paths == [str(tmp_path / "joern-install" / "joern-cli")]
        assert str(tmp_path / "joern-install") not in paths

    def test_home_bin_joern_never_declares_home(
            self, tmp_path, monkeypatch):
        home = tmp_path / "home"
        home_bin = home / "bin"
        home_bin.mkdir(parents=True)
        (home / "lib").mkdir()
        launchers = {}
        for name in ("joern", "joern-parse"):
            p = home_bin / name
            p.write_text("#!/bin/sh\n")
            launchers[name] = str(p)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        monkeypatch.setenv("HOME", str(home))
        paths = joern_tool_paths()
        assert str(home) not in paths
        assert str(home_bin) in paths

    def test_system_installs_need_no_declaration(self, monkeypatch):
        monkeypatch.setattr(
            "shutil.which",
            lambda name: "/usr/bin/env" if name in (
                "joern", "joern-parse", "java") else None)
        assert joern_tool_paths() == []

    def test_nothing_resolved_returns_empty(self, monkeypatch):
        monkeypatch.setattr("shutil.which", lambda name: None)
        assert joern_tool_paths() == []

    def test_user_local_jdk_root_included_when_jdk_shaped(
            self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path)
        jdk_bin = tmp_path / "jdk" / "bin"
        jdk_bin.mkdir(parents=True)
        (tmp_path / "jdk" / "release").write_text("JAVA_VERSION=\"25\"\n")
        java = jdk_bin / "java"
        java.write_text("")
        launchers["java"] = str(java)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        paths = joern_tool_paths()
        assert str(tmp_path / "jdk") in paths

    def test_home_bin_java_never_declares_home(self, tmp_path, monkeypatch):
        # A wrapper at ~/bin/java must not climb to $HOME: only the
        # bin dir itself may be declared, HOME never enters the set.
        home = tmp_path / "home"
        home_bin = home / "bin"
        home_bin.mkdir(parents=True)
        java = home_bin / "java"
        java.write_text("#!/bin/sh\n")
        launchers = _fake_install(tmp_path)
        launchers["java"] = str(java)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        monkeypatch.setenv("HOME", str(home))
        paths = joern_tool_paths()
        assert str(home) not in paths
        assert str(home_bin) in paths

    def test_jdk_shaped_home_still_refused(self, tmp_path, monkeypatch):
        # Even a $HOME that carries JDK shape markers (planted or
        # coincidental) is never declared.
        home = tmp_path / "home"
        home_bin = home / "bin"
        home_bin.mkdir(parents=True)
        (home / "release").write_text("JAVA_VERSION=\"25\"\n")
        java = home_bin / "java"
        java.write_text("")
        launchers = _fake_install(tmp_path)
        launchers["java"] = str(java)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        monkeypatch.setenv("HOME", str(home))
        paths = joern_tool_paths()
        assert str(home) not in paths

    def test_dotlocal_shim_declares_bin_dir_only(self, tmp_path, monkeypatch):
        # A version-manager shim at ~/.local/bin/java must not climb
        # to ~/.local (keyrings, browser profiles live beside it).
        home = tmp_path / "home"
        local_bin = home / ".local" / "bin"
        local_bin.mkdir(parents=True)
        java = local_bin / "java"
        java.write_text("#!/bin/sh\n")
        launchers = _fake_install(tmp_path)
        launchers["java"] = str(java)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        monkeypatch.setenv("HOME", str(home))
        paths = joern_tool_paths()
        assert str(home / ".local") not in paths
        assert str(local_bin) in paths

    def test_system_prefixes_pinned_to_sandbox_copy(self):
        # prereqs mirrors core.sandbox.python_paths._SYSTEM_PREFIXES;
        # this pin makes drift test-visible instead of silent.
        from core.sandbox.python_paths import (
            _SYSTEM_PREFIXES as sandbox_prefixes,
        )
        assert prereqs._SYSTEM_PREFIXES == sandbox_prefixes

    def test_symlinked_launcher_resolves_to_real_parent(
            self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path)
        shim_dir = tmp_path / "shims"
        shim_dir.mkdir()
        shim = shim_dir / "joern-parse"
        shim.symlink_to(launchers["joern-parse"])
        launchers["joern-parse"] = str(shim)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        paths = joern_tool_paths()
        assert paths == [str(tmp_path / "joern-install" / "joern-cli")]


class TestRunnerDeclaresToolPaths:
    def _recording_runner(self, seen, stdout: str = ""):
        def _runner(cmd, **kwargs):
            seen.update(kwargs)
            from types import SimpleNamespace
            return SimpleNamespace(returncode=0, stdout=stdout, stderr="")
        return _runner

    def test_build_cpg_passes_tool_paths(self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        target = tmp_path / "src"
        target.mkdir()
        (target / "a.c").write_text("int main(void){return 0;}\n")
        seen: dict = {}
        build_cpg(target, subprocess_runner=self._recording_runner(seen))
        assert seen.get("tool_paths") == [
            str(tmp_path / "joern-install" / "joern-cli")]

    def test_run_query_passes_tool_paths(self, tmp_path, monkeypatch):
        launchers = _fake_install(tmp_path)
        monkeypatch.setattr(
            "shutil.which", lambda name: launchers.get(name))
        cpg_path = tmp_path / "cpg.bin"
        cpg_path.write_bytes(b"\x00")
        cpg = JoernCPG(path=cpg_path, target=tmp_path, languages=["c"])
        seen: dict = {}
        run_query(
            cpg, "cpg.method.l",
            subprocess_runner=self._recording_runner(seen, stdout=""),
        )
        assert seen.get("tool_paths") == [
            str(tmp_path / "joern-install" / "joern-cli")]

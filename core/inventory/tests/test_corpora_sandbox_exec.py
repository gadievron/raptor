"""Corpus drivers must execute fetched build systems inside the sandbox.

The drivers clone pinned upstream refs and run the FETCHED build
machinery (autogen/configure/make/cmake/ctest/cargo) plus the binaries
it produces. Pre-fix they did so via bare ``subprocess.run`` with
``env={**os.environ, ...}`` — attacker build scripts (supply-chain
compromise of a pinned tag) would run with the operator's full
environment, network, and filesystem. These tests pin the helper's
sandbox policy and the drivers' adoption of it.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

import core.sandbox as sandbox_mod
from core.inventory.binary_oracle_corpora import _sandbox_exec

REPO = Path(__file__).resolve().parents[3]
CORPORA = REPO / "core" / "inventory" / "binary_oracle_corpora"

_DRIVERS = (
    "zlib.py", "libsodium.py", "snappy.py", "leveldb.py",
    "regex_rust.py", "zstd_holdout.py", "synthetic.py",
)


class _Recorder:
    def __init__(self, returncode=0):
        self.calls = []
        self.returncode = returncode

    def __call__(self, cmd, **kwargs):
        self.calls.append((list(cmd), kwargs))
        return SimpleNamespace(returncode=self.returncode,
                               stdout="out", stderr="err")


class TestRunBuildStep:
    def test_sandboxed_network_blocked_env_sanitised(
            self, tmp_path, monkeypatch):
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run", rec)
        monkeypatch.setenv("LD_PRELOAD", "/tmp/evil.so")
        monkeypatch.setenv("PYTHONSTARTUP", "/tmp/evil.py")

        _sandbox_exec.run_build_step(
            ["./configure", "--static"], cwd=tmp_path, timeout=10,
            extra_env={"CFLAGS": "-O0"},
        )

        cmd, kwargs = rec.calls[0]
        assert cmd == ["./configure", "--static"]
        assert kwargs["block_network"] is True
        assert kwargs["target"] == str(tmp_path)
        assert kwargs["output"] == str(tmp_path)
        assert kwargs["env_caller_filtered"] is True
        env = kwargs["env"]
        assert "LD_PRELOAD" not in env
        assert "PYTHONSTARTUP" not in env
        assert env["CFLAGS"] == "-O0"

    def test_network_optin_only_for_declared_fetch_steps(
            self, tmp_path, monkeypatch):
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run", rec)
        _sandbox_exec.run_build_step(
            ["cargo", "build"], cwd=tmp_path, timeout=10, network=True,
        )
        assert rec.calls[0][1]["block_network"] is False

    def test_nonzero_exit_raises_calledprocesserror(
            self, tmp_path, monkeypatch):
        rec = _Recorder(returncode=2)
        monkeypatch.setattr(sandbox_mod, "run", rec)
        with pytest.raises(subprocess.CalledProcessError):
            _sandbox_exec.run_build_step(
                ["make"], cwd=tmp_path, timeout=10)

    def test_writable_paths_forwarded(self, tmp_path, monkeypatch):
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run", rec)
        extra = tmp_path / "profraw"
        _sandbox_exec.run_build_step(
            ["ctest"], cwd=tmp_path, timeout=10, writable_paths=[extra],
        )
        assert rec.calls[0][1]["writable_paths"] == [str(extra)]

    def test_scope_widens_sandbox_root_but_not_cwd(
            self, tmp_path, monkeypatch):
        """Out-of-tree builds pass the scratch parent as ``scope`` so
        the sibling src/ tree is visible under mount-ns isolation; the
        step still executes in its build dir."""
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run", rec)
        build = tmp_path / "build"
        build.mkdir()
        _sandbox_exec.run_build_step(
            ["cmake", "../src"], cwd=build, scope=tmp_path, timeout=10,
        )
        kwargs = rec.calls[0][1]
        assert kwargs["cwd"] == str(build)
        assert kwargs["target"] == str(tmp_path)
        assert kwargs["output"] == str(tmp_path)


class TestRunTool:
    def test_routes_through_run_trusted(self, tmp_path, monkeypatch):
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run_trusted", rec)
        out = _sandbox_exec.run_tool(
            ["nm", "lib.a"], cwd=tmp_path, timeout=5, check=False)
        cmd, kwargs = rec.calls[0]
        assert cmd == ["nm", "lib.a"]
        assert kwargs["cwd"] == str(tmp_path)
        assert out.stdout == "out"

    def test_input_text_forwarded(self, monkeypatch):
        rec = _Recorder()
        monkeypatch.setattr(sandbox_mod, "run_trusted", rec)
        _sandbox_exec.run_tool(
            ["c++filt"], timeout=5, check=False, input_text="_ZN3foo")
        assert rec.calls[0][1]["input"] == "_ZN3foo"

    def test_nonzero_exit_raises_when_checked(self, monkeypatch):
        rec = _Recorder(returncode=1)
        monkeypatch.setattr(sandbox_mod, "run_trusted", rec)
        with pytest.raises(subprocess.CalledProcessError):
            _sandbox_exec.run_tool(["gcov"], timeout=5)


class TestDriverAdoption:
    """Drift-guard: no driver may run a fetched build system or an
    os.environ-inheriting subprocess outside the helper."""

    def test_no_inherited_environ_in_subprocess_env(self):
        for name in _DRIVERS:
            text = (CORPORA / name).read_text(encoding="utf-8")
            assert "{**os.environ" not in text, (
                f"{name}: builds must use run_build_step's sanitised "
                f"env, not the operator's os.environ")

    def test_build_systems_not_invoked_via_bare_subprocess(self):
        build_cmds = ('"make"', '"cmake"', '"ctest"', '"cargo"',
                      '"./configure"', '"./autogen.sh"')
        for name in _DRIVERS:
            text = (CORPORA / name).read_text(encoding="utf-8")
            for chunk in text.split("subprocess.run(")[1:]:
                head = chunk[:200]
                for cmd in build_cmds:
                    assert cmd not in head, (
                        f"{name}: {cmd} runs via bare subprocess.run — "
                        f"route it through run_build_step")

    def test_drivers_import_the_helper(self):
        for name in _DRIVERS:
            text = (CORPORA / name).read_text(encoding="utf-8")
            assert "run_build_step" in text, (
                f"{name}: no run_build_step usage found")


def test_helper_env_base_is_get_safe_env(monkeypatch, tmp_path):
    """The helper's base env must come from get_safe_env, not a copy of
    the process env — belt-and-braces on top of the driver lint."""
    rec = _Recorder()
    monkeypatch.setattr(sandbox_mod, "run", rec)
    monkeypatch.setenv("SOME_RANDOM_OPERATOR_VAR", "x")
    _sandbox_exec.run_build_step(["make"], cwd=tmp_path, timeout=5)
    env = rec.calls[0][1]["env"]
    assert "SOME_RANDOM_OPERATOR_VAR" not in env
    assert "PATH" in env  # compilers must still resolve

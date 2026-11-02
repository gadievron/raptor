"""Timeout handling in libexec/raptor-run-sandboxed.

The script's run() call carries a 1800s backstop; a child that hits it
raises subprocess.TimeoutExpired, which must surface as the documented
structured error (`[sandbox] ERROR`, exit 2) with the child's partial
output passed through — not as a raw traceback.

Hermetic: the script is exec'd in-process with a stubbed core.sandbox
module, so no namespaces, Landlock, or real children are involved.
"""

from __future__ import annotations

import contextlib
import importlib.machinery
import importlib.util
import subprocess
import sys
import types
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[3]
SCRIPT = REPO_ROOT / "libexec" / "raptor-run-sandboxed"


def _exec_script(monkeypatch, tmp_path, run_fn) -> None:
    """Execute the script top-to-bottom with a stubbed sandbox."""
    fake = types.ModuleType("core.sandbox")

    class SandboxSetupError(Exception):
        pass

    @contextlib.contextmanager
    def sandbox(**_kwargs):
        yield run_fn

    fake.SandboxSetupError = SandboxSetupError
    fake.SANDBOX_ENGAGE_EXIT_CODE = 3
    fake.sandbox = sandbox
    monkeypatch.setitem(sys.modules, "core.sandbox", fake)

    out_dir = tmp_path / "out"
    monkeypatch.setenv("_RAPTOR_TRUSTED", "1")
    monkeypatch.setenv("OUTPUT_DIR", str(out_dir))
    monkeypatch.setattr(sys, "argv", ["raptor-run-sandboxed", "/bin/true"])

    loader = importlib.machinery.SourceFileLoader(
        "raptor_run_sandboxed_under_test", str(SCRIPT))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()):
        loader.exec_module(mod)


def test_timeout_produces_structured_error(monkeypatch, tmp_path, capsys):
    def run_fn(cmd, **_kwargs):
        raise subprocess.TimeoutExpired(
            cmd, 1800, output="PARTIAL-OUT\n", stderr="PARTIAL-ERR\n")

    with pytest.raises(SystemExit) as exc:
        _exec_script(monkeypatch, tmp_path, run_fn)
    assert exc.value.code == 2
    captured = capsys.readouterr()
    assert "[sandbox] ERROR" in captured.err
    assert "TimeoutExpired" in captured.err
    # Partial child output attached to the exception is passed through.
    assert "PARTIAL-OUT" in captured.out
    assert "PARTIAL-ERR" in captured.err


def test_success_path_mirrors_child_exit(monkeypatch, tmp_path, capsys):
    def run_fn(cmd, **_kwargs):
        return SimpleNamespace(
            returncode=7, stdout="child-out\n", stderr="", sandbox_info={})

    with pytest.raises(SystemExit) as exc:
        _exec_script(monkeypatch, tmp_path, run_fn)
    assert exc.value.code == 7
    captured = capsys.readouterr()
    assert "child-out" in captured.out
    assert "[sandbox] ERROR" not in captured.err


def test_env_timeout_override_reaches_run(monkeypatch, tmp_path):
    """RAPTOR_SANDBOX_TIMEOUT raises the 1800s default per run —
    ASAN builds of large projects routinely exceed 30 minutes and the
    hardcoded backstop killed them with no override."""
    seen: dict = {}

    def run_fn(cmd, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return SimpleNamespace(
            returncode=0, stdout="", stderr="", sandbox_info={})

    monkeypatch.setenv("RAPTOR_SANDBOX_TIMEOUT", "7200")
    with pytest.raises(SystemExit) as exc:
        _exec_script(monkeypatch, tmp_path, run_fn)
    assert exc.value.code == 0
    assert seen["timeout"] == 7200


def test_default_timeout_still_1800(monkeypatch, tmp_path):
    seen: dict = {}

    def run_fn(cmd, **kwargs):
        seen["timeout"] = kwargs.get("timeout")
        return SimpleNamespace(
            returncode=0, stdout="", stderr="", sandbox_info={})

    monkeypatch.delenv("RAPTOR_SANDBOX_TIMEOUT", raising=False)
    with pytest.raises(SystemExit):
        _exec_script(monkeypatch, tmp_path, run_fn)
    assert seen["timeout"] == 1800


@pytest.mark.parametrize("bad", ["abc", "-5", "0", "1.5"])
def test_invalid_env_timeout_refuses(monkeypatch, tmp_path, capsys, bad):
    """A malformed override must refuse loudly, never fall back
    silently (an unbounded or zero timeout defeats the backstop)."""
    def run_fn(cmd, **_kwargs):  # pragma: no cover — must not be reached
        raise AssertionError("sandbox must not engage")

    monkeypatch.setenv("RAPTOR_SANDBOX_TIMEOUT", bad)
    with pytest.raises(SystemExit) as exc:
        _exec_script(monkeypatch, tmp_path, run_fn)
    assert exc.value.code == 1
    assert "RAPTOR_SANDBOX_TIMEOUT" in capsys.readouterr().err

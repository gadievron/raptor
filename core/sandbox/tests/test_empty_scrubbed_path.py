"""Inherited home-only PATH must not survive sandbox environment preparation."""

import os
import sys

import pytest

from core.sandbox import context
from core.sandbox.errors import SandboxSetupError
from core.sandbox.tests.test_context_decision_pins import _Driver, _SpawnRecorder
from core.testing.module_bindings import patch_module_attribute
from core.testing.state_isolation import pin_user_state_dirs

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux dispatcher preparation")


@pytest.fixture
def prepared(monkeypatch, tmp_path):
    pin_user_state_dirs(monkeypatch, tmp_path / "state")
    home = tmp_path / "home"
    tools = home / "bin"
    tools.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("PATH", str(tools))
    recorder = _SpawnRecorder()
    _Driver(monkeypatch, recorder)

    def forbid_process(*args, **kwargs):
        pytest.fail("environment preparation must not launch a process")

    monkeypatch.setattr(context, "_run_teardown_first_timeout", forbid_process)
    patch_module_attribute(monkeypatch, context, "subprocess", "Popen", forbid_process)
    return tools, recorder


@pytest.mark.parametrize("mode", ["home-only", "mixed", "declared", "explicit"])
def test_scrubbed_path_and_explicit_controls(prepared, monkeypatch, tmp_path, mode):
    tools, recorder = prepared
    sandbox_kwargs = {}
    run_kwargs = {}
    expected = os.defpath
    if mode == "mixed":
        monkeypatch.setenv("PATH", str(tools) + os.pathsep + os.defpath)
    elif mode == "declared":
        sandbox_kwargs["tool_paths"] = [str(tools)]
        expected = str(tools)
    elif mode == "explicit":
        run_kwargs["env"] = {"PATH": str(tools)}
        expected = str(tools)
    with context.sandbox(profile="full", target=str(tmp_path), **sandbox_kwargs) as run:
        result = run(["/bin/true"], capture_output=True, timeout=1, **run_kwargs)
    assert result.returncode == 0
    assert len(recorder.calls) == 1
    assert recorder.calls[0]["env"]["PATH"] == expected


def test_home_only_bare_tool_refuses_changed_resolution(prepared, tmp_path):
    tools, recorder = prepared
    executable = tools / "owned-home-only-tool"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    with context.sandbox(profile="full", target=str(tmp_path)) as run:
        with pytest.raises(SandboxSetupError, match="refusing to exec a different binary"):
            run([executable.name], capture_output=True, timeout=1)
    assert recorder.calls == []

"""Offline argv keeps a selected symlink without expanding sandbox grants."""

import builtins
import importlib.util
from pathlib import Path
import shutil
import subprocess
from types import ModuleType

import pytest

from core.config import RaptorConfig
from core.testing.module_views import module_function_view
from packages.semgrep import runner


def _launcher(tmp_path):
    dispatcher = tmp_path / "usr" / "lib" / "snapd" / "snapd"
    dispatcher.parent.mkdir(parents=True)
    dispatcher.write_text("owned dispatcher metadata; never executed\n")
    launcher = tmp_path / "snap" / "bin" / "semgrep"
    launcher.parent.mkdir(parents=True)
    launcher.symlink_to(dispatcher)
    return launcher, dispatcher


def _offline_view(launcher, *, sandbox_run=None, probe_runner=None, runtime_paths=(), tool_paths=None):
    private_shutil = ModuleType(shutil.__name__)
    vars(private_shutil).update(vars(shutil))

    def which(name):
        assert name in {"semgrep", str(launcher)}
        return str(launcher)

    private_shutil.which = which

    class OfflineConfig(RaptorConfig):
        SEMGREP_OFFLINE = True

        @staticmethod
        def get_safe_env():
            return {"PATH": "/usr/bin:/bin"}

    config = ModuleType("core.config")
    config.RaptorConfig = OfflineConfig
    context = ModuleType("core.sandbox.context")
    context.run = sandbox_run
    paths = ModuleType("core.sandbox.python_paths")
    paths.python_runtime_tool_paths = lambda: list(runtime_paths)
    paths.python_tool_paths = tool_paths if tool_paths is not None else lambda selected: []

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        if level == 0 and name in {"core.config", "core.sandbox.context", "core.sandbox.python_paths"}:
            return {"core.config": config, "core.sandbox.context": context,
                    "core.sandbox.python_paths": paths}[name]
        return builtins.__import__(name, globals, locals, fromlist, level)

    bindings = {"shutil": private_shutil}
    if probe_runner is not None:
        bindings["_default_sandbox_runner"] = lambda *args, **kwargs: probe_runner
    return module_function_view(runner, bindings=bindings, import_hook=imported)


def test_offline_version_probe_preserves_selected_launcher(tmp_path):
    launcher, _ = _launcher(tmp_path)
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "1.56.0\n", "")

    result = _offline_view(launcher, probe_runner=run)._version_probe()
    assert result is not None and result.stdout == "1.56.0\n"
    assert result.path == str(launcher)
    assert len(calls) == 1
    assert calls[0][0] == [str(launcher), "--version", "--metrics", "off", "--disable-version-check"]
    assert calls[0][1]["timeout"] == 15


@pytest.mark.parametrize("selected", ["absolute", "relative"])
def test_offline_scan_preserves_launcher_with_existing_grants(tmp_path, monkeypatch, selected):
    launcher, dispatcher = _launcher(tmp_path)
    if selected == "relative":
        monkeypatch.chdir(tmp_path)
        launcher_input = launcher.relative_to(tmp_path)
    else:
        launcher_input = launcher
    target = tmp_path / "target"
    target.mkdir()
    config = tmp_path / "owned.yaml"
    config.write_text("owned rule metadata; never parsed\n")
    output = tmp_path / "output"
    output.mkdir()
    runtime = tmp_path / "owned-runtime"
    runtime.mkdir()
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    view = _offline_view(launcher_input, sandbox_run=run, runtime_paths=[str(runtime)])
    invoke = view._default_sandbox_runner(target, str(config), output_dir=str(output))
    assert invoke is not None
    result = invoke([str(launcher_input), "--json"], env={"PATH": "/usr/bin:/bin"}, timeout=3)
    assert result.returncode == 0
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv == [str(launcher), "--json"]
    assert kwargs["tool_paths"] == [str(config), str(dispatcher.parent), str(runtime)]
    assert str(launcher.parent) not in kwargs["tool_paths"]
    assert kwargs["block_network"] is True
    assert kwargs["fake_home"] is True
    assert kwargs["target"] == str(target)
    assert kwargs["output"] == str(output)
    assert kwargs["timeout"] == 3


def test_offline_scan_uses_resolved_identity_for_actual_runtime_grants(tmp_path):
    source = Path(__file__).resolve().parents[3] / "core/sandbox/python_paths.py"
    spec = importlib.util.spec_from_file_location("owned_python_paths", source)
    actual_paths = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(actual_paths)
    launcher, dispatcher = _launcher(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    config = tmp_path / "owned.yaml"
    config.write_text("owned rule metadata; never parsed\n")
    output = tmp_path / "output"
    output.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    old_grants = actual_paths.python_tool_paths(str(dispatcher))
    assert str(dispatcher.parent) in old_grants
    assert str(launcher.parent) in actual_paths.python_tool_paths(str(launcher))
    calls = []

    def run(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, "", "")

    invoke = _offline_view(launcher, sandbox_run=run, runtime_paths=[str(runtime)],
                           tool_paths=actual_paths.python_tool_paths)._default_sandbox_runner(
                               target, str(config), output_dir=str(output))
    invoke([str(launcher), "--json"], timeout=3)
    argv, kwargs = calls[0]
    assert argv == [str(launcher), "--json"]
    expected = list(dict.fromkeys([*old_grants, str(config), str(dispatcher.parent), str(runtime)]))
    assert kwargs["tool_paths"] == expected
    assert str(launcher.parent) not in kwargs["tool_paths"]

"""Native local-import and function-global faults own every lookup namespace."""
import ast
import builtins
import copy
import ctypes
import ctypes.util
from functools import lru_cache
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from core.testing.module_views import module_function_view

_REPO = Path(__file__).resolve().parents[3]
_SITES = [{'anchor': ['test_pipe_allocation_failure_is_unavailable'],
  'attribute': 'pipe',
  'call': "monkeypatch.setattr(landlock.os, 'pipe', no_pipe)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 32,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_failed_fork_releases_both_pipe_ends'],
  'attribute': 'pipe',
  'call': "monkeypatch.setattr(landlock.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 49,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_failed_fork_releases_both_pipe_ends'],
  'attribute': 'fork',
  'call': "monkeypatch.setattr(landlock.os, 'fork', fork)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 50,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['verdict_fixture'],
  'attribute': 'pipe',
  'call': "monkeypatch.setattr(landlock.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 83,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['verdict_fixture'],
  'attribute': 'fork',
  'call': "monkeypatch.setattr(landlock.os, 'fork', lambda: PID)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 84,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_interrupted_verdict_read_retries_without_losing_byte'],
  'attribute': 'read',
  'call': "monkeypatch.setattr(landlock.os, 'read', read)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 113,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_parent_action_failure_retains_child_cleanup'],
  'attribute': 'pidfd_open',
  'call': "monkeypatch.setattr(probes.os, 'pidfd_open', no_pidfd, raising=False)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 149,
  'new_target': 'probes.os',
  'target': 'probes.os'},
 {'anchor': ['test_parent_action_and_exit_share_deadline'],
  'attribute': 'pidfd_open',
  'call': "monkeypatch.setattr(probes.os, 'pidfd_open', no_pidfd, raising=False)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 176,
  'new_target': 'probes.os',
  'target': 'probes.os'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'find_library',
  'call': "monkeypatch.setattr(ctypes.util, 'find_library', lambda name: None)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 234,
  'new_target': 'landlock.ctypes.util',
  'target': 'ctypes.util'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'fork',
  'call': "monkeypatch.setattr(landlock.os, 'fork', fork)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 236,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'pipe',
  'call': "monkeypatch.setattr(landlock.os, 'pipe', pipe)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 237,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': '_exit',
  'call': "monkeypatch.setattr(landlock.os, '_exit', exit_child)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 238,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'read',
  'call': "monkeypatch.setattr(landlock.os, 'read', read)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 239,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_failed_writer_close_is_not_retried'],
  'attribute': 'close',
  'call': "patch.setattr(landlock.os, 'close', close)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 132,
  'new_target': 'landlock.os',
  'target': 'landlock.os'},
 {'anchor': ['test_artifact_directories_are_not_traversed'],
  'attribute': 'scandir',
  'call': "patcher.setattr(det.os, 'scandir', guarded_scandir)",
  'file': '.github/scripts/tests/test_check_env_docs.py',
  'line': 543,
  'new_target': 'det.os',
  'target': 'det.os'},
 {'anchor': ['test_cargo_probe_pins_relative_rustup_home'],
  'attribute': 'run',
  'call': "monkeypatch.setattr(cargofuzz_runner.subprocess, 'run', capture)",
  'file': 'core/run/tests/test_probe_execution_boundary.py',
  'line': 116,
  'new_target': 'cargofuzz_runner.subprocess',
  'target': 'cargofuzz_runner.subprocess'},
 {'anchor': ['test_probe_config_failure_never_inherits_ambient_secrets'],
  'attribute': 'run',
  'call': "monkeypatch.setattr(toolprobe.subprocess, 'run', capture)",
  'file': 'core/run/tests/test_probe_execution_boundary.py',
  'line': 133,
  'new_target': 'toolprobe.subprocess',
  'target': 'toolprobe.subprocess'},
 {'anchor': ['test_probe_strips_internal_dispatch_markers'],
  'attribute': 'run',
  'call': "monkeypatch.setattr(toolprobe.subprocess, 'run', capture)",
  'file': 'core/run/tests/test_probe_execution_boundary.py',
  'line': 151,
  'new_target': 'toolprobe.subprocess',
  'target': 'toolprobe.subprocess'},
 {'anchor': ['test_cargo_probe_retires_private_home_on_timeout'],
  'attribute': 'run',
  'call': "monkeypatch.setattr(cargofuzz_runner.subprocess, 'run', timeout)",
  'file': 'core/run/tests/test_probe_execution_boundary.py',
  'line': 199,
  'new_target': 'cargofuzz_runner.subprocess',
  'target': 'cargofuzz_runner.subprocess'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'gettempdir',
  'call': "monkeypatch.setattr(tempfile, 'gettempdir', lambda: str(tmp_path))",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 235,
  'new_target': 'landlock.tempfile',
  'target': 'tempfile'},
 {'anchor': ['test_real_probe_child_and_artifacts_are_cleaned'],
  'attribute': 'poll',
  'call': "monkeypatch.setattr(select, 'poll', CancelPoll)",
  'file': 'core/sandbox/tests/test_landlock_probe_lifecycle.py',
  'line': 243,
  'new_target': 'probes.select',
  'target': 'select'}]


@lru_cache(maxsize=None)
def _native(file):
    name = "local_lookup_native_" + file.replace("/", "_").replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(name, str(_REPO / file))
    spec = importlib.util.spec_from_loader(name, loader)
    module = importlib.util.module_from_spec(spec)
    with patch.object(sys, "path", sys.path.copy()), pytest.MonkeyPatch.context() as scope:
        scope.setitem(sys.modules, name, module)
        loader.exec_module(module)
    return module


def _namespace(module, before):
    now = vars(module)
    assert now.keys() == before.keys(), module.__name__
    assert all(now[name] is value for name, value in before.items()), module.__name__


def _setup(native, file, scope, detector=None):
    name = ("_owned_local_probe_modules" if "landlock_probe" in file else
            "_owned_detector_walk" if "check_env_docs" in file else "_owned_execution_probe_modules")
    fixture = getattr(native, name, None)
    if fixture is not None:
        args = (scope, detector) if detector is not None else (scope,)
        fixture.__wrapped__(*args)


def _environment(file, native, scope, borrowed):
    detector = native.det.__wrapped__() if "check_env_docs" in file else None
    names = ["landlock", "probes"] if "landlock_probe" in file else [] if detector else ["toolprobe", "startup", "cargofuzz_runner", "capability"]
    owners = [getattr(native, name) for name in names]
    if borrowed:
        for name in names:
            original = getattr(native, name)
            scope.setitem(vars(native), name, module_function_view(original))
        owners += [getattr(native, name) for name in names]
        if detector:
            scope.setattr(detector, "os", module_function_view(detector.os))
    from core.sandbox import landlock, probes
    from core.run import toolprobe
    from core.startup import init
    from packages.fuzzing import capability, cargofuzz_runner
    modules = [os, select, tempfile, subprocess, ctypes, ctypes.util, builtins,
               landlock, probes, toolprobe, init, capability, cargofuzz_runner, *owners]
    if detector:
        modules += [detector, detector.os]
    return detector, [(module, dict(vars(module))) for module in modules]


def _node(row):
    tree = ast.parse((_REPO / row["file"]).read_text())
    parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
    original = ast.parse(row["call"], mode="eval").body
    changed = copy.deepcopy(original)
    changed.args[0] = ast.parse(row["new_target"], mode="eval").body
    matches = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or ast.dump(node) not in {ast.dump(original), ast.dump(changed)}:
            continue
        chain = []
        parent = parents.get(node)
        while parent:
            if isinstance(parent, (ast.FunctionDef, ast.ClassDef)):
                chain.append(parent.name)
            parent = parents.get(parent)
        if chain[::-1] == row["anchor"]:
            matches.append(node)
    assert len(matches) == 1, row
    return copy.deepcopy(matches[0])


@pytest.mark.parametrize("index", [
    pytest.param(index, id=row["file"] + ":" + str(row["line"]), marks=pytest.mark.skipif(
        sys.platform != "linux" and "landlock_probe" in row["file"], reason="Linux Landlock probe namespace contracts",
    ))
    for index, row in enumerate(_SITES)
])
@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_fault_namespace_is_owned(index, borrowed, exit_mode):
    row = _SITES[index]
    native = _native(row["file"])
    with pytest.MonkeyPatch.context() as inherited:
        detector, snapshots = _environment(row["file"], native, inherited, borrowed)
        bindings = dict(vars(native))
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _setup(native, row["file"], scope, detector)
                namespace = dict(vars(native), monkeypatch=scope, patch=scope, patcher=scope)
                if detector is not None:
                    namespace["det"] = detector
                node = _node(row)
                fake = MagicMock(name="private_fault")
                node.args[2] = ast.Name(id="_fake", ctx=ast.Load())
                namespace["_fake"] = fake
                eval(compile(ast.fix_missing_locations(ast.Expression(node)), row["file"], "eval"), namespace)
                for module, before in snapshots:
                    if module is not detector:
                        _namespace(module, before)
                target = eval(compile(ast.Expression(node.args[0]), row["file"], "eval"), namespace)
                assert getattr(target, row["attribute"]) is fake
                if exit_mode != "normal":
                    raise RuntimeError("local lookup exit") if exit_mode == "error" else KeyboardInterrupt("local lookup exit")
        except BaseException as error:
            caught = error
        for module, before in snapshots:
            _namespace(module, before)
        _namespace(native, bindings)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "local lookup exit"


@pytest.mark.parametrize("file", list(dict.fromkeys(row["file"] for row in _SITES)))
@pytest.mark.parametrize("borrowed", [False, True])
def test_unmodified_native_namespace_control(file, borrowed):
    native = _native(file)
    with pytest.MonkeyPatch.context() as inherited:
        _, snapshots = _environment(file, native, inherited, borrowed)
        for module, before in snapshots:
            _namespace(module, before)


@pytest.mark.parametrize("borrowed", [False, True])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_detector_guard_reaches_real_walk_helpers(tmp_path, borrowed, exit_mode):
    file = ".github/scripts/tests/test_check_env_docs.py"
    native = _native(file)
    with pytest.MonkeyPatch.context() as inherited:
        detector, snapshots = _environment(file, native, inherited, borrowed)
        root = tmp_path / "tree"
        root.mkdir()
        (root / "child").mkdir()
        (root / "child/file.txt").write_text("owned")
        seen = []
        original = os.scandir
        def scandir(path):
            seen.append(Path(path))
            return original(path)
        caught = None
        try:
            with pytest.MonkeyPatch.context() as scope:
                _setup(native, file, scope, detector)
                scope.setattr(detector.os, "scandir", scandir)
                found = list(detector.os.walk(root))
                assert len(found) == 2 and seen == [root, root / "child"]
                for module, before in snapshots:
                    if module is not detector:
                        _namespace(module, before)
                if exit_mode != "normal":
                    raise RuntimeError("walk exit") if exit_mode == "error" else KeyboardInterrupt("walk exit")
        except BaseException as error:
            caught = error
        for module, before in snapshots:
            _namespace(module, before)
        if exit_mode == "normal":
            assert caught is None, repr(caught)
        else:
            assert isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt), repr(caught)
            assert str(caught) == "walk exit"


@pytest.mark.parametrize("borrowed", [False, True])
def test_startup_local_import_shares_owned_capture_and_cache(tmp_path, borrowed):
    file = "core/run/tests/test_probe_execution_boundary.py"
    native = _native(file)
    with pytest.MonkeyPatch.context() as inherited:
        _, snapshots = _environment(file, native, inherited, borrowed)
        cache = native.toolprobe._CACHE
        inherited.setitem(cache, ("owned-control", (), True), object())
        before_cache = cache.copy()
        with pytest.MonkeyPatch.context() as scope:
            _setup(native, file, scope)
            binary = tmp_path / "fixture-tool"
            binary.write_text("#!/bin/sh\nexit 99\n")
            binary.chmod(0o700)
            scope.setenv("PATH", str(tmp_path))
            scope.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
            calls = []
            def capture(command, **kwargs):
                calls.append(command)
                return subprocess.CompletedProcess(command, 0, "fixture 1.2.3", "")
            scope.setattr(native.toolprobe.subprocess, "run", capture)
            assert native.startup._cached_cli_version("fixture-tool") == "1.2.3"
            assert calls == [[str(binary), "--version"]]
            native.toolprobe.reset_probe_cache()
            assert cache == before_cache
            for module, before in snapshots:
                _namespace(module, before)
        assert cache == before_cache

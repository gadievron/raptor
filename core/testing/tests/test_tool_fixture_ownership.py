"""Tool fixtures own temporary files and preserve borrowed process state."""

import ast
from concurrent.futures import Future
from contextlib import contextmanager
from importlib import import_module
from inspect import signature
import os
from pathlib import Path
import tempfile
import threading
from types import FunctionType, ModuleType

import pytest

from core.atomic_fs import rmtree_hardened


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/semgrep/tests/conftest.py", "semgrep_scratch", "scratch", 6),
    ("packages/semgrep/tests/conftest.py", "_isolated_scope_probe_cache", "scope", 4),
    ("packages/ghidra/tests/test_context_inject.py", "_clear_cache", "ghidra", 2),
    ("packages/joern/tests/test_tool_paths.py", "_fresh_path_cache", "paths", 6),
]


def _view(name):
    result = ModuleType(name)
    result.__dict__.update(vars(import_module(name)))
    return result


def _prepare(case, tmp_path, fail_at=None):
    kind = case[2]
    created = set()
    if kind in ("scratch", "scope"):
        owner = _view("packages.semgrep.runner")
        owner._SCRATCH_LOCK = threading.Lock()
        owner._SCOPE_PROBE_LOCK = threading.Lock()
        pending = Future()
        owner._SCOPE_PROBE_CACHE = (("caller",), (1, 2, 3))
        owner._SCOPE_PROBE_PENDING = (("pending",), pending)
        owner._scope_upgrade_warned = True
        original_dir = tmp_path / "semgrep-sbx-borrowed"
        original_dir.mkdir()
        sentinel = original_dir / "caller.txt"
        sentinel.write_bytes(b"caller scratch must survive")
        owner._scratch_parent = str(original_dir)
        owner._scratch_owner_pid = os.getpid()
        registrations = {str(original_dir)}
        owner.keepalive_register = lambda path: registrations.add(str(path))
        owner.keepalive_unregister = lambda path: registrations.discard(str(path))
        temporary = _view("tempfile")

        def mkdtemp(prefix="", dir=None, **kwargs):
            path = tempfile.mkdtemp(prefix=prefix, dir=tmp_path if dir is None else dir, **kwargs)
            created.add(Path(path))
            return path

        temporary.mkdtemp = mkdtemp
        owner.tempfile = temporary
        for name in ("_sandbox_scratch_parent", "_invocation_scratch_dir", "_reset_sandbox_scratch", "_reset_scope_probe_cache"):
            raw = getattr(owner, name)
            clone = FunctionType(raw.__code__, owner.__dict__, name, raw.__defaults__)
            clone.__kwdefaults__ = raw.__kwdefaults__
            setattr(owner, name, clone)
        if kind == "scratch":
            fields = ("_SCRATCH_LOCK", "_scratch_parent", "_scratch_owner_pid", "tempfile", "keepalive_register", "keepalive_unregister")
        else:
            fields = ("_SCOPE_PROBE_LOCK", "_SCOPE_PROBE_CACHE", "_SCOPE_PROBE_PENDING", "_scope_upgrade_warned")
        alias = "runner"
    elif kind == "ghidra":
        owner = _view("packages.ghidra.context_inject")
        from packages.ghidra.model import REDatabase, REFunction
        function = REFunction(name="caller", address=4096, size=16, source_tool="ghidra")
        database = REDatabase(source_tool="ghidra", binary_path="/caller/binary", functions=[function])
        owner._GHIDRA_CACHE = {"/caller/project": [database]}
        owner._GHIDRA_FUNC_INDEX = {"/caller/project": {"caller": [function]}}
        owner._GHIDRA_LOCK = threading.RLock()
        fields = ("_GHIDRA_CACHE", "_GHIDRA_FUNC_INDEX", "_GHIDRA_LOCK")
        alias = "context_inject"
        raw = owner.clear_ghidra_cache
        owner.clear_ghidra_cache = FunctionType(raw.__code__, owner.__dict__)
    else:
        owner = _view("packages.joern.prereqs")
        owner._resolved_joern = "/caller/joern"
        owner._resolved_joern_parse = "/caller/joern-parse"
        owner._resolved_java = "/caller/java"
        owner._joern_resolved = owner._joern_parse_resolved = owner._java_resolved = True
        fields = ("_resolved_joern", "_joern_resolved", "_resolved_joern_parse", "_joern_parse_resolved", "_resolved_java", "_java_resolved")
        alias = "prereqs"
        raw = owner.reset_path_cache
        owner.reset_path_cache = FunctionType(raw.__code__, owner.__dict__)
    snapshot = {name: getattr(owner, name) for name in fields}
    dictionaries = [(value, value.copy()) for value in snapshot.values() if isinstance(value, dict)]
    calls = 0

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            nonlocal calls
            super().setattr(*args, **kwargs)
            calls += 1
            if calls == fail_at:
                raise RuntimeError("injected setup failure")

    helper = _view("core.testing.module_state")
    raw = helper.isolated_module_state.__wrapped__
    pytest_view = _view("pytest")
    pytest_view.MonkeyPatch = Patch
    clone = FunctionType(raw.__code__, dict(raw.__globals__, pytest=pytest_view))
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper.isolated_module_state = contextmanager(clone)
    package = _view("packages.ghidra" if kind == "ghidra" else "packages.semgrep")
    setattr(package, "context_inject" if kind == "ghidra" else "runner", owner)
    run = _view("core.run")
    scratch = _view("core.run.scratch")
    run.scratch = scratch
    atomic = _view("core.atomic_fs")
    cleanup_calls = []
    cleanup_failure = {"path": None}

    def remove_owned(path):
        cleanup_calls.append(Path(path))
        if Path(path) == cleanup_failure["path"]:
            return False
        return rmtree_hardened(path)

    atomic.rmtree_hardened = remove_owned

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name in ("packages.semgrep", "packages.ghidra"):
            return package
        if name == "core.atomic_fs":
            return atomic
        if name == "core.run":
            return run
        return __import__(name, globals, locals, fromlist, level)

    namespace = {alias: owner, "Path": Path, "runner_mod": owner,
                 "cleanup_calls": cleanup_calls, "cleanup_failure": cleanup_failure,
                 "clear_ghidra_cache": getattr(owner, "clear_ghidra_cache", None),
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for name, value in snapshot.items():
            assert getattr(owner, name) is value
        for value, before in dictionaries:
            assert value == before
            for key, payload in before.items():
                assert value[key] is payload
        if kind in ("scratch", "scope"):
            assert sentinel.read_bytes() == b"caller scratch must survive"
            assert registrations == {str(original_dir)}
            assert not pending.done()

    def cleanup():
        for path in sorted(created, key=lambda p: len(p.parts), reverse=True):
            assert rmtree_hardened(path)

    return namespace, owner, Patch, snapshot, restored, cleanup


def _start(case, namespace, patch, tmp_path):
    path, name, kind, _ = case
    tree = ast.parse((ROOT / path).read_text())
    if kind == "scratch" and not any(getattr(n, "name", None) == name for n in tree.body):
        # Exercise the old native owner, rather than failing on a missing new fixture.
        path = "packages/semgrep/tests/test_runner_batched.py"
        tree = ast.parse((ROOT / path).read_text())
        tree = next(n for n in tree.body if getattr(n, "name", None) == "TestSandboxScratch")
        name = "_fresh_scratch"
    node = next(n for n in tree.body if getattr(n, "name", None) == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[name]
    available = {"self": object(), "monkeypatch": patch, "tmp_path": tmp_path}
    generator = function(**{key: available[key] for key in signature(function).parameters})
    value = next(generator)
    return generator, value


@pytest.mark.parametrize("case", CASES, ids=[c[2] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
@pytest.mark.parametrize("body_patch", [False, True], ids=["direct-writes", "body-patches"])
def test_tool_fixture_restores_borrowed_state(case, mode, body_patch, tmp_path):
    namespace, owner, patch_type, snapshot, restored, cleanup = _prepare(case, tmp_path)
    generator = None
    owned = None
    original_mkdtemp = tempfile.mkdtemp
    real_scratch = import_module("core.run.scratch")
    original_registrations = real_scratch._keepalive_paths
    registrations_before = original_registrations.copy()
    original_ticker = real_scratch._keepalive_thread
    try:
        with patch_type.context() as patch:
            generator, local = _start(case, namespace, patch, tmp_path)
            if case[2] == "scratch":
                owned = Path(owner._sandbox_scratch_parent())
                (owned / "owned.txt").write_text("owned")
                if local is not None:
                    assert str(owned) in local._keepalive_paths
            assert tempfile.mkdtemp is original_mkdtemp
            assert real_scratch._keepalive_paths is original_registrations
            assert real_scratch._keepalive_paths == registrations_before
            assert real_scratch._keepalive_thread is original_ticker
            for name, value in snapshot.items():
                active = getattr(owner, name)
                if name.lower().endswith("lock"):
                    assert active is value
                elif case[2] != "scratch":
                    assert active is not value
                    assert not active
            if body_patch:
                field = {"scratch": "_scratch_parent", "scope": "_SCOPE_PROBE_CACHE",
                         "ghidra": "_GHIDRA_CACHE", "paths": "_resolved_joern"}[case[2]]
                value = {"scratch": None, "scope": (("owned",), (9,)),
                         "ghidra": {}, "paths": "/owned/joern"}[case[2]]
                patch.setattr(owner, field, value)
            if mode == "close":
                generator.close()
            elif mode == "throw":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                with pytest.raises(StopIteration):
                    next(generator)
        restored()
        if owned is not None:
            assert not owned.exists()
    finally:
        if generator is not None:
            generator.close()
        cleanup()


FAULTS = [(case, step) for case in CASES for step in (1, case[3])]


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[2] + ":" + str(step) for c, step in FAULTS])
def test_tool_fixture_restores_partial_setup(case, fail_at, tmp_path):
    namespace, _, patch_type, _, restored, cleanup = _prepare(case, tmp_path, fail_at)
    generator = None
    try:
        with patch_type.context() as patch:
            with pytest.raises(RuntimeError, match="injected setup failure"):
                generator, _ = _start(case, namespace, patch, tmp_path)
        restored()
    finally:
        if generator is not None:
            generator.close()
        cleanup()


def test_scratch_fixture_reclaims_tree_after_product_cleanup_failure(tmp_path):
    namespace, owner, patch_type, _, restored, cleanup = _prepare(CASES[0], tmp_path)
    generator = None
    original_remove = owner.rmtree_hardened
    try:
        with patch_type.context() as patch:
            generator, _ = _start(CASES[0], namespace, patch, tmp_path)
            owned = Path(owner._sandbox_scratch_parent())
            (owned / "partial").write_text("owned")
            # Bypass body monkeypatch undo to exercise the fixture's final fallback.
            owner.rmtree_hardened = lambda path: False
            with pytest.raises(StopIteration):
                next(generator)
            assert not owned.exists()
        restored()
    finally:
        owner.rmtree_hardened = original_remove
        if generator is not None:
            generator.close()
        cleanup()


def test_runner_battery_uses_module_scratch_scope():
    tree = ast.parse((ROOT / "packages/semgrep/tests/test_runner_batched.py").read_text())
    fixture = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_fresh_scratch"), None)
    assert fixture is not None
    assert "semgrep_scratch" in [arg.arg for arg in fixture.args.args]
    assert not any(isinstance(n, ast.Call) and ast.unparse(n.func) == "sys.path.insert" for n in ast.walk(tree))


def test_scratch_fixture_attempts_all_fallback_removals(tmp_path):
    namespace, owner, patch_type, _, restored, cleanup = _prepare(CASES[0], tmp_path)
    generator = None
    original_remove = owner.rmtree_hardened
    try:
        with patch_type.context() as patch:
            generator, _ = _start(CASES[0], namespace, patch, tmp_path)
            first = Path(owner._sandbox_scratch_parent())
            second = Path(owner.tempfile.mkdtemp(prefix="semgrep-sbx-extra-"))
            owner.rmtree_hardened = lambda path: False
            namespace["cleanup_failure"]["path"] = first
            with pytest.raises(AssertionError, match="scanner scratch cleanup failed"):
                next(generator)
            assert first in namespace["cleanup_calls"]
            assert second in namespace["cleanup_calls"]
            assert not second.exists()
        restored()
    finally:
        owner.rmtree_hardened = original_remove
        if generator is not None:
            generator.close()
        cleanup()

"""Module setup must own patches, loader state and temporary directories."""

import ast
import builtins
from contextlib import ExitStack
import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path
import sys
import tempfile
from types import ModuleType
from unittest.mock import patch, _patch

import pytest


ROOT = Path(__file__).resolve().parents[3]
PATCH_PATHS = [
    "core/orchestration/tests/test_agentic_passes.py",
    "core/orchestration/tests/test_agentic_passes_integration.py",
    "core/orchestration/tests/test_skill_dispatch.py",
    "core/sage/tests/test_finding_verdict_operator.py",
    "core/sage/tests/test_sage_hooks.py",
    "core/sage/tests/test_sage_hooks_cve.py",
    "core/sage/tests/test_sage_hooks_pipelines.py",
]
CLI_PATHS = ["core/sage/tests/" + name for name in (
    "test_sage_cli_escape.py", "test_sage_cli_hardening.py", "test_sage_cli_list_ids.py",
    "test_sage_cli_pagination.py", "test_sage_cli_report_paths.py",
    "test_sage_cli_store_redaction.py", "test_sage_cli_task_create_status.py",
    "test_sage_cli_task_domain.py",
)]
SDK_NAMES = ("sage_sdk", "sage_sdk.models", "sage_sdk.client", "sage_sdk.auth")


def _view(original):
    view = ModuleType(original.__name__)
    view.__dict__.update(vars(original))
    return view


def _load_lifecycle(path, namespace):
    for node in ast.parse((ROOT / path).read_text()).body:
        if isinstance(node, ast.FunctionDef) and node.name in {"setUpModule", "tearDownModule", "_child_isolation"}:
            node.decorator_list = []
            exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)


def _global_names(path):
    tree = ast.parse((ROOT / path).read_text())
    setup = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "setUpModule")
    return next(n.names for n in setup.body if isinstance(n, ast.Global))


@pytest.mark.parametrize("path", PATCH_PATHS)
@pytest.mark.parametrize("mode", ["normal", "start_error", "start_interrupt", "stop_error", "stop_before"])
def test_patch_module_scope_restores_handles_and_owned_resources(path, mode, tmp_path):
    import os
    target = ModuleType("module_fixture_target")
    target._key_path = lambda: tmp_path / "caller.key"
    target._session_has_human_terminal = lambda: False
    env = {"XDG_DATA_HOME": "/caller-data"}
    os_view = _view(os)
    os_view.environ = env
    owned_patches, owned_dirs = [], []
    namespace = {"__name__": "module_fixture", "Path": Path, "os": os_view}
    borrowed_scope = ExitStack()
    closed = []
    borrowed_scope.callback(closed.append, "borrowed")
    namespace["_module_fixture_scope"] = borrowed_scope
    expected_starts = 2 if "integration" in path else 1
    error = KeyboardInterrupt if mode == "start_interrupt" else RuntimeError

    def remember(patcher):
        owned_patches.append(patcher)
        start, stop = patcher.start, patcher.stop

        def start_owned():
            result = start()
            if mode in {"start_error", "start_interrupt"} and len(owned_patches) == expected_starts:
                raise error("start interrupted after effect")
            return result

        def stop_owned():
            if mode == "stop_before":
                raise RuntimeError("stop interrupted before effect")
            result = stop()
            if mode == "stop_error":
                raise RuntimeError("stop interrupted after effect")
            return result

        patcher.start, patcher.stop = start_owned, stop_owned
        return patcher

    def make_patch(name, **kwargs):
        return remember(patch.object(target, name.rsplit(".", 1)[-1], **kwargs))

    make_patch.dict = lambda mapping, values: remember(patch.dict(mapping, values))

    def temporary(*args, **kwargs):
        owned = tempfile.TemporaryDirectory(*args, dir=tmp_path, **kwargs)
        owned_dirs.append((owned, Path(owned.name)))
        return owned

    temp_view = _view(tempfile)
    temp_view.TemporaryDirectory = temporary
    namespace.update(patch=make_patch, tempfile=temp_view, TemporaryDirectory=temporary)
    _load_lifecycle(path, namespace)
    with ExitStack() as borrowed:
        for name in _global_names(path):
            if name.endswith("_tmp"):
                holder = tempfile.TemporaryDirectory(dir=tmp_path)
                borrowed.callback(holder.cleanup)
                Path(holder.name, "caller").write_text("retain")
                namespace[name] = holder
            elif name == "_xdg_patch":
                namespace[name] = patch.dict(env, {"XDG_DATA_HOME": "/borrowed-data"})
                namespace[name].start()
                borrowed.callback(namespace[name].stop)
            else:
                attribute = "_key_path" if name == "_key_patch" else "_session_has_human_terminal"
                namespace[name] = patch.object(target, attribute, return_value="borrowed")
                namespace[name].start()
                borrowed.callback(namespace[name].stop)
        before = {name: namespace[name] for name in _global_names(path)}
        target_before = dict(vars(target))
        env_before = env.copy()
        active_before = tuple(_patch._active_patches)
        try:
            if mode.startswith("start_"):
                with pytest.raises(error):
                    namespace["setUpModule"]()
            else:
                namespace["setUpModule"]()
                if mode in {"stop_error", "stop_before"}:
                    with pytest.raises(RuntimeError):
                        namespace["tearDownModule"]()
                else:
                    namespace["tearDownModule"]()
            for name, value in before.items():
                assert namespace[name] is value, name
                if name.endswith("_tmp"):
                    assert Path(value.name, "caller").read_text() == "retain"
            assert vars(target) == target_before
            assert env == env_before
            assert all(not path.exists() for _owner, path in owned_dirs)
            assert tuple(_patch._active_patches) == active_before
            assert namespace["_module_fixture_scope"] is borrowed_scope
            assert closed == []
        finally:
            scope = namespace.get("_module_fixture_scope")
            if scope is not borrowed_scope:
                scope.close()
            for owned in reversed(owned_patches):
                type(owned).stop(owned)
            for owned, _path in owned_dirs:
                owned.cleanup()
            borrowed_scope.close()


CLI_CASES = [(path, sdk) for path in CLI_PATHS for sdk in (
    ("absent", "none", "module") if "store_redaction" in path else ("absent",)
)]


@pytest.mark.parametrize("path,sdk_state", CLI_CASES)
@pytest.mark.parametrize("trust_state", ["absent", "empty", "set"])
@pytest.mark.parametrize("mode", ["normal", "load_error", "load_interrupt"])
def test_cli_module_scope_preserves_namespace_and_exact_sdk_state(path, sdk_state, trust_state, mode, tmp_path):
    import os
    sys_view, os_view, pytest_view = _view(sys), _view(os), _view(pytest)
    sys_view.path = list(sys.path)
    sys_view.modules = dict(sys.modules)
    os_view.environ = {}
    if trust_state != "absent":
        os_view.environ["_RAPTOR_TRUSTED"] = "" if trust_state == "empty" else "caller"
    for name in SDK_NAMES:
        sys_view.modules.pop(name, None)
        if sdk_state != "absent":
            sys_view.modules[name] = None if sdk_state == "none" else ModuleType(name)
    before_sdk = {name: (name in sys_view.modules, sys_view.modules.get(name)) for name in SDK_NAMES}
    env_before = os_view.environ.copy()
    path_before, path_contents = sys_view.path, sys_view.path.copy()

    class LocalPatch(pytest.MonkeyPatch):
        def setenv(self, name, value, prepend=None):
            assert prepend is None
            self.setitem(os_view.environ, name, value)

    pytest_view.MonkeyPatch = LocalPatch
    import_real = builtins.__import__

    def import_local(name, *args, **kwargs):
        return {"sys": sys_view, "os": os_view, "pytest": pytest_view}.get(name) or import_real(name, *args, **kwargs)

    private_builtins = {**vars(builtins), "__import__": import_local}
    stub = tmp_path / "owned_cli.py"
    stub.write_text('import sys, os\nassert os.environ.get("_RAPTOR_TRUSTED") == "1"\nsys.path.insert(0, "owned-cli")\nloaded = True\n')
    error = KeyboardInterrupt if mode == "load_interrupt" else RuntimeError

    class Loader(SourceFileLoader):
        def __init__(self, name, _path):
            super().__init__(name, str(stub))

        def exec_module(self, module):
            module.__dict__["__builtins__"] = private_builtins
            super().exec_module(module)
            if mode != "normal":
                raise error("loader interrupted after effect")

    caller = ModuleType("caller_cli")
    saved_sdk = {"caller": ModuleType("caller_sdk")}
    borrowed_scope = ExitStack()
    namespace = {"__name__": "module_fixture", "__builtins__": private_builtins,
                 "_cli": caller, "_saved_sdk_modules": saved_sdk, "_SDK_MODULES": SDK_NAMES,
                 "_module_fixture_scope": borrowed_scope, "REPO_ROOT": ROOT,
                 "sys": sys_view, "os": os_view, "pytest": pytest_view,
                 "patch": patch, "SourceFileLoader": Loader, "importlib": importlib}
    _load_lifecycle(path, namespace)
    try:
        if mode == "normal":
            namespace["setUpModule"]()
            assert namespace["_cli"].loaded
            if "tearDownModule" in namespace:
                namespace["tearDownModule"]()
        else:
            with pytest.raises(error):
                namespace["setUpModule"]()
        assert namespace["_cli"] is caller
        assert namespace["_saved_sdk_modules"] is saved_sdk
        assert list(saved_sdk) == ["caller"]
        assert os_view.environ == env_before
        assert sys_view.path is path_before
        assert sys_view.path == path_contents
        for name, (present, value) in before_sdk.items():
            assert (name in sys_view.modules) == present, name
            if present:
                assert sys_view.modules[name] is value
        assert namespace["_module_fixture_scope"] is borrowed_scope
    finally:
        scope = namespace.get("_module_fixture_scope")
        if scope is not borrowed_scope:
            scope.close()
        borrowed_scope.close()


@pytest.mark.parametrize("mode", ["resume", "close", "interrupt", "allocate1", "allocate2", "allocate3"])
def test_cli_child_paths_restore_after_allocation_failure(monkeypatch, tmp_path_factory, tmp_path, mode):
    fields = {name: str(tmp_path / name) for name in ("_CHILD_TMPDIR", "_CHILD_HOME", "_CHILD_OUT_DIR")}
    namespace = {"__name__": "child_fixture", "pytest": pytest, **fields}
    _load_lifecycle("core/startup/tests/test_cli_smoke.py", namespace)
    mktemp = tmp_path_factory.mktemp
    calls = 0

    def allocate(*args, **kwargs):
        nonlocal calls
        path = mktemp(*args, **kwargs)
        calls += 1
        if mode == "allocate" + str(calls):
            raise RuntimeError("allocation interrupted")
        return path

    monkeypatch.setattr(tmp_path_factory, "mktemp", allocate)
    generator = namespace["_child_isolation"](tmp_path_factory)
    try:
        if mode.startswith("allocate"):
            with pytest.raises(RuntimeError):
                next(generator)
        else:
            next(generator)
            assert all(Path(namespace[name]).is_dir() for name in fields)
            if mode == "resume":
                with pytest.raises(StopIteration):
                    next(generator)
            elif mode == "interrupt":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                generator.close()
        for name, value in fields.items():
            assert namespace[name] is value
    finally:
        generator.close()


@pytest.mark.parametrize("fail_at", [1, 2])
@pytest.mark.parametrize("outer_scope", [False, True])
def test_module_scope_publication_failure_restores_namespace(fail_at, outer_scope):
    from contextlib import contextmanager
    from types import FunctionType
    from core.testing.module_scope import module_fixture_setup

    caller = ModuleType("caller_cli")
    namespace = {"_cli": caller}
    borrowed = ExitStack()
    if outer_scope:
        namespace["_module_fixture_scope"] = borrowed
    before = namespace.copy()
    calls = 0

    class FailingPatch(pytest.MonkeyPatch):
        def setitem(self, *args, **kwargs):
            nonlocal calls
            super().setitem(*args, **kwargs)
            calls += 1
            if calls == fail_at:
                raise RuntimeError("scope publication interrupted")

    pytest_view = _view(pytest)
    pytest_view.MonkeyPatch = FailingPatch
    original = module_fixture_setup.__wrapped__
    raw = FunctionType(original.__code__, {**original.__globals__, "pytest": pytest_view})
    with pytest.raises(RuntimeError, match="scope publication interrupted"):
        with contextmanager(raw)(namespace, ("_cli",)):
            pytest.fail("setup yielded after failed publication")
    assert namespace.keys() == before.keys()
    assert all(namespace[name] is value for name, value in before.items())
    borrowed.close()

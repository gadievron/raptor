"""Metadata fixture scopes preserve real module state and cached objects."""

import ast
from contextlib import contextmanager
from importlib import import_module
from inspect import isgenerator, signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest


CASES = [
    ("core/llm/tests/test_model_resolution.py", "_isolated_cache", "model", 3),
    (
        "core/llm/tests/test_methodology.py",
        "TestLoadMethodology._clear",
        "methodology",
        2,
    ),
    ("core/run/tests/test_toolprobe.py", "_clean_cache", "probe", 1),
    (
        "core/run/target_types/tests/test_target_types.py",
        "_reset_catalog_cache",
        "targets",
        1,
    ),
    (
        "packages/sca/parsers/tests/test_b10_workspaces.py",
        "_clear_catalog_cache",
        "workspace",
        1,
    ),
]
ROOT = Path(__file__).resolve().parents[3]
MODULES = {
    "model": "core.llm.model_resolution",
    "methodology": "core.llm.methodology",
    "probe": "core.run.toolprobe",
    "targets": "core.run.target_types",
    "workspace": "packages.sca.parsers._pnpm_catalog",
}


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


def _prepare(case, fail_at=None):
    path, fixture_name, kind, _ = case
    owner = _view(MODULES[kind])
    if kind == "model":
        owner._INVENTORY = ["caller-snapshot"]
        owner._INVENTORY_PROBED = True
        owner._LOGGED_RESOLUTIONS = {("caller-alias", "caller-snapshot")}
        owner._INVENTORY_LOCK = threading.Lock()
        fields = ("_INVENTORY", "_INVENTORY_PROBED", "_LOGGED_RESOLUTIONS")

        def reset():
            owner._INVENTORY = None
            owner._INVENTORY_PROBED = False
            owner._LOGGED_RESOLUTIONS.clear()
    elif kind == "methodology":
        owner._cache = {"caller.md": ("Caller body.", 1.0)}
        owner._raptor_dir = Path("/caller/root")
        fields = ("_cache", "_raptor_dir")

        def reset():
            owner._cache.clear()
            owner._raptor_dir = None
    elif kind == "probe":
        owner._CACHE = {("caller-tool", ("--version",)): None}
        owner._CACHE_LOCK = threading.Lock()
        fields = ("_CACHE",)

        def reset():
            owner._CACHE.clear()
    elif kind == "targets":
        owner._CACHED_CATALOG = (owner.CatalogEntry.from_dict({"name": "caller"}),)
        fields = ("_CACHED_CATALOG",)

        def reset():
            owner._CACHED_CATALOG = None
    else:
        owner._CATALOG_CACHE = {Path("/caller/root"): {"default": {"caller": "1.0"}}}
        fields = ("_CATALOG_CACHE",)

        def reset():
            owner._CATALOG_CACHE.clear()

    snapshot = {name: getattr(owner, name) for name in fields}
    contents = [
        (value, value.copy())
        for value in snapshot.values()
        if isinstance(value, (list, dict, set))
    ]
    steps = []

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            steps.append(None)
            if len(steps) == fail_at:
                raise RuntimeError("injected setup failure")

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "importlib":
            view = _view(name)

            def private_import(module_name):
                assert module_name == MODULES[kind]
                return owner

            view.import_module = private_import
            return view
        if name == "core.testing.module_state":
            original = import_module(name).isolated_module_state.__wrapped__
            pytest_view = _view("pytest")
            pytest_view.MonkeyPatch = Patch
            clone = FunctionType(
                original.__code__,
                dict(original.__globals__, pytest=pytest_view),
                original.__name__,
            )
            clone.__kwdefaults__ = original.__kwdefaults__
            view = ModuleType(name)
            view.isolated_module_state = contextmanager(clone)
            return view
        return __import__(name, globals, locals, fromlist, level)

    namespace = {
        "model_resolution": owner,
        "_reset_cache_for_tests": reset,
        "clear_cache": reset,
        "reset_probe_cache": reset,
        "_clear_cache": reset,
        "__builtins__": dict(vars(__import__("builtins")), __import__=fixture_import),
    }
    node = ast.parse((ROOT / path).read_text())
    for part in fixture_name.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[node.name], Patch, owner, snapshot, contents


def _start(function, patch):
    available = {"self": object(), "monkeypatch": patch}
    result = function(
        **{name: available[name] for name in signature(function).parameters}
    )
    if isgenerator(result):
        next(result)
        return result
    return None


def _finish(generator, mode):
    if generator is None:
        return
    try:
        if mode == "close":
            generator.close()
        elif mode == "throw":
            with pytest.raises(KeyboardInterrupt):
                generator.throw(KeyboardInterrupt)
        else:
            with pytest.raises(StopIteration):
                next(generator)
    finally:
        generator.close()


def _restored(owner, snapshot, contents):
    for name, value in snapshot.items():
        assert getattr(owner, name) is value
    for value, before in contents:
        assert value == before
        if isinstance(value, dict):
            for key, payload in before.items():
                assert value[key] is payload
    if "_CACHED_CATALOG" in snapshot:
        assert owner._CACHED_CATALOG[0] is snapshot["_CACHED_CATALOG"][0]


@pytest.mark.parametrize("case", CASES, ids=[c[2] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_metadata_fixture_restores_borrowed_state(case, mode):
    function, patch_type, owner, snapshot, contents = _prepare(case)
    patch = patch_type()
    generator = None
    try:
        generator = _start(function, patch)
        for name, original in snapshot.items():
            active = getattr(owner, name)
            assert active is not original
            if isinstance(original, (list, tuple, Path)):
                assert active is None
            elif isinstance(original, bool):
                assert active is False
            else:
                assert isinstance(active, type(original))
                assert not active
        if case[2] == "model":
            owner._INVENTORY = ["test-snapshot"]
            owner._INVENTORY_PROBED = True
            owner._LOGGED_RESOLUTIONS.add(("test-alias", "test-snapshot"))
        elif case[2] == "methodology":
            owner._cache["test.md"] = ("Test body.", 2.0)
            owner._raptor_dir = Path("/test/root")
        elif case[2] == "probe":
            owner._CACHE[("test-tool", ("--version",))] = None
        elif case[2] == "targets":
            owner._CACHED_CATALOG = (owner.CatalogEntry.from_dict({"name": "test"}),)
        else:
            owner._CATALOG_CACHE[Path("/test/root")] = {"default": {"test": "2.0"}}
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _restored(owner, snapshot, contents)


@pytest.mark.parametrize(
    "case,fail_at",
    [(case, step) for case in CASES for step in sorted({1, case[3]})],
    ids=[case[2] + "-" + str(step) for case in CASES for step in sorted({1, case[3]})],
)
def test_metadata_fixture_restores_partial_setup(case, fail_at):
    function, patch_type, owner, snapshot, contents = _prepare(case, fail_at)
    patch = patch_type()
    generator = None
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            generator = _start(function, patch)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    _restored(owner, snapshot, contents)

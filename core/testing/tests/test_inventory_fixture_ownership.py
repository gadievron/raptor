"""Private ownership of inventory caches, warning sets, and model LRUs."""

import ast
from builtins import __import__ as real_import
from collections import OrderedDict
from contextlib import contextmanager
from functools import lru_cache
from importlib import import_module
from inspect import isgenerator, signature
from pathlib import Path
from types import FunctionType, SimpleNamespace

import pytest


CASES = [
    ("core/analysis/tests/test_reach_verdict_log.py", "_isolated_sidecar", "reach", 3),
    ("core/concepts/tests/test_slice_memo.py", "_clean_caches", "slice", 3),
    ("core/inventory/tests/test_checklist_frame_mac.py", "_hermetic", "frame", 5),
    (
        "packages/exploitability_validation/tests/test_parent_checklist_pointer.py",
        "_hermetic_frame_key",
        "private_frame",
        5,
    ),
    ("core/inventory/tests/test_macro_resolve.py", "_clear_caches", "macro", 2),
    ("core/inventory/tests/test_header_functions.py", "_clear_cache", "header", 1),
]
ROOT = Path(__file__).resolve().parents[3]
WARNINGS = (
    "_warned_unstamped",
    "_warned_relocated",
    "_warned_key_paths",
    "_warned_absent_key",
)


class _Lock:
    held = False

    def __enter__(self):
        assert not self.held
        self.held = True

    def __exit__(self, *exc):
        self.held = False


class _Owner(SimpleNamespace):
    def __setattr__(self, name, value):
        if name in self.__dict__.get("guarded", ()):
            assert self.lock.held, "cache replacement must hold its lock"
        super().__setattr__(name, value)


def _prepare(case, fail_at=None):
    path, fixture_name, kind, _ = case
    reach = _Owner(_IN_MEMORY={"borrowed": object()}, lock=_Lock())
    reach._LOCK = reach.lock
    reach.guarded = ("_IN_MEMORY",)
    frame = _Owner(**{name: {"borrowed"} for name in WARNINGS})
    macro = _Owner(
        _table_cache=OrderedDict(borrowed=object()),
        _rust_table_cache=OrderedDict(borrowed=object()),
    )
    header = _Owner(_cache=OrderedDict(borrowed=object()), lock=_Lock())
    header._cache_lock = header.lock
    header.guarded = ("_cache",)
    model = _Owner(_slice_memos=OrderedDict(borrowed=object()), lock=_Lock())
    model._slice_memo_lock = model.lock
    model.guarded = ("_slice_memos", "_load_cached")

    @lru_cache(maxsize=3, typed=True)
    def cached(key):
        return (key,)

    cached("borrowed")
    model.__dict__["_load_cached"] = cached
    owners = {
        "reach": reach,
        "slice": model,
        "frame": frame,
        "private_frame": frame,
        "macro": macro,
        "header": header,
    }
    modules = {
        "core.inventory.checklist_frame_mac": frame,
        "core.inventory.macro_resolve": macro,
        "core.inventory.header_functions": header,
    }
    env = {
        "XDG_DATA_HOME": "borrowed-home",
        "RAPTOR_REACH_VERDICT_LOG": "borrowed-log",
        "RAPTOR_REACH_VERDICT_LOG_DISABLED": "1",
    }
    env_before = env.copy()
    steps = []

    class Patch(pytest.MonkeyPatch):
        def _after(self):
            steps.append(None)
            if len(steps) == fail_at:
                raise RuntimeError("injected setup failure")

        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            self._after()

        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            self._after()

        def setenv(self, name, value, prepend=None):
            assert prepend is None
            self.setitem(env, name, value)

        def delenv(self, name, raising=True):
            super().delitem(env, name, raising=raising)
            self._after()

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.inventory" and "checklist_frame_mac" in fromlist:
            return SimpleNamespace(checklist_frame_mac=frame)
        if name == "importlib":
            return SimpleNamespace(import_module=lambda name: modules[name])
        if name == "core.testing.module_state":
            helper = import_module(name).isolated_module_state.__wrapped__
            clone = FunctionType(
                helper.__code__,
                dict(helper.__globals__, pytest=SimpleNamespace(MonkeyPatch=Patch)),
                helper.__name__,
            )
            clone.__kwdefaults__ = helper.__kwdefaults__
            return SimpleNamespace(isolated_module_state=contextmanager(clone))
        return real_import(name, globals, locals, fromlist, level)

    alias = lru_cache(maxsize=2)(lambda key: key)
    alias("alias")
    namespace = {
        "reach_verdict_log": reach,
        "ab": model,
        "cm": frame,
        "pytest": SimpleNamespace(MonkeyPatch=Patch),
        "Path": Path,
        "_load_cached": alias,
        "_table_cache": macro._table_cache,
        "_rust_table_cache": macro._rust_table_cache,
        "_cache": header._cache,
    }
    namespace["__builtins__"] = dict(
        vars(__import__("builtins")), __import__=fixture_import
    )
    tree = ast.parse((ROOT / path).read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == fixture_name
    )
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    snapshots = {
        name: value
        for name, value in vars(owners[kind]).items()
        if name.startswith("_")
    }
    containers = [
        (value, value.copy())
        for value in snapshots.values()
        if isinstance(value, (dict, set))
    ]
    return (
        namespace[fixture_name],
        Patch,
        namespace,
        owners[kind],
        snapshots,
        containers,
        env,
        env_before,
        cached,
        alias,
    )


def _start(function, patch, tmp_path):
    available = {"monkeypatch": patch, "tmp_path": tmp_path}
    result = function(
        **{name: available[name] for name in signature(function).parameters}
    )
    if isgenerator(result):
        return result, next(result)
    return None, result


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


def _restored(
    owner, snapshots, containers, env, env_before, cached, alias, infos, namespace
):
    for name, value in snapshots.items():
        assert getattr(owner, name) is value
    for value, before in containers:
        assert value == before
    assert env == env_before
    assert cached.cache_info() == infos[0]
    assert alias.cache_info() == infos[1]
    assert namespace["_load_cached"] is alias


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_inventory_fixture_preserves_borrowed_state(case, mode, tmp_path):
    (
        function,
        patch_type,
        namespace,
        owner,
        snapshots,
        containers,
        env,
        before,
        cached,
        alias,
    ) = _prepare(case)
    infos = cached.cache_info(), alias.cache_info()
    patch = patch_type()
    generator = None
    try:
        generator, value = _start(function, patch, tmp_path)
        for name, original in snapshots.items():
            if isinstance(original, (dict, set)):
                active = getattr(owner, name)
                assert type(active) is type(original)
                assert active is not original
                assert not active
                if isinstance(active, set):
                    active.add("local")
                else:
                    active["local"] = object()
        if case[2] == "slice":
            assert namespace["_load_cached"] is owner._load_cached
            assert owner._load_cached is not cached
            assert owner._load_cached.cache_parameters() == cached.cache_parameters()
            assert owner._load_cached("local") == ("local",)
        if case[2] == "reach":
            assert value == tmp_path / "reach_verdict_log.json"
        if case[2] == "private_frame":
            patch.undo()  # Must not undo the fixture's private key scope.
            assert env["XDG_DATA_HOME"] == str(tmp_path / "xdg")
        for borrowed, contents in containers:
            assert borrowed == contents
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _restored(
        owner, snapshots, containers, env, before, cached, alias, infos, namespace
    )


@pytest.mark.parametrize(
    "case,fail_at", [(case, step) for case in CASES for step in sorted({1, case[3]})]
)
def test_inventory_fixture_unwinds_partial_setup(case, fail_at, tmp_path):
    (
        function,
        patch_type,
        namespace,
        owner,
        snapshots,
        containers,
        env,
        before,
        cached,
        alias,
    ) = _prepare(case, fail_at)
    infos = cached.cache_info(), alias.cache_info()
    patch = patch_type()
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            _start(function, patch, tmp_path)
    finally:
        patch.undo()
    _restored(
        owner, snapshots, containers, env, before, cached, alias, infos, namespace
    )

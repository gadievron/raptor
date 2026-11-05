"""Native source-cache fixtures must preserve borrowed state and locks."""

from builtins import __import__ as real_import
from contextlib import contextmanager
from functools import lru_cache
from importlib import import_module
from inspect import isgenerator, signature
from types import FunctionType, SimpleNamespace

import pytest


CASES = [
    ("packages.source_intel.tests.test_cache_invalidation", "_reset_caches", "all", 11),
    ("packages.source_intel.tests.test_signature_memo", "_reset", "inventory", 3),
    (
        "packages.source_intel.tests.test_conditional",
        "_clear_cache_between_tests",
        "conditional",
        1,
    ),
    ("packages.llm_analysis.tests.test_source_intel_inject", "_reset", "injection", 3),
    ("packages.llm_analysis.tests.test_flow_context_inject", "_reset", "flow", 1),
    ("packages.llm_analysis.tests.test_orchestrator", "_clear_prep_caches", "prep", 4),
]


class _Lock:
    def __init__(self):
        self.held = False

    def __enter__(self):
        assert not self.held
        self.held = True

    def __exit__(self, *exc):
        self.held = False


class _Module(SimpleNamespace):
    def __setattr__(self, name, value):
        lock = self.__dict__.get("guards", {}).get(name)
        if lock is not None:
            assert lock.held, "cache replacement and restoration require its lock"
        super().__setattr__(name, value)


def _prepare(case, fail_at=None):
    inventory_lock, result_lock, signature_lock, flow_lock = (_Lock() for _ in range(4))
    inventory = _Module(
        _INVENTORY_BY_TARGET={"borrowed": object()},
        _SIG_MEMO={"borrowed": object()},
        _SIG_MEMO_DEPTH=7,
        _INVENTORY_LOCK=inventory_lock,
    )
    inventory.guards = {
        name: inventory_lock
        for name in ("_INVENTORY_BY_TARGET", "_SIG_MEMO", "_SIG_MEMO_DEPTH")
    }
    keys = _Module(
        _TREE_HASH_MEMO={"borrowed": object()}, _RULES_HASH_MEMO={"borrowed": object()}
    )
    adapter = _Module(
        _PREREQS_MEMO={"borrowed": object()}, _POINTER_REF_MEMO={"borrowed": object()}
    )
    injection = _Module(
        _SI_RESULT_CACHE={"borrowed": object()},
        _SI_FLAGS_CACHE={"borrowed": object()},
        _SIG_MEMO={"borrowed": object()},
        _SI_LOCK=result_lock,
        _SIG_MEMO_LOCK=signature_lock,
    )
    injection.guards = {
        "_SI_RESULT_CACHE": result_lock,
        "_SI_FLAGS_CACHE": result_lock,
        "_SIG_MEMO": signature_lock,
    }
    flow = _Module(_FC_CACHE={"borrowed": object()}, _FC_LOCK=flow_lock)
    flow.guards = {"_FC_CACHE": flow_lock}

    @lru_cache(maxsize=3, typed=True)
    def cached(path, mtime, size):
        return path, mtime, size

    cached("borrowed", 1, 2)
    conditional = _Module(_index_file_stat=cached)
    modules = {
        "packages.source_intel.analyze": inventory,
        "packages.source_intel.cache": keys,
        "packages.source_intel.adapter": adapter,
        "packages.llm_analysis.source_intel_inject": injection,
        "packages.llm_analysis.flow_context_inject": flow,
        "packages.source_intel.conditional": conditional,
    }

    def clear_inventory():
        with inventory_lock:
            inventory._INVENTORY_BY_TARGET.clear()
            inventory._SIG_MEMO.clear()

    def clear_injection():
        with result_lock:
            injection._SI_RESULT_CACHE.clear()
            injection._SI_FLAGS_CACHE.clear()

    def clear_flow():
        with flow_lock:
            flow._FC_CACHE.clear()

    def clear_all():
        clear_inventory()
        for owner in (keys, adapter):
            for value in vars(owner).values():
                value.clear()
        clear_injection()

    injection.clear_si_result_cache = clear_injection
    flow.clear_flow_context_cache = clear_flow
    module_name, fixture_name, kind, _ = case
    original = getattr(import_module(module_name), fixture_name).__wrapped__
    namespace = dict(original.__globals__)
    alias = {"alias": object()}
    namespace.update(
        clear_inventory_cache=clear_inventory,
        clear_all_source_intel_caches=clear_all,
        clear_cache_for_tests=clear_injection,
        clear_flow_context_cache=clear_flow,
        clear_cache=cached.cache_clear,
        _INVENTORY_BY_TARGET=alias,
    )
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

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "importlib":
            return SimpleNamespace(import_module=lambda name: modules[name])
        if name in modules:
            return modules[name]
        if name == "core.testing.module_state":
            helper = import_module(name).isolated_module_state.__wrapped__
            helper_globals = dict(
                helper.__globals__, pytest=SimpleNamespace(MonkeyPatch=Patch)
            )
            clone = FunctionType(
                helper.__code__, helper_globals, helper.__name__, helper.__defaults__
            )
            clone.__kwdefaults__ = helper.__kwdefaults__
            return SimpleNamespace(isolated_module_state=contextmanager(clone))
        return real_import(name, globals, locals, fromlist, level)

    namespace["__builtins__"] = dict(
        vars(__import__("builtins")), __import__=fixture_import
    )
    function = FunctionType(
        original.__code__, namespace, original.__name__, original.__defaults__
    )
    snapshots = [
        (
            owner,
            {
                name: value
                for name, value in vars(owner).items()
                if name.startswith("_") and not name.endswith("LOCK")
            },
        )
        for owner in modules.values()
    ]
    # Locks aren't replaced; dictionary snapshots pin identity and contents.
    contents = [
        (value, value.copy())
        for _, fields in snapshots
        for value in fields.values()
        if isinstance(value, dict)
    ]
    contents.append((alias, alias.copy()))
    return function, Patch, namespace, modules, snapshots, contents, cached, alias


def _start(function, patch):
    result = function(
        **(
            {"monkeypatch": patch}
            if "monkeypatch" in signature(function).parameters
            else {}
        )
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


def _assert_restored(namespace, snapshots, contents, cached, cache_info, alias):
    for owner, fields in snapshots:
        for name, value in fields.items():
            assert getattr(owner, name) is value
    for value, original in contents:
        assert value == original
    assert cached.cache_info() == cache_info
    assert namespace["_INVENTORY_BY_TARGET"] is alias


@pytest.mark.parametrize("case", CASES)
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_native_source_cache_fixture_owns_its_state(case, mode):
    function, patch_type, namespace, modules, snapshots, contents, cached, alias = (
        _prepare(case)
    )
    cache_info = cached.cache_info()
    patch = patch_type()
    generator = None
    try:
        generator = _start(function, patch)
        kind = case[2]
        active_owners = {
            "all": list(modules.values())[:4],
            "inventory": [modules["packages.source_intel.analyze"]],
            "injection": [modules["packages.llm_analysis.source_intel_inject"]],
            "flow": [modules["packages.llm_analysis.flow_context_inject"]],
            "prep": [
                modules["packages.llm_analysis.source_intel_inject"],
                modules["packages.llm_analysis.flow_context_inject"],
            ],
            "conditional": [],
        }[kind]
        for owner in active_owners:
            before = next(fields for original, fields in snapshots if original is owner)
            for name, value in before.items():
                if isinstance(value, dict):
                    active = getattr(owner, name)
                    assert active is not value
                    assert active == {}
                    active["local"] = object()
            if owner is modules["packages.source_intel.analyze"]:
                assert owner._SIG_MEMO_DEPTH == 0
        if kind == "all":
            assert (
                namespace["_INVENTORY_BY_TARGET"]
                is modules["packages.source_intel.analyze"]._INVENTORY_BY_TARGET
            )
        if kind == "conditional":
            active = modules["packages.source_intel.conditional"]._index_file_stat
            assert active is not cached
            assert active.cache_parameters() == cached.cache_parameters()
            assert active.cache_info().currsize == 0
            assert active("local", 1, 2) == ("local", 1, 2)
        for value, original in contents:
            assert value == original
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _assert_restored(namespace, snapshots, contents, cached, cache_info, alias)


@pytest.mark.parametrize(
    "case,fail_at", [(case, step) for case in CASES for step in sorted({1, case[3]})]
)
def test_source_cache_fixture_unwinds_partial_setup(case, fail_at):
    function, patch_type, namespace, _, snapshots, contents, cached, alias = _prepare(
        case, fail_at
    )
    cache_info = cached.cache_info()
    patch = patch_type()
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            _start(function, patch)
    finally:
        patch.undo()
    _assert_restored(namespace, snapshots, contents, cached, cache_info, alias)

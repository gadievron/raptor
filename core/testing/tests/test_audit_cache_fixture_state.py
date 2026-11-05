"""Audit cache fixtures preserve borrowed dictionaries and bounded memos."""

import ast
from contextlib import contextmanager
from importlib import import_module
from inspect import isgenerator, signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest

from core.audit.run_memo import BoundedMemo


CASES = [
    ("core/audit/tests/test_compiler_tu_cache.py", "_fresh_caches", "compiler", 3),
    ("core/audit/tests/test_compile_probe.py", "_toolchain", "toolchain", 2),
    ("core/audit/tests/test_codeql_sweep_memo.py", "_fresh_memo", "codeql", 1),
    (
        "core/audit/tests/test_substrate_vocabulary.py",
        "_fresh_codeql_memo",
        "codeql",
        1,
    ),
    ("core/audit/tests/test_substrate.py", "_fresh_caches", "substrate", 2),
    ("core/audit/tests/test_substrate_coccinelle.py", "_fresh_caches", "substrate", 2),
]
ROOT = Path(__file__).resolve().parents[3]


def _module_view(name):
    original = import_module(name)
    view = ModuleType(name)
    view.__dict__.update(vars(original))
    return view


def _prepare(case, fail_at=None):
    path, fixture_name, kind, _ = case
    if kind == "compiler":
        owner = _module_view("core.audit.compiler_sweep")
        owner._PROBE_LOCK = threading.Lock()
        owner._PROBE_CACHE = {"borrowed": False}
        owner._TU_CACHE_MAX_ENTRIES = 3
        owner._tu_cache = BoundedMemo(3)
        owner._include_dirs_memo = BoundedMemo(3)
        owner._tu_cache.get_or_compute("borrowed", lambda: {})
        owner._include_dirs_memo.get_or_compute("borrowed", lambda: [])
        fields = ("_PROBE_CACHE", "_tu_cache", "_include_dirs_memo")
    elif kind == "toolchain":
        owner = _module_view("core.audit.compile_probe")
        owner._TOOLCHAIN_LOCK = threading.Lock()
        owner._TOOLCHAIN_CACHE = {"c": None}
        fields = ("_TOOLCHAIN_CACHE", "_find_toolchain")
    elif kind == "codeql":
        owner = _module_view("core.audit.sweep")
        owner._CODEQL_MEMO_MAX_ENTRIES = 3
        owner._codeql_memo = BoundedMemo(3)
        owner._codeql_memo.get_or_compute("borrowed", lambda: [])
        fields = ("_codeql_memo",)
    else:
        owner = _module_view("core.audit.substrate")
        owner._LANG_LOCK = threading.Lock()
        owner._TREE_LOCK = threading.Lock()
        owner._LANG_CACHE = {("borrowed", "file.c"): "c"}
        owner._TREE_CACHE = {(1, 2): ([], frozenset({"c"}))}
        fields = ("_LANG_CACHE", "_TREE_CACHE")
    snapshot = {name: getattr(owner, name) for name in fields}
    dictionaries = [
        (value, value.copy()) for value in snapshot.values() if isinstance(value, dict)
    ]
    memos = [
        (value, value.peek("borrowed", touch=False), value.hit_count, value.miss_count)
        for value in snapshot.values()
        if isinstance(value, BoundedMemo)
    ]
    steps = []

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            steps.append(None)
            if len(steps) == fail_at:
                raise RuntimeError("injected setup failure")

    def reset_compiler():
        owner._PROBE_CACHE.clear()

    def reset_tu():
        owner._tu_cache.clear()
        owner._include_dirs_memo.clear()

    def reset_substrate():
        owner._LANG_CACHE.clear()
        owner._TREE_CACHE.clear()

    if kind == "compiler":
        owner._reset_probe_cache = reset_compiler
        owner._reset_tu_cache = reset_tu
    elif kind == "toolchain":
        owner._reset_toolchain_cache = lambda: owner._TOOLCHAIN_CACHE.clear()
    elif kind == "codeql":
        owner._reset_codeql_memo = owner._codeql_memo.clear
    else:
        owner._reset_substrate_caches = reset_substrate

    def fixture_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.audit" and "substrate" in fromlist:
            view = _module_view(name)
            view.substrate = owner
            return view
        if name == "importlib":
            view = _module_view(name)
            view.import_module = lambda key: owner
            return view
        if name == "core.testing.module_state":
            original = import_module(name).isolated_module_state.__wrapped__
            pytest_view = ModuleType("private_pytest")
            pytest_view.__dict__.update(vars(pytest))
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
        "compiler_sweep": owner,
        "cp": owner,
        "sweep_mod": owner,
        "_reset_substrate_caches": reset_substrate,
        "__builtins__": dict(vars(__import__("builtins")), __import__=fixture_import),
    }
    tree = ast.parse((ROOT / path).read_text())
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == fixture_name
    )
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    return namespace[fixture_name], Patch, owner, snapshot, dictionaries, memos


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


def _restored(owner, snapshot, dictionaries, memos):
    for name, value in snapshot.items():
        assert getattr(owner, name) is value
    for borrowed, contents in dictionaries:
        assert borrowed == contents
        for key, value in contents.items():
            assert borrowed[key] is value
    for memo, contents, hits, misses in memos:
        after = memo.peek("borrowed", touch=False)
        assert after == contents
        assert after[0] is contents[0]
        assert memo.hit_count == hits
        assert memo.miss_count == misses


@pytest.mark.parametrize("case", CASES, ids=[Path(c[0]).stem for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_audit_cache_fixture_preserves_inherited_state(case, mode):
    function, patch_type, owner, snapshot, dictionaries, memos = _prepare(case)
    patch = patch_type()
    generator = None
    try:
        generator = _start(function, patch)
        for name, original in snapshot.items():
            active = getattr(owner, name)
            assert active is not original
            if isinstance(original, dict):
                assert active == {}
                if name == "_LANG_CACHE":
                    active[("local", "file.c")] = None
                elif name == "_TREE_CACHE":
                    active[(3, 4)] = ([], frozenset())
                else:
                    active["c++"] = None
            elif isinstance(original, BoundedMemo):
                assert isinstance(active, BoundedMemo)
                assert active._max_entries == original._max_entries
                assert len(active) == 0
                assert active.hit_count == active.miss_count == 0
                value = {} if name == "_tu_cache" else []
                active.get_or_compute("local", lambda: value)
        if case[2] == "toolchain":
            assert owner._find_toolchain("c") == ("/usr/bin/cc", "cc (test) 13.2.0")
    finally:
        try:
            _finish(generator, mode)
        finally:
            patch.undo()
    _restored(owner, snapshot, dictionaries, memos)


@pytest.mark.parametrize(
    "case,fail_at",
    [(case, step) for case in CASES for step in sorted({1, case[3]})],
    ids=[
        Path(case[0]).stem + "-" + str(step)
        for case in CASES
        for step in sorted({1, case[3]})
    ],
)
def test_audit_cache_fixture_restores_partial_setup(case, fail_at):
    function, patch_type, owner, snapshot, dictionaries, memos = _prepare(case, fail_at)
    patch = patch_type()
    generator = None
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            generator = _start(function, patch)
    finally:
        if generator is not None:
            generator.close()
        patch.undo()
    _restored(owner, snapshot, dictionaries, memos)

"""Audit collection and fixture scopes preserve borrowed caches and budgets."""

import ast
from contextlib import contextmanager
from importlib import import_module
from inspect import signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest

from core.audit.run_memo import BoundedMemo


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("test_preprocessor_view.py", "_fresh_probe_cache", "cpp", 1),
    ("test_expanded_semgrep.py", "_fresh_probe_cache", "cpp", 1),
    ("test_sweep_expanded.py", "_fresh_state", "budget", 2),
    ("test_cocci_file_scope_memo.py", "_fresh_caches", "substrate", 2),
    ("test_live_transport_guards.py", "TestCompilerMintedIdentities._fresh_compiler_caches", "compiler", 3),
    ("test_live_transport_guards.py", "TestCppMintedIdentities._fresh_cpp_probe_cache", "cpp", 1),
]


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


def _prepare(case, fail_at=None):
    _, _, kind, _ = case
    pv = _view("core.audit.preprocessor_view")
    pv._PROBE_LOCK = threading.Lock()
    pv._PROBE_CACHE = {"c": ["/caller/gcc", "-E", "-x", "c"]}
    es = _view("core.audit.expanded_semgrep")
    es._PROCESS_BUDGET = es.ExpansionBudget(3)
    es._PROCESS_BUDGET.used = 1
    es._PROCESS_BUDGET._views[("/caller", "main.c")] = pv.ExpandedView(
        ok=True, file_path="main.c", text="int x;", line_map=(("main.c", 1),),
    )
    substrate = _view("core.audit.substrate")
    substrate._LANG_LOCK = threading.Lock()
    substrate._TREE_LOCK = threading.Lock()
    substrate._LANG_CACHE = {("/caller", "main.c"): "c"}
    substrate._TREE_CACHE = {(1, 2): ([], frozenset({"c"}))}
    cs = _view("core.audit.compiler_sweep")
    cs._PROBE_LOCK = threading.Lock()
    cs._PROBE_CACHE = {"gcc": ("/caller/gcc", "json"), "clang": None}
    cs._tu_cache = BoundedMemo(cs._TU_CACHE_MAX_ENTRIES)
    cs._include_dirs_memo = BoundedMemo(cs._TU_CACHE_MAX_ENTRIES)
    cs._tu_cache.get_or_compute("caller", lambda: {})
    cs._include_dirs_memo.get_or_compute("caller", lambda: ["/caller/include"])
    for memo in (cs._tu_cache, cs._include_dirs_memo):
        memo.get_or_compute("caller", lambda: pytest.fail("warm memo missed"))
    owners = [(pv, ("_PROBE_CACHE", "_PROBE_LOCK"))]
    if kind == "budget":
        owners.append((es, ("_PROCESS_BUDGET",)))
    elif kind == "substrate":
        owners = [(substrate, ("_LANG_CACHE", "_TREE_CACHE", "_LANG_LOCK", "_TREE_LOCK"))]
    elif kind == "compiler":
        owners = [(cs, ("_PROBE_CACHE", "_tu_cache", "_include_dirs_memo", "_PROBE_LOCK"))]
    snapshot = [(owner, {name: getattr(owner, name) for name in fields}) for owner, fields in owners]
    dictionaries = [(value, value.copy()) for _, fields in snapshot for value in fields.values() if isinstance(value, dict)]
    memos = [(memo, memo.peek("caller", touch=False)[0], memo.hit_count, memo.miss_count)
             for memo in (cs._tu_cache, cs._include_dirs_memo)] if kind == "compiler" else []
    budget = es._PROCESS_BUDGET
    budget_views = budget._views.copy()
    calls = 0

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            nonlocal calls
            super().setattr(*args, **kwargs)
            calls += 1
            if calls == fail_at:
                raise RuntimeError("injected setup failure")

    # Bind the real reset implementations to private module globals as well.
    for owner, names in [(pv, ("_reset_probe_cache",)), (es, ("_reset_process_budget",)),
                         (cs, ("_reset_probe_cache", "_reset_tu_cache")),
                         (substrate, ("_reset_substrate_caches",))]:
        for name in names:
            raw = getattr(owner, name)
            clone = FunctionType(raw.__code__, owner.__dict__, name, raw.__defaults__)
            clone.__kwdefaults__ = raw.__kwdefaults__
            setattr(owner, name, clone)
    helper = _view("core.testing.module_state")
    raw = helper.isolated_module_state.__wrapped__
    pytest_view = _view("pytest")
    pytest_view.MonkeyPatch = Patch
    clone = FunctionType(raw.__code__, dict(raw.__globals__, pytest=pytest_view))
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper.isolated_module_state = contextmanager(clone)
    audit_view = _view("core.audit")
    audit_view.compiler_sweep = cs
    audit_view.substrate = substrate

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name == "core.audit":
            return audit_view
        return __import__(name, globals, locals, fromlist, level)

    namespace = {"pv": pv, "es": es, "_reset_substrate_caches": substrate._reset_substrate_caches,
                 "isolated_module_state": helper.isolated_module_state,
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for owner, fields in snapshot:
            for name, value in fields.items():
                assert getattr(owner, name) is value
        for value, before in dictionaries:
            assert value == before
            for key, payload in before.items():
                assert value[key] is payload
        for memo, payload, hits, misses in memos:
            value, present = memo.peek("caller", touch=False)
            assert present
            assert value is payload
            assert memo.hit_count == hits
            assert memo.miss_count == misses
        assert budget.used == 1
        assert budget.max_expansions == 3
        assert budget._views == budget_views
        for key, payload in budget_views.items():
            assert budget._views[key] is payload

    return namespace, snapshot, restored


def _fixture(case, namespace):
    path, name, _, _ = case
    node = ast.parse((ROOT / "core/audit/tests" / path).read_text())
    for part in name.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[node.name]
    return function(**({"self": object()} if "self" in signature(function).parameters else {}))


@pytest.mark.parametrize("case", CASES, ids=[c[0] + ":" + c[1] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_audit_fixture_preserves_borrowed_state(case, mode):
    namespace, snapshot, restored = _prepare(case)
    generator = _fixture(case, namespace)
    try:
        next(generator)
        for owner, fields in snapshot:
            for name, borrowed in fields.items():
                active = getattr(owner, name)
                if name.endswith("LOCK"):
                    assert active is borrowed
                    continue
                assert active is not borrowed
                assert isinstance(active, type(borrowed))
                if isinstance(active, dict):
                    assert not active
                    active["owned"] = None
                elif isinstance(active, BoundedMemo):
                    assert active._max_entries == borrowed._max_entries
                    assert active.hit_count == active.miss_count == 0
                    active.get_or_compute("owned", lambda: {})
                else:
                    assert active.used == 0
                    assert not active._views
                    active.used = 1
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
    restored()


FAULTS = [(case, step) for case in CASES for step in sorted({1, case[3]})]


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[0] + ":" + c[1] + ":" + str(step) for c, step in FAULTS])
def test_audit_fixture_restores_partial_setup(case, fail_at):
    namespace, _, restored = _prepare(case, fail_at)
    generator = _fixture(case, namespace)
    try:
        with pytest.raises(RuntimeError, match="injected setup failure"):
            next(generator)
    finally:
        generator.close()
    restored()


@pytest.mark.parametrize("case", CASES[:3], ids=[c[0] for c in CASES[:3]])
@pytest.mark.parametrize("probe_raises", [False, True])
def test_collection_probe_preserves_borrowed_cache(case, probe_raises):
    namespace, _, restored = _prepare(case)
    pv = namespace["pv"]
    calls = []

    def probe(is_cxx):
        calls.append(is_cxx)
        assert pv._PROBE_CACHE == {}
        pv._PROBE_CACHE["c"] = ["/owned/cpp", "-E"]
        if probe_raises:
            raise RuntimeError("injected probe failure")
        return pv._PROBE_CACHE["c"]

    pv._preprocessor_for = probe
    tree = ast.parse((ROOT / "core/audit/tests" / case[0]).read_text())
    nodes = [n for n in tree.body if isinstance(n, ast.With) and any(
        isinstance(x, ast.Name) and x.id == "HAVE_CPP" for x in ast.walk(n)
    )]
    if not nodes:
        nodes = [n for n in tree.body if (
            isinstance(n, ast.Assign) and any(isinstance(x, ast.Name) and x.id == "HAVE_CPP" for x in n.targets)
        ) or (isinstance(n, ast.Expr) and isinstance(n.value, ast.Call) and ast.unparse(n.value.func) == "pv._reset_probe_cache")]
    assert nodes
    code = compile(ast.Module(body=nodes, type_ignores=[]), case[0], "exec")
    if probe_raises:
        with pytest.raises(RuntimeError, match="injected probe failure"):
            exec(code, namespace)
    else:
        exec(code, namespace)
        assert namespace["HAVE_CPP"] is True
    assert calls == [False]
    restored()

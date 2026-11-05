"""Audit metadata fixture scopes preserve caller objects and checkpoint bytes."""

import ast
from collections import OrderedDict
from contextlib import contextmanager
from importlib import import_module
from inspect import signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("test_return_domain.py", "_fresh_caches", "domain", 2),
    ("test_return_domain_lazy_depth.py", "clear_return_domain_caches", "domain", 2),
    ("test_constant_resolution.py", "_clear_cache", "constants", 1),
    ("test_codeql_query_resolver.py", "_fresh_caches", "resolver-warning", 3),
    ("test_cwe_dispatch_codeql_ids.py", "_fresh_resolver_cache", "resolver", 2),
    ("test_git_oracle.py", "_fresh_cache", "git", 1),
    ("test_sweep_checkpoint.py", "_fresh_registry", "checkpoint", 2),
]


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


def _checkpoint(owner, tmp_path):
    """Warm a real checkpoint, with its key and journal wholly under tmp_path."""
    from core.audit import sweep_checkpoint
    from core.audit.sweep import SweepResult
    from core.audit.sweep_memo import SweepMemo

    run_dir = tmp_path / "caller-run"
    run_dir.mkdir()
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(sweep_checkpoint, "_mac_key_path", lambda: tmp_path / "mac.key")
        writer = owner.SweepCheckpoint(run_dir)
        key = SweepMemo.make_key("coccinelle", {"rule": "caller", "file": "main.c"})
        assert key is not None
        writer.record(key, SweepResult(tool="coccinelle", file_path="main.c",
                                      function_name="", outcome="refuted"))
        checkpoint = owner.SweepCheckpoint(run_dir)
    assert checkpoint._loaded
    trail = run_dir / owner.CHECKPOINT_FILENAME
    return checkpoint, trail


def _prepare(case, tmp_path, fail_at=None):
    _, _, kind, _ = case
    if kind == "domain":
        owner = _view("core.audit.return_domain")
        owner._DOMAIN_CACHE_LOCK = threading.RLock()
        owner._DOMAIN_CACHE = {("callee", ("main.c",)): owner.ReturnDomain("callee", {0, 1}),
                               ("missing", ("main.c",)): None}
        owner._CONSTANTS_CACHE = {"/caller": {"CAP": 7}}
        fields = ("_DOMAIN_CACHE", "_CONSTANTS_CACHE", "_DOMAIN_CACHE_LOCK")
        alias, reset = "rd", "clear_cache"
    elif kind == "constants":
        owner = _view("core.audit.constant_resolution")
        table = owner.ConstantTable(unique={"CAP": owner.ResolvedConstant("CAP", 7, "main.h", 1)})
        owner._cache = OrderedDict([("/caller", table)])
        fields = ("_cache",)
        alias, reset = "cr", "clear_cache"
    elif kind.startswith("resolver"):
        owner = _view("core.audit.codeql_query_resolver")
        owner._CACHE_LOCK = threading.Lock()
        owner._PACK_INDEX_CACHE = {"codeql/cpp-queries": {"cpp/caller": str(tmp_path / "Caller.ql")},
                                   "codeql/missing-queries": None}
        owner._PACK_LOCKS = {"codeql/cpp-queries": threading.Lock()}
        fields = ("_PACK_INDEX_CACHE", "_PACK_LOCKS", "_CACHE_LOCK")
        alias, reset = "resolver", "clear_cache"
    elif kind == "git":
        owner = _view("core.audit.git_oracle")
        owner._CACHE_LOCK = threading.Lock()
        owner._FILE_CACHE = {("/caller", "main.c", 25): [owner.CorroborationRecord(
            sha="a" * 40, subject="caller commit", date="2026-01-01T00:00:00Z", files=("main.c",),
        )]}
        fields = ("_FILE_CACHE", "_CACHE_LOCK")
        alias, reset = "git_oracle", "_reset_cache"
    else:
        owner = _view("core.audit.sweep_checkpoint")
        owner._registry_lock = threading.Lock()
        checkpoint, trail = _checkpoint(owner, tmp_path)
        owner._registry = {str(trail.parent): checkpoint, str(tmp_path / "disabled"): None}
        owner._key_warned = {str(tmp_path / "caller-key")}
        fields = ("_registry", "_key_warned", "_registry_lock")
        alias, reset = "sc", "reset_checkpoint_registry"
    snapshot = [(owner, {name: getattr(owner, name) for name in fields})]
    orch = _view("core.audit.orchestrator")
    orch._CODEQL_UNSUPPORTED_IDS_LOGGED = {"cpp/caller"}
    if kind == "resolver-warning":
        snapshot.append((orch, {"_CODEQL_UNSUPPORTED_IDS_LOGGED": orch._CODEQL_UNSUPPORTED_IDS_LOGGED}))
    dictionaries = [(value, value.copy()) for _, values in snapshot for value in values.values() if isinstance(value, dict)]
    sets = [(value, value.copy()) for _, values in snapshot for value in values.values() if isinstance(value, set)]
    if kind == "checkpoint":
        checkpoint_fields = vars(checkpoint).copy()
        checkpoint_loaded = checkpoint._loaded.copy()
        checkpoint_persisted = checkpoint._persisted.copy()
        trail_before = trail.read_bytes()
    raw = getattr(owner, reset)
    private_reset = FunctionType(raw.__code__, owner.__dict__, reset, raw.__defaults__)
    private_reset.__kwdefaults__ = raw.__kwdefaults__
    setattr(owner, reset, private_reset)
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
    audit = _view("core.audit")
    setattr(audit, owner.__name__.rsplit(".", 1)[-1], owner)

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name == "core.audit":
            return audit
        return __import__(name, globals, locals, fromlist, level)

    namespace = {alias: owner, "orch": orch, reset: private_reset,
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for module, values in snapshot:
            for name, value in values.items():
                assert getattr(module, name) is value
        for value, before in dictionaries:
            assert value == before
            if isinstance(value, OrderedDict):
                assert list(value) == list(before)
            for key, payload in before.items():
                assert value[key] is payload
        for value, before in sets:
            assert value == before
        if kind == "checkpoint":
            for name, value in checkpoint_fields.items():
                assert getattr(checkpoint, name) is value
            assert checkpoint._loaded == checkpoint_loaded
            for key, payload in checkpoint_loaded.items():
                assert checkpoint._loaded[key] is payload
            assert checkpoint._persisted == checkpoint_persisted
            assert trail.read_bytes() == trail_before

    return namespace, Patch, snapshot, restored


def _start(case, namespace, patch):
    path, name, _, _ = case
    node = next(n for n in ast.parse((ROOT / "core/audit/tests" / path).read_text()).body
                if isinstance(n, ast.FunctionDef) and n.name == name)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[name]
    generator = function(**({"monkeypatch": patch} if "monkeypatch" in signature(function).parameters else {}))
    next(generator)
    return generator


@pytest.mark.parametrize("case", CASES, ids=[c[0] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_audit_metadata_fixture_preserves_caller_state(case, mode, tmp_path):
    namespace, patch_type, snapshot, restored = _prepare(case, tmp_path)
    generator = None
    try:
        with patch_type.context() as patch:
            generator = _start(case, namespace, patch)
            for owner, values in snapshot:
                for name, borrowed in values.items():
                    active = getattr(owner, name)
                    if name.lower().endswith("lock"):
                        assert active is borrowed
                        continue
                    assert active is not borrowed
                    assert isinstance(active, type(borrowed))
                    assert not active
                    if isinstance(active, set):
                        active.add("owned")
                    elif name == "_PACK_LOCKS":
                        active["codeql/owned-queries"] = threading.Lock()
                    else:
                        active["owned"] = None
            if mode == "close":
                generator.close()
            elif mode == "throw":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                with pytest.raises(StopIteration):
                    next(generator)
    finally:
        if generator is not None:
            generator.close()
    restored()


FAULTS = [(case, step) for case in CASES for step in sorted({1, case[3]})]


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[0] + ":" + str(step) for c, step in FAULTS])
def test_audit_metadata_fixture_restores_partial_setup(case, fail_at, tmp_path):
    namespace, patch_type, _, restored = _prepare(case, tmp_path, fail_at)
    generator = None
    try:
        with patch_type.context() as patch:
            with pytest.raises(RuntimeError, match="injected setup failure"):
                generator = _start(case, namespace, patch)
    finally:
        if generator is not None:
            generator.close()
    restored()

"""Discovery fixture scopes retain warmed caller caches and coordination state."""

import ast
from contextlib import contextmanager
from functools import lru_cache
from importlib import import_module
from inspect import signature
from pathlib import Path
import subprocess
import tempfile
import threading
from types import FunctionType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/coccinelle/tests/test_runner.py", "_isolated_spatch_resolution", "spatch", 2),
    ("packages/coccinelle/tests/test_lexical_cache.py", "empty_lexical_cache", "lexical", 1),
    ("packages/joern/tests/test_broker.py", "_fresh_toolchain_paths", "paths", 6),
    ("packages/sca/tests/test_risk.py", "_flushed_calibration_cache", "risk", 1),
    ("core/testing/tests/test_asan.py", "clear_probe_cache", "asan", 1),
    ("core/concepts/tests/test_audit_bridge.py", "TestGrepHintGuard._fresh_demotion_log", "hint", 2),
    ("core/security/tests/test_cc_dispatch_recheck.py", "_fresh_state", "trust", 3),
    ("core/sandbox/tests/test_host_consent.py", "_fresh_latches", "warnings", 1),
]
MODULES = {
    "spatch": "packages.coccinelle.runner", "lexical": "packages.coccinelle.runner",
    "paths": "packages.joern.prereqs", "risk": "packages.sca.risk",
    "asan": "core.testing.asan", "hint": "core.concepts.audit_bridge",
    "trust": "core.security.cc_trust", "warnings": "core.sandbox.host_consent",
}


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


def _clone(raw, globals):
    result = FunctionType(raw.__code__, globals, raw.__name__, raw.__defaults__)
    result.__kwdefaults__ = raw.__kwdefaults__
    return result


def _prepare(case, tmp_path, fail_at=None):
    kind = case[2]
    owner = _view(MODULES[kind])
    # Bind real function bytecode to the private consumer's globals too.
    for name, value in tuple(vars(owner).items()):
        if isinstance(value, FunctionType) and value.__module__ == owner.__name__:
            setattr(owner, name, _clone(value, owner.__dict__))
    cache_field = None
    if kind == "spatch":
        owner._resolved_spatch, owner._spatch_resolved = "/caller/spatch", True
        fields = ("_resolved_spatch", "_spatch_resolved")
    elif kind == "paths":
        owner._resolved_joern = "/caller/joern"
        owner._resolved_joern_parse = "/caller/joern-parse"
        owner._resolved_java = "/caller/java"
        owner._joern_resolved = owner._joern_parse_resolved = owner._java_resolved = True
        fields = ("_resolved_joern", "_joern_resolved", "_resolved_joern_parse", "_joern_parse_resolved", "_resolved_java", "_java_resolved")
    elif kind == "risk":
        owner._CALIBRATION_STATUS_CACHE = "passed"
        fields = ("_CALIBRATION_STATUS_CACHE",)
    elif kind == "warnings":
        owner._warned_reasons = {"caller reason"}
        owner._warned_lock = threading.Lock()
        fields = ("_warned_reasons", "_warned_lock")
    else:
        if kind == "lexical":
            cache_field, cache_args = "_cached_lexical_scan", ("@r@\n@@\nint caller;", owner._CHAR_LITERAL_CAP)
            fields = (cache_field,)
        elif kind == "asan":
            cache_field, cache_args = "_runtime_unavailable_reason", ("owned-compiler",)
            fields = (cache_field,)
            process_view = _view("subprocess")
            process_view.run = lambda command, **kwargs: subprocess.CompletedProcess(command, 1, "", "owned compiler unavailable")
            temporary_view = _view("tempfile")
            temporary_view.TemporaryDirectory = lambda **kwargs: tempfile.TemporaryDirectory(dir=tmp_path, **kwargs)
            owner.subprocess, owner.tempfile = process_view, temporary_view
        elif kind == "hint":
            cache_field, cache_args = "_grep_hint_compilable", ("caller_literal",)
            owner._demoted_hints_logged = {"caller hint"}
            fields = (cache_field, "_demoted_hints_logged")
        else:
            cache_field = "_scan_cached"
            cache_args = (str(tmp_path), owner._read_config_state(tmp_path))
            owner._trust_override_set = True
            fields = (cache_field, "_trust_override_set")
        borrowed = getattr(owner, cache_field)
        fresh = lru_cache(**borrowed.cache_parameters())(_clone(borrowed.__wrapped__, owner.__dict__))
        setattr(owner, cache_field, fresh)
        fresh(*cache_args)
        fresh(*cache_args)
        cache_stats, cache_parameters = fresh.cache_info(), fresh.cache_parameters()
    snapshot = {name: getattr(owner, name) for name in fields}
    sets = [(value, value.copy()) for value in snapshot.values() if isinstance(value, set)]
    calls = 0

    def after_write():
        nonlocal calls
        calls += 1
        if calls == fail_at:
            raise RuntimeError("injected setup failure")

    class Patch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            after_write()

        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            after_write()

    helper = _view("core.testing.module_state")
    raw = helper.isolated_module_state.__wrapped__
    pytest_view = _view("pytest")
    pytest_view.MonkeyPatch = Patch
    clone = _clone(raw, dict(raw.__globals__, pytest=pytest_view))
    helper.isolated_module_state = contextmanager(clone)
    parents = {}
    for parent in ("packages.sca", "core.concepts", "core.security"):
        parents[parent] = _view(parent)
        setattr(parents[parent], owner.__name__.rsplit(".", 1)[-1], owner)

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name in parents:
            return parents[name]
        return __import__(name, globals, locals, fromlist, level)

    namespace = {"runner_mod": owner, "runner": owner, "prereqs": owner, "asan": owner, "hc": owner,
                 "_scan_cached": getattr(owner, "_scan_cached", None),
                 "set_trust_override": getattr(owner, "set_trust_override", None),
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for name, value in snapshot.items():
            assert getattr(owner, name) is value
        for value, before in sets:
            assert value == before
        if cache_field is not None:
            borrowed = snapshot[cache_field]
            assert borrowed.cache_info() == cache_stats
            assert borrowed.cache_parameters() == cache_parameters
            if kind == "trust":
                assert namespace["_scan_cached"] is borrowed

    return namespace, owner, Patch, snapshot, restored


def _start(case, namespace, patch):
    path, name, _, _ = case
    node = ast.parse((ROOT / path).read_text())
    for part in name.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[node.name]
    available = {"self": object(), "monkeypatch": patch}
    result = function(**{key: available[key] for key in signature(function).parameters})
    next(result)
    return result


@pytest.mark.parametrize("case", CASES, ids=[c[2] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
@pytest.mark.parametrize("body_patch", [False, True], ids=["direct-writes", "body-patches"])
def test_discovery_fixture_preserves_borrowed_state(case, mode, body_patch, tmp_path):
    namespace, owner, patch_type, snapshot, restored = _prepare(case, tmp_path)
    generator = None
    try:
        with patch_type.context() as patch:
            generator = _start(case, namespace, patch)
            for name, borrowed in snapshot.items():
                active = getattr(owner, name)
                if name.endswith("lock"):
                    assert active is borrowed
                    continue
                assert active is not borrowed
                if hasattr(active, "cache_info"):
                    assert active.cache_info().currsize == 0
                    assert active.cache_parameters() == borrowed.cache_parameters()
                    value = lru_cache(**active.cache_parameters())(active.__wrapped__)
                    if case[2] == "trust":
                        assert namespace["_scan_cached"] is active
                elif isinstance(active, set):
                    assert not active
                    value = {"owned reason"}
                elif isinstance(active, bool):
                    assert active is False
                    value = False
                else:
                    assert active is None
                    value = "/owned/tool" if name.startswith("_resolved") else "failed"
                if body_patch:
                    patch.setattr(owner, name, value)
                else:
                    setattr(owner, name, value)
            if mode == "close":
                generator.close()
            elif mode == "throw":
                with pytest.raises(KeyboardInterrupt):
                    generator.throw(KeyboardInterrupt)
            else:
                with pytest.raises(StopIteration):
                    next(generator)
        restored()
    finally:
        if generator is not None:
            generator.close()


FAULTS = [(case, step) for case in CASES for step in sorted({1, case[3]})]


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[2] + ":" + str(step) for c, step in FAULTS])
def test_discovery_fixture_restores_partial_setup(case, fail_at, tmp_path):
    namespace, _, patch_type, _, restored = _prepare(case, tmp_path, fail_at)
    generator = None
    try:
        with patch_type.context() as patch:
            with pytest.raises(RuntimeError, match="injected setup failure"):
                generator = _start(case, namespace, patch)
        restored()
    finally:
        if generator is not None:
            generator.close()

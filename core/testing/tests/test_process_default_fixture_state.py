"""Default-state fixtures preserve borrowed flags, LRU contents and objects."""

import ast
from contextlib import contextmanager
from functools import lru_cache
from importlib import import_module
from inspect import signature
from pathlib import Path
import threading
from types import FunctionType, ModuleType

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/codeql/tests/test_codeql_trust_integration.py", "_clear_trust_state", "ql", 1),
    ("core/security/tests/test_cc_trust.py", "_reset_trust_override", "cc", 1),
    ("core/security/tests/test_cc_trust_self_worktree.py", "_reset_trust_override", "cc", 1),
    ("core/security/tests/test_codeql_trust.py", "_reset_trust_override", "ql", 1),
    ("core/security/tests/test_codeql_trust_self_worktree.py", "_reset_trust_override", "ql", 1),
    ("core/security/tests/test_cc_trust.py", "_clear_trust_cache", "cache", 2),
    ("core/security/tests/test_cc_trust_self_worktree.py", "_clear_trust_cache", "cache", 2),
    ("packages/codeql/tests/test_buildless_mode.py", "TestTracedBuildTrustIndependence._reset_overrides", "both", 3),
    ("core/http/tests/test_urllib_backend.py", "_reset_default_breaker", "breaker", 1),
    ("packages/exploit_feasibility/tests/test_config_env_overrides.py", "_clean_global_config", "config", 1),
    ("packages/cve_env/tests/unit/test_set_cve_version_context.py", "_reset_context", "version", 1),
]


def _view(name):
    view = ModuleType(name)
    view.__dict__.update(vars(import_module(name)))
    return view


def _bind(owner, name):
    raw = getattr(owner, name)
    clone = FunctionType(raw.__code__, owner.__dict__, name, raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    setattr(owner, name, clone)
    return clone


def _prepare(case, tmp_path, fail_at=None):
    kind = case[2]
    cc = _view("core.security.cc_trust")
    ql = _view("core.security.codeql_trust")
    cc._trust_override_set = ql._trust_override_set = True
    _bind(cc, "set_trust_override")
    _bind(ql, "set_trust_override")
    cc._scan_cached = lru_cache(**cc._scan_cached.cache_parameters())(cc._scan_cached.__wrapped__)
    state = cc._read_config_state(tmp_path)
    cc._scan_cached(str(tmp_path), state)
    cc._scan_cached(str(tmp_path), state)
    original_scan = cc._scan_cached
    original_stats = original_scan.cache_info()
    original_parameters = original_scan.cache_parameters()
    if kind in ("cc", "cache", "both"):
        owner = cc
        fields = ("_scan_cached",) if kind == "cache" else ("_trust_override_set", "_scan_cached") if kind == "both" else ("_trust_override_set",)
    elif kind == "ql":
        owner, fields = ql, ("_trust_override_set",)
    elif kind == "breaker":
        owner = _view("core.http.urllib_backend")
        owner._DEFAULT_CIRCUIT_BREAKER_LOCK = threading.Lock()
        breaker = owner._HostCircuitBreaker()
        breaker.record_failure("caller.invalid", 443)
        breaker.record_failure("caller.invalid", 443)
        owner._DEFAULT_CIRCUIT_BREAKER = breaker
        fields = ("_DEFAULT_CIRCUIT_BREAKER", "_DEFAULT_CIRCUIT_BREAKER_LOCK")
        failures = {key: values.copy() for key, values in breaker._failures.items()}
        deadlines = breaker._open_until.copy()
        _bind(owner, "reset_default_circuit_breaker")
    elif kind == "config":
        owner = _view("packages.exploit_feasibility.config")
        owner._global_config_lock = threading.Lock()
        owner._global_config = owner.AnalysisConfig(verbose=True)
        config_fields = vars(owner._global_config).copy()
        fields = ("_global_config", "_global_config_lock")
        _bind(owner, "reset_config")
    else:
        owner = _view("cve_env.agent.tools")
        owner._CURRENT_CVE_VERSION = "caller-version"
        fields = ("_CURRENT_CVE_VERSION",)
    snapshot = [(owner, {name: getattr(owner, name) for name in fields})]
    if kind == "both":
        snapshot.append((ql, {"_trust_override_set": ql._trust_override_set}))
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
    clone = FunctionType(raw.__code__, dict(raw.__globals__, pytest=pytest_view))
    clone.__kwdefaults__ = raw.__kwdefaults__
    helper.isolated_module_state = contextmanager(clone)
    security = _view("core.security")
    security.cc_trust, security.codeql_trust = cc, ql
    core = _view("core")
    core.security = security
    http = _view("core.http")
    http.urllib_backend = owner
    feasibility = _view("packages.exploit_feasibility")
    feasibility.config = owner

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name == "core.security":
            return security
        if name in ("core.security.cc_trust", "core.security.codeql_trust"):
            return (cc if name.endswith("cc_trust") else ql) if fromlist else core
        if name == "core.http":
            return http
        if name == "packages.exploit_feasibility" or (level == 2 and "config" in fromlist):
            return feasibility
        return __import__(name, globals, locals, fromlist, level)

    namespace = {"cve_tools": owner, "_scan_cached": original_scan,
                 "set_trust_override": owner.set_trust_override if kind in ("cc", "ql", "cache", "both") else None,
                 "reset_default_circuit_breaker": getattr(owner, "reset_default_circuit_breaker", None),
                 "reset_config": getattr(owner, "reset_config", None),
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for module, values in snapshot:
            for name, value in values.items():
                assert getattr(module, name) is value
        if kind in ("cache", "both"):
            assert original_scan.cache_info() == original_stats
            assert original_scan.cache_parameters() == original_parameters
            if kind == "cache":
                assert namespace["_scan_cached"] is original_scan
        if kind == "breaker":
            assert breaker._failures == failures
            assert breaker._open_until == deadlines
        if kind == "config":
            assert vars(owner._global_config) == config_fields
            for name, value in config_fields.items():
                assert getattr(owner._global_config, name) is value

    return namespace, Patch, snapshot, restored


def _start(case, namespace, patch):
    path, name, _, _ = case
    node = ast.parse((ROOT / path).read_text())
    for part in name.split("."):
        node = next(n for n in node.body if getattr(n, "name", None) == part)
    node.decorator_list = []
    exec(compile(ast.Module(body=[node], type_ignores=[]), path, "exec"), namespace)
    function = namespace[node.name]
    available = {"monkeypatch": patch, "self": object()}
    result = function(**{key: available[key] for key in signature(function).parameters})
    next(result)
    return result


@pytest.mark.parametrize("case", CASES, ids=[c[0] + ":" + c[1] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
@pytest.mark.parametrize("body_patch", [False, True], ids=["direct-writes", "body-patches"])
def test_default_fixture_restores_borrowed_state(case, mode, body_patch, tmp_path):
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
                    if name == "_scan_cached":
                        assert active.cache_parameters() == borrowed.cache_parameters()
                        assert active.cache_info().currsize == 0
                        if case[2] == "cache":
                            assert namespace["_scan_cached"] is active
                        value = lru_cache(**active.cache_parameters())(active.__wrapped__)
                    elif name == "_DEFAULT_CIRCUIT_BREAKER":
                        assert active is None
                        value = owner._HostCircuitBreaker()
                    elif name == "_global_config":
                        assert active is None
                        value = owner.AnalysisConfig(verbose=False)
                    elif name == "_CURRENT_CVE_VERSION":
                        assert active == ""
                        value = "owned-version"
                    else:
                        assert active is False
                        value = True
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


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[0] + ":" + c[1] + ":" + str(step) for c, step in FAULTS])
def test_default_fixture_restores_partial_setup(case, fail_at, tmp_path):
    namespace, patch_type, _, restored = _prepare(case, tmp_path, fail_at)
    generator = None
    try:
        with patch_type.context() as patch:
            with pytest.raises(RuntimeError, match="injected setup failure"):
                generator = _start(case, namespace, patch)
        restored()
    finally:
        if generator is not None:
            generator.close()

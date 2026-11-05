"""Metadata fixtures preserve cached clients, counters and imported aliases."""

import ast
import os
from collections import defaultdict
from contextlib import contextmanager
import __future__
from functools import lru_cache
from importlib import import_module
from inspect import signature
from pathlib import Path
import subprocess
import threading
from types import FunctionType, ModuleType
from unittest import mock

import pytest


ROOT = Path(__file__).resolve().parents[3]
CASES = [
    ("packages/cve_diff/tests/unit/infra/test_github_client.py", "_isolate", "github", 9),
    ("packages/cve_diff/tests/unit/infra/conftest.py", "_isolated_api_events", "events", 2),
    ("packages/cve_diff/tests/unit/agent/test_forge_hosts.py", "_isolated_forge_client", "forge", 1),
    ("packages/cve_env/tests/unit/test_arch.py", "_isolated_host_arch", "arch", 2),
    ("packages/cve_env/tests/unit/test_migration_resilience.py", "_isolated_compose_probe", "compose", 2),
]
CUSTOM = ("get_repo", "get_languages", "commit_exists", "_get_commit_cached")


def _clone(raw, globals):
    clone = FunctionType(raw.__code__, globals, raw.__name__, raw.__defaults__)
    clone.__kwdefaults__ = raw.__kwdefaults__
    return clone


def _view(name):
    owner = ModuleType(name)
    owner.__dict__.update(vars(import_module(name)))
    for field, value in tuple(vars(owner).items()):
        if isinstance(value, FunctionType) and value.__module__ == name and not value.__code__.co_freevars:
            setattr(owner, field, _clone(value, owner.__dict__))
    return owner


def _client():
    """Fully initialize a real client and pool without starting a proxy or request."""
    from core.http import egress_backend, urllib_backend

    from core.testing.module_state import isolated_module_state

    with isolated_module_state(
        urllib_backend, {"_DEFAULT_CIRCUIT_BREAKER": urllib_backend._HostCircuitBreaker()},
        lock=urllib_backend._DEFAULT_CIRCUIT_BREAKER_LOCK,
    ), pytest.MonkeyPatch.context() as patch:
        patch.setattr(egress_backend, "seatbelt_parent_proxy_url", lambda: "http://127.0.0.1:1")
        client = egress_backend.EgressClient(allowed_hosts={"api.github.com"})
    pool = client._http.connection_from_url("https://api.github.com")
    return client, pool


def _prepare(case, tmp_path, fail_at=None):
    kind = case[2]
    client = pool = bucket = None
    cache_args = {}
    extra = None
    if kind == "github":
        owner = _view("cve_diff.infra.github_client")
        client, pool = _client()

        def get_json(url, **kwargs):
            if url.endswith("/languages"):
                return {"C": 42}
            if "/commits/" in url:
                return {"sha": "abcd1234", "files": [{"filename": "caller.c"}]}
            return {"full_name": "caller/repo"}

        client.get_json = get_json
        owner.EgressClient = lambda **kwargs: client
        owner._token = lambda: None
        bucket = owner.TokenBucket(capacity=50, refill_per_second=1, now=lambda: 0.0)
        owner.TokenBucket = lambda **kwargs: bucket
        for name in CUSTOM:
            raw = getattr(owner, name).__wrapped__
            setattr(owner, name, owner._cache_unless_none(_clone(raw, owner.__dict__)))
            cache_args[name] = ("caller/repo", "abcd1234") if name in ("commit_exists", "_get_commit_cached") else ("caller/repo",)
        for name in ("_bucket", "_client"):
            borrowed = getattr(owner, name)
            setattr(owner, name, lru_cache(**borrowed.cache_parameters())(_clone(borrowed.__wrapped__, owner.__dict__)))
            cache_args[name] = ()
        owner._warn_lock = threading.Lock()
        owner._warned_token_missing = owner._warned_rate_limited = True
        fields = (*CUSTOM, "_bucket", "_client", "_warn_lock", "_warned_token_missing", "_warned_rate_limited")
    elif kind == "events":
        owner = _view("cve_diff.infra.api_status")
        owner._lock = threading.Lock()
        owner._events = defaultdict(owner._events.default_factory)
        owner._events["caller"][429] = 3
        owner._cache_events = defaultdict(owner._cache_events.default_factory)
        owner._cache_events["caller"] = {"hits": 2, "misses": 1}
        fields = ("_events", "_cache_events", "_lock")
    elif kind == "forge":
        owner = _view("cve_diff.agent.tools")
        client, pool = _client()
        owner.EgressClient = lambda **kwargs: client
        owner._OVERRIDE_CONFIG_PATH = tmp_path / "forge.json"
        borrowed = owner._forge_client
        owner._forge_client = lru_cache(**borrowed.cache_parameters())(_clone(borrowed.__wrapped__, owner.__dict__))
        fields = ("_forge_client",)
        cache_args[fields[0]] = ()
    elif kind == "arch":
        owner = _view("cve_env.tools.arch")
        platform = _view("platform")
        platform.machine, platform.system = lambda: "x86_64", lambda: "Linux"
        owner._platform = platform
        borrowed = owner.detect_host_arch
        owner.detect_host_arch = lru_cache(**borrowed.cache_parameters())(_clone(borrowed.__wrapped__, owner.__dict__))
        fields = ("detect_host_arch",)
        cache_args[fields[0]] = ()
    else:
        from core.container.proc import RunOutcome

        owner = _view("core.container.compose")
        owner.shutil = _view("shutil")
        owner.shutil.which = lambda name: "/caller/" + name
        owner.run_cli = lambda *args, **kwargs: RunOutcome(0, "version", "", False)
        borrowed = owner._compose_invocation
        owner._compose_invocation = lru_cache(**borrowed.cache_parameters())(_clone(borrowed.__wrapped__, owner.__dict__))
        extra = _view("cve_env.tools.docker_compose_up")
        extra._compose_invocation = owner._compose_invocation
        fields = ("_compose_invocation",)
        cache_args[fields[0]] = ()
    for name, args in cache_args.items():
        function = getattr(owner, name)
        function(*args)
        function(*args)
    snapshot = {name: getattr(owner, name) for name in fields}
    dictionaries = [(value, {key: dict(payload) for key, payload in value.items()}, dict(value), value.default_factory)
                    for value in snapshot.values() if isinstance(value, defaultdict)]
    caches = []
    for name in cache_args:
        function = getattr(owner, name)
        info = function.cache_info()
        caches.append((function, (info.hits, info.misses, info.currsize),
                       function.cache_parameters() if hasattr(function, "cache_parameters") else None))
    bucket_fields = vars(bucket).copy() if bucket is not None else None
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
    helper.isolated_module_state = contextmanager(_clone(raw, dict(raw.__globals__, pytest=pytest_view)))
    infra = _view("cve_diff.infra")
    infra.api_status = owner
    tools = _view("cve_env.tools")
    tools.arch, tools.docker_compose_up = owner, extra
    container = _view("core.container")
    container.compose = owner

    def private_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "core.testing.module_state":
            return helper
        if name == "cve_diff.infra":
            return infra
        if name == "cve_env.tools":
            return tools
        if name == "core.container":
            return container
        return __import__(name, globals, locals, fromlist, level)

    def native_patch(target, **kwargs):
        if target == "cve_env.tools.arch.Path":
            return mock.patch.object(owner, "Path", **kwargs)
        if target == "core.container.compose.shutil.which":
            return mock.patch.object(owner.shutil, "which", **kwargs)
        if target == "core.container.proc.subprocess.run":
            # Transport isn't the subject here; preserve the upper-layer timeout outcome.
            from core.container.proc import RunOutcome
            return mock.patch.object(owner, "run_cli", return_value=RunOutcome(None, "", "timeout", True))
        raise AssertionError(target)

    namespace = {"github_client": owner, "api_status": owner, "tools": owner,
                 "detect_host_arch": getattr(owner, "detect_host_arch", None),
                 "mock": mock, "patch": native_patch, "subprocess": subprocess,
                 "__builtins__": dict(vars(import_module("builtins")), __import__=private_import)}

    def restored():
        for name, value in snapshot.items():
            assert getattr(owner, name) is value
        for value, before, payloads, factory in dictionaries:
            assert value.default_factory is factory
            assert value == before
            for key, payload in payloads.items():
                assert value[key] is payload
        for function, before, parameters in caches:
            info = function.cache_info()
            assert (info.hits, info.misses, info.currsize) == before
            if parameters is not None:
                assert function.cache_parameters() == parameters
        if extra is not None:
            assert extra._compose_invocation is snapshot["_compose_invocation"]
        if kind == "arch":
            assert namespace["detect_host_arch"] is snapshot["detect_host_arch"]
        if client is not None:
            assert len(client._http.pools) == 1
            assert client._http.connection_from_url("https://api.github.com") is pool
        if bucket is not None:
            assert vars(bucket) == bucket_fields
            for name, value in bucket_fields.items():
                assert getattr(bucket, name) is value

    def cleanup():
        if client is not None:
            client._http.clear()

    return namespace, owner, Patch, snapshot, restored, cleanup


def _function(path, name, namespace):
    node = next(n for n in ast.parse((ROOT / path).read_text()).body if getattr(n, "name", None) == name)
    node.decorator_list = []
    code = compile(ast.Module(body=[node], type_ignores=[]), path, "exec", flags=__future__.annotations.compiler_flag)
    exec(code, namespace)
    return namespace[name]


def _legacy_consumer(case, namespace, owner, tmp_path):
    """Run the real old consumer operation when the owning fixture is new."""
    kind = case[2]
    if kind == "events":
        _function("packages/cve_diff/tests/unit/infra/test_api_status.py", "test_record_cache_hit_increments_hits", namespace)()
    elif kind == "forge":
        import json
        def override(data):
            owner._OVERRIDE_CONFIG_PATH.write_text(json.dumps(data))
        _function(case[0], "test_forge_client_uses_resolved_hosts_at_call_time", namespace)(override)
    elif kind == "arch":
        owner._platform = mock.Mock()
        _function(case[0], "test_detect_host_arch_arm64_darwin", namespace)(owner._platform)
    elif kind == "compose":
        _function(case[0], "test_compose_invocation_falls_back_when_probe_times_out", namespace)()
    yield


def _start(case, namespace, owner, patch, tmp_path):
    path, name, _, _ = case
    exists = (ROOT / path).exists()
    names = {getattr(n, "name", None) for n in ast.parse((ROOT / path).read_text()).body} if exists else set()
    if name not in names:
        result = _legacy_consumer(case, namespace, owner, tmp_path)
    else:
        function = _function(path, name, namespace)
        available = {"monkeypatch": patch}
        result = function(**{key: available[key] for key in signature(function).parameters})
    next(result)
    return result


@pytest.mark.parametrize("case", CASES, ids=[c[2] for c in CASES])
@pytest.mark.parametrize("mode", ["normal", "close", "throw"])
def test_metadata_fixture_preserves_warm_callers(case, mode, tmp_path):
    namespace, owner, patch_type, snapshot, restored, cleanup = _prepare(case, tmp_path)
    generator = None
    try:
        with patch_type.context() as patch:
            generator = _start(case, namespace, owner, patch, tmp_path)
            for name, borrowed in snapshot.items():
                active = getattr(owner, name)
                if name.endswith("lock"):
                    assert active is borrowed
                elif hasattr(active, "cache_info"):
                    assert active is not borrowed
                    assert active.cache_info().currsize == 0
                    if hasattr(borrowed, "cache_parameters"):
                        assert active.cache_parameters() == borrowed.cache_parameters()
                    patch.setattr(owner, name, active)
                elif isinstance(active, defaultdict):
                    assert active is not borrowed
                    assert active.default_factory is borrowed.default_factory
                    assert not active
                    if name == "_events":
                        active["owned"][429] += 1
                    else:
                        active["owned"]["hits"] += 1
                else:
                    assert active is False
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
        cleanup()


FAULTS = [(case, step) for case in CASES for step in sorted({1, case[3]})]


@pytest.mark.parametrize("case,fail_at", FAULTS, ids=[c[2] + ":" + str(step) for c, step in FAULTS])
def test_metadata_fixture_restores_partial_setup(case, fail_at, tmp_path):
    namespace, owner, patch_type, _, restored, cleanup = _prepare(case, tmp_path, fail_at)
    generator = None
    try:
        with patch_type.context() as patch:
            with pytest.raises(RuntimeError, match="injected setup failure"):
                generator = _start(case, namespace, owner, patch, tmp_path)
        restored()
    finally:
        if generator is not None:
            generator.close()
        cleanup()


@pytest.mark.parametrize("original", [None, "", "caller-token"], ids=["missing", "empty", "set"])
@pytest.mark.parametrize("mode", ["normal", "close", "first-write-fault", "last-write-fault"])
def test_github_fixture_restores_exact_token_presence(original, mode, tmp_path):
    namespace, owner, patch_type, _, restored, cleanup = _prepare(CASES[0], tmp_path,
        1 if mode == "first-write-fault" else 9 if mode == "last-write-fault" else None)
    generator = None
    try:
        with pytest.MonkeyPatch.context() as environment:
            # Register outer absence as well, so a failed baseline cannot leak its token.
            environment.setenv("GITHUB_TOKEN", os.environ.get("GITHUB_TOKEN", ""))
            if original is None:
                environment.delenv("GITHUB_TOKEN")
            else:
                environment.setenv("GITHUB_TOKEN", original)
            with patch_type.context() as patch:
                if mode.endswith("fault"):
                    with pytest.raises(RuntimeError, match="injected setup failure"):
                        generator = _start(CASES[0], namespace, owner, patch, tmp_path)
                else:
                    generator = _start(CASES[0], namespace, owner, patch, tmp_path)
                    assert "GITHUB_TOKEN" not in os.environ
                    os.environ["GITHUB_TOKEN"] = "owned-token"
                    if mode == "close":
                        generator.close()
                    else:
                        with pytest.raises(StopIteration):
                            next(generator)
            if original is None:
                assert "GITHUB_TOKEN" not in os.environ
            else:
                assert os.environ["GITHUB_TOKEN"] == original
            restored()
    finally:
        if generator is not None:
            generator.close()
        cleanup()

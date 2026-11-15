"""SAGE fixture lifecycle against a valid, private negative-cache module."""

import __future__
import ast
import builtins
import hashlib
import json
from pathlib import Path
import threading
import time
from types import ModuleType, SimpleNamespace
import unittest

import pytest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[3]
PINS = {
    "setUp": "ca331cef52ba6d9c88dfabe04fdb0a142c5a995d57209ca86676f6d03570e550",
    "tearDown": "16f733923cdc59e527c50f5c02f06d23168e11520bdcdc35e24d397546a4430c",
}
PRODUCER_PINS = {
    "_CLIENT_NONE_TTL_S": "ca7871634cda6118acf3fc57d800502316e6ef462d948bb77cb64e33300cd8f6",
    "_get_client": "893664e7edf28fceea5f381ce773ebdd7c012c90b9b0d4fded07b4a99e47afaa",
}
HELPER_SHA256 = "c4a32dbbf620e4e04a05c62ecc8ad840bb5008eb1808549a0708354c94b0d8c0"


def _exercise(tmp_path, body_error, expected_restored):
    source = ROOT / "core/sage/tests/test_sage_hooks.py"
    text = source.read_text()
    tree = ast.parse(text)
    cls = next(
        n
        for n in tree.body
        if isinstance(n, ast.ClassDef) and n.name == "TestGetClientThreadSafety"
    )
    nodes = [n for n in cls.body if isinstance(n, ast.FunctionDef) and n.name in PINS]
    assert len(nodes) == 2
    for n in nodes:
        assert (
            hashlib.sha256(ast.get_source_segment(text, n).encode()).hexdigest()
            == PINS[n.name]
        )
    producer = ROOT / "core/sage/hooks.py"
    pt = producer.read_text()
    selected = [
        n
        for n in ast.parse(pt).body
        if (isinstance(n, ast.FunctionDef) and n.name == "_get_client")
        or (
            isinstance(n, ast.AnnAssign)
            and isinstance(n.target, ast.Name)
            and n.target.id == "_CLIENT_NONE_TTL_S"
        )
    ]
    assert len(selected) == 2
    for n in selected:
        name = n.name if isinstance(n, ast.FunctionDef) else n.target.id
        assert (
            hashlib.sha256(ast.get_source_segment(pt, n).encode()).hexdigest()
            == PRODUCER_PINS[name]
        )
    hooks = ModuleType("owned_sage_fixture")
    attempts = []

    def forbidden_init():
        attempts.append(True)
        raise AssertionError("unexpected provider/config initialization")

    stamp = time.time()
    hooks.__dict__.update(
        _client=None,
        _client_initialised=True,
        _client_none_decided_at=stamp,
        _client_lock=threading.Lock(),
        _ollama_gpu_available=forbidden_init,
        time=time,
    )
    exec(
        compile(
            ast.Module(body=selected, type_ignores=[]),
            str(producer),
            "exec",
            flags=__future__.annotations.compiler_flag,
        ),
        hooks.__dict__,
    )
    original = (hooks._client, hooks._client_initialised, hooks._client_none_decided_at)
    assert 0 <= time.time() - stamp < hooks._CLIENT_NONE_TTL_S
    assert hooks._get_client() is None and not attempts
    helper = ROOT / "core/testing/module_state.py"
    assert hashlib.sha256(helper.read_bytes()).hexdigest() == HELPER_SHA256
    helper_ns = {}
    exec(compile(helper.read_text(), str(helper), "exec"), helper_ns)
    native_import = builtins.__import__

    def scoped_import(name, *args, **kwargs):
        if name == "core.sage":
            return SimpleNamespace(hooks=hooks)
        return native_import(name, *args, **kwargs)

    patchers = []

    def scoped_patch(target, *args, **kwargs):
        assert target == "core.sage.hooks._ollama_gpu_available"
        owned = patch.object(hooks, "_ollama_gpu_available", *args, **kwargs)
        patchers.append(owned)
        return owned

    namespace = {
        "__builtins__": dict(vars(builtins), __import__=scoped_import),
        "patch": scoped_patch,
        "isolated_module_state": helper_ns["isolated_module_state"],
    }
    exec(
        compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace
    )
    primary = RuntimeError("controlled fixture body boundary")

    def body(self):
        assert hooks._client is None and hooks._client_initialised is False
        if body_error:
            raise primary

    class Result(unittest.TestResult):
        actual_error = None

        def addError(self, test, err):
            self.actual_error = err[1]
            super().addError(test, err)

    case = type(
        "SageLifecycleComponent",
        (unittest.TestCase,),
        {
            "setUp": namespace["setUp"],
            "tearDown": namespace["tearDown"],
            "test_boundary": body,
            "__module__": __name__,
        },
    )
    result = Result()
    try:
        unittest.TestSuite([case("test_boundary")]).run(result)
        assert result.testsRun == 1 and not result.failures
        assert len(result.errors) == int(body_error)
        assert (
            (result.actual_error is primary)
            if body_error
            else result.actual_error is None
        )
        observed = (
            hooks._client,
            hooks._client_initialised,
            hooks._client_none_decided_at,
        )
        assert (observed == original) is expected_restored
        assert hooks._ollama_gpu_available is forbidden_init
        assert not attempts and len(patchers) == 1
        if expected_restored:
            assert hooks._get_client() is None and not attempts
        else:
            assert observed == (None, False, stamp)
        (tmp_path / "observation.json").write_text(
            json.dumps(
                {
                    "body_error": body_error,
                    "cache_restored_before_rescue": expected_restored,
                    "initialised_after_cleanup": hooks._client_initialised,
                    "negative_timestamp_preserved": hooks._client_none_decided_at
                    == stamp,
                    "gpu_binding_restored": True,
                    "unexpected_initialization": attempts,
                    "scope": "private-module exact setup/teardown and real unittest cleanup only; actual cached-negative producer path, no provider/concurrency/full-native test execution",
                }
            )
            + "\n"
        )
    finally:
        for owned in patchers:
            owned.stop()
        hooks._client, hooks._client_initialised, hooks._client_none_decided_at = (
            original
        )


@pytest.mark.parametrize(
    "body_error", [False, True], ids=["complete", "controlled-body-error"]
)
def test_negative_cache_fixture_ownership(tmp_path, body_error):
    _exercise(tmp_path, body_error, True)

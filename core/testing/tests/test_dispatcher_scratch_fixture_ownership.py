"""Scratch fixture request owns directories before marker and server setup."""

import builtins
from contextlib import ExitStack
import importlib
import json
import os
from pathlib import Path
import shutil
import tempfile
from types import FunctionType, ModuleType, SimpleNamespace

import pytest

CASES = ["test_construction_sweeps_dead_owner_run_scoped_dirs", "test_ensure_inprocess_sweeps_dead_owner_dirs"]


def _bindings(tmp_path, *, stage=None, error=None, after=False, allocation=1):
    owner = importlib.import_module("core.llm.dispatcher.tests.test_inproc_scratch_cleanup")
    original_functions = {name: getattr(owner, name) for name in ["_owned_dir", "_inproc_dir", *CASES]}
    resources, reached = [], []
    failure = error("owned scratch fixture setup failure") if error else None

    class OwnedPath(type(Path())):
        def mkdir(self, *args, **kwargs):
            result = super().mkdir(*args, **kwargs)
            resources.append(self)
            return result

        def write_text(self, *args, **kwargs):
            if stage == "marker" and len(resources) == allocation:
                reached.append(stage)
                if after:
                    super().write_text(*args, **kwargs)
                raise failure
            return super().write_text(*args, **kwargs)

    def constructor(*args, **kwargs):
        reached.append("constructor")
        raise failure

    private = ModuleType("tempfile")
    vars(private).update(vars(tempfile))
    private.gettempdir = lambda: str(tmp_path)
    lifecycle = ModuleType("core.llm.dispatcher.lifecycle")
    lifecycle.ensure_inprocess_dispatcher_env = constructor

    def importing(name, *args, **kwargs):
        if name == "core.llm.dispatcher.lifecycle":
            return lifecycle
        return builtins.__import__(name, *args, **kwargs)

    namespace = dict(vars(owner), tempfile=private, Path=OwnedPath, LLMDispatcher=constructor,
                     __builtins__=dict(vars(builtins), __import__=importing))
    for name, original in original_functions.items():
        function = FunctionType(original.__code__, namespace, original.__name__,
                                original.__defaults__, original.__closure__)
        function.__kwdefaults__ = original.__kwdefaults__
        namespace[name] = function

    def unchanged():
        return all(getattr(owner, name) is original for name, original in original_functions.items())

    return owner, namespace, resources, reached, failure, unchanged


@pytest.mark.parametrize("name", CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
def test_constructor_failure_retires_fixture_directories(name, error, tmp_path):
    _exercise_failure(name, error, tmp_path, stage="constructor")


@pytest.mark.parametrize("name", CASES)
@pytest.mark.parametrize("error", [OSError, KeyboardInterrupt, SystemExit])
@pytest.mark.parametrize("after", [False, True], ids=["before-write", "after-write"])
@pytest.mark.parametrize("allocation", [1, 2], ids=["first-directory", "second-directory"])
def test_marker_failure_retires_acquired_directories(name, error, after, allocation, tmp_path):
    _exercise_failure(name, error, tmp_path, stage="marker", after=after, allocation=allocation)


def _exercise_failure(name, error, tmp_path, *, stage, after=False, allocation=1):
    owner, namespace, resources, reached, failure, unchanged = _bindings(
        tmp_path, stage=stage, error=error, after=after, allocation=allocation,
    )
    before_env = dict(os.environ)
    try:
        with pytest.MonkeyPatch.context() as patch, ExitStack() as finalizers:
            # Forward the fixture's sole request API to a real callback stack;
            # original domain nodes separately exercise pytest's real request.
            request = SimpleNamespace(addfinalizer=finalizers.callback)
            args = ({"fake_creds": owner.fake_creds.__wrapped__()} if name == CASES[0]
                    else {"monkeypatch": patch})
            with pytest.raises(error) as caught:
                namespace[name](request=request, **args)
            assert caught.value is failure
            assert reached == [stage]
            assert len(resources) == (2 if stage == "constructor" else allocation)
            assert all(path.is_dir() for path in resources)
        assert all(not path.exists() for path in resources)
        restored = dict(os.environ) == before_env
        assert restored and unchanged()
    finally:
        for path in resources:
            shutil.rmtree(path, ignore_errors=True)


@pytest.mark.parametrize("helper", ["_owned_dir", "_inproc_dir"])
def test_marker_lives_until_owning_request_finishes(helper, tmp_path):
    owner, namespace, resources, reached, _, unchanged = _bindings(tmp_path)
    try:
        with ExitStack() as finalizers:
            request = SimpleNamespace(addfinalizer=finalizers.callback)
            path = (namespace[helper]("raptor-llm-owned-", os.getpid(), request)
                    if helper == "_owned_dir" else namespace[helper](os.getpid(), request))
            assert path.is_dir()
            marker = json.loads((path / owner.OWNER_MARKER_NAME).read_text())
            assert marker["pid"] == os.getpid() and isinstance(marker["created"], float)
            assert not reached
        assert not path.exists() and unchanged()
    finally:
        for path in resources:
            shutil.rmtree(path, ignore_errors=True)

"""Filesystem fault injection leaves shared modules usable during the test."""
from functools import lru_cache
import importlib.machinery
import importlib.util
import inspect
import os
from pathlib import Path
import shutil
from types import ModuleType

import pytest

from core.testing.module_bindings import patch_module_attribute

_FILES = ['core/atomic_fs/tests/test_artifact_fd_cleanup.py', 'core/atomic_fs/tests/test_atomic_fs.py', 'core/atomic_fs/tests/test_cleanup_failures.py', 'core/atomic_fs/tests/test_fs_lock_bounded.py', 'core/atomic_fs/tests/test_fs_lock_required.py', 'core/annotations/tests/test_locking_bounded.py', 'core/project/tests/test_project_file_lock_bounded.py', 'core/run/tests/test_metadata_lock_bounded.py', 'core/dataflow/tests/test_pack_write_lock_bounded.py', 'core/coverage/tests/test_lock_bounded.py', 'core/inventory/tests/test_checklist_lock_bounded.py', 'core/threat_model/tests/test_model_write_lock_bounded.py', 'packages/binary_analysis/tests/test_artifact_lock_bounded.py', 'core/run/tests/test_safe_io.py']
_REPO = Path(__file__).resolve().parents[3]


@lru_cache(maxsize=None)
def _native_module(file):
    loader = importlib.machinery.SourceFileLoader(
        "owned_fs_probe_" + file.replace("/", "_").replace(".", "_"), str(_REPO / file))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


def _native_cases():
    cases = []
    for file in _FILES:
        module = _native_module(file)
        functions = [(name, fn) for name, fn in vars(module).items()
                     if name.startswith("test_") and inspect.isfunction(fn)]
        for name, cls in vars(module).items():
            if name.startswith("Test") and inspect.isclass(cls):
                functions.extend((name + "." + method, fn) for method, fn in vars(cls).items()
                                 if method.startswith("test_") and inspect.isfunction(fn))
        for name, function in functions:
            source = inspect.getsource(function)
            if not any(token in source for token in (
                    "patch_module_attribute(", "setattr(os,", "setattr(_os,",
                    "setattr(fs.shutil,", 'setattr(Path, "unlink"')):
                continue
            variants = [({}, [])]
            for mark in getattr(function, "pytestmark", []):
                if mark.name != "parametrize":
                    for _, marks in variants:
                        marks.append(mark)
                    continue
                names = mark.args[0]
                names = [part.strip() for part in names.split(",")] if isinstance(names, str) else names
                expanded = []
                for parameters, marks in variants:
                    for value in mark.args[1]:
                        values = value.values if hasattr(value, "values") and hasattr(value, "marks") else value
                        values = (values,) if len(names) == 1 and not hasattr(value, "marks") else values
                        extra = list(value.marks) if hasattr(value, "marks") else []
                        expanded.append(({**parameters, **dict(zip(names, values))}, marks + extra))
                variants = expanded
            for index, (parameters, marks) in enumerate(variants):
                cases.append(pytest.param((file, name, parameters), marks=marks,
                                          id=Path(file).stem + "-" + name + "-" + str(index)))
    return cases


def _snapshot():
    return [(owner, dict(vars(owner))) for owner in (os, shutil, Path)]


def _assert_shared(before):
    for owner, namespace in before:
        changed = [name for name, value in namespace.items()
                   if vars(owner).get(name) is not value]
        assert changed == [], f"shared {owner.__name__} attributes changed: {changed}"


@pytest.mark.parametrize("case", _native_cases())
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_native_fault_stays_on_consumer(request, case, exit_mode):
    file, name, parameters = case
    module = _native_module(file)
    if "." in name:
        cls, method = name.split(".")
        function = getattr(getattr(module, cls)(), method)
    else:
        function = getattr(module, name)
    before = _snapshot()

    class CheckedPatch(pytest.MonkeyPatch):
        def setattr(self, *args, **kwargs):
            super().setattr(*args, **kwargs)
            _assert_shared(before)

        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            _assert_shared(before)

    class OwnedError(Exception):
        pass

    error = {"error": OwnedError, "interrupt": KeyboardInterrupt}.get(exit_mode)
    caught = None
    try:
        with CheckedPatch.context() as scope:
            arguments = {name: parameters[name] if name in parameters
                         else scope if name == "monkeypatch"
                         else request.getfixturevalue(name)
                         for name in inspect.signature(function).parameters}
            function(**arguments)
            _assert_shared(before)
            if error is not None:
                raise error("owned scope exit")
    except BaseException as failure:
        caught = failure
    _assert_shared(before)
    if error is None:
        assert caught is None, repr(caught)
    else:
        assert isinstance(caught, error), repr(caught)
        assert str(caught) == "owned scope exit"


@pytest.mark.parametrize("lazy", [False, True], ids=["stored", "lazy"])
@pytest.mark.parametrize("exit_mode", ["normal", "error", "interrupt"])
def test_module_view_restores_exact_borrowed_binding(lazy, exit_mode):
    consumer = ModuleType("owned_consumer")
    if lazy:
        consumer.__getattr__ = lambda name: os if name == "os" else None
    else:
        consumer.os = os
    raw = dict(vars(consumer))
    before = _snapshot()
    caught = None
    try:
        with pytest.MonkeyPatch.context() as scope:
            first = patch_module_attribute(scope, consumer, "os", "getpid", lambda: 41)
            second = patch_module_attribute(scope, consumer, "os", "getppid", lambda: 42)
            assert isinstance(first, ModuleType) and isinstance(second, ModuleType)
            assert first is not os and second is not first
            assert consumer.os.getpid() == 41
            assert consumer.os.getppid() == 42
            assert consumer.os.O_RDONLY == os.O_RDONLY
            _assert_shared(before)
            if exit_mode != "normal":
                raise RuntimeError("owned failure") if exit_mode == "error" else KeyboardInterrupt("owned failure")
    except BaseException as error:
        caught = error
    assert vars(consumer) == raw
    assert consumer.os is os
    _assert_shared(before)
    assert caught is None if exit_mode == "normal" else isinstance(caught, RuntimeError if exit_mode == "error" else KeyboardInterrupt)


@pytest.mark.parametrize("error", [RuntimeError, KeyboardInterrupt])
def test_publication_failure_unwinds_through_real_monkeypatch(error):
    consumer = ModuleType("owned_consumer")
    consumer.os = os
    before = _snapshot()

    class InterruptedPublication(pytest.MonkeyPatch):
        def setitem(self, *args, **kwargs):
            super().setitem(*args, **kwargs)
            raise error("publication failed after assignment")

    with pytest.raises(error, match="publication failed"):
        with InterruptedPublication.context() as scope:
            patch_module_attribute(scope, consumer, "os", "getpid", lambda: 41)
    assert consumer.os is os
    _assert_shared(before)


def test_invalid_attribute_does_not_publish_consumer_view():
    consumer = ModuleType("owned_consumer")
    consumer.os = os
    with pytest.MonkeyPatch.context() as scope:
        with pytest.raises(AttributeError):
            patch_module_attribute(scope, consumer, "os", "_absent_test_attribute", object())
        assert consumer.os is os


def test_nonmodule_binding_is_rejected_without_mutation():
    consumer = ModuleType("owned_consumer")
    consumer.os = object()
    original = consumer.os
    with pytest.MonkeyPatch.context() as scope:
        with pytest.raises(TypeError, match="must be modules"):
            patch_module_attribute(scope, consumer, "os", "getpid", lambda: 41)
    assert consumer.os is original

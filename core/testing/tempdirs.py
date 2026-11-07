"""Fresh test state directories without pytest's numbered-directory scans."""
from __future__ import annotations

from pathlib import Path
from tempfile import mkdtemp
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import pytest


def isolated_test_dir(factory: pytest.TempPathFactory, prefix: str) -> Path:
    """Create private per-test state beneath the worker's retained basetemp.

    Numbered mktemp scans all siblings on every allocation. Autouse fixtures
    multiply that cost across large suites and also slow ordinary tmp_path
    allocations by filling their shared parent. Keep state under one parent
    and let mkdtemp choose an unused name without listing existing entries.
    """
    parent = factory.getbasetemp() / 'isolated-state'
    parent.mkdir(mode=0o700, exist_ok=True)
    return Path(mkdtemp(prefix=f'{prefix}-', dir=parent))


def private_tempfile_module(original=None):
    """Return real temporary-file factories with private lookup/cache state.

    Borrow current constants, caller overrides and temp-root selection. Rebind
    tempfile's Python functions, including a TemporaryDirectory constructor,
    so internal helpers read this view rather than the process-wide module.
    Returned directory objects remain genuine TemporaryDirectory instances.
    The caller owns publication through monkeypatch or another cleanup scope.
    """
    import tempfile
    import threading
    from types import FunctionType

    from core.testing.module_views import module_function_view

    original = tempfile if original is None else original
    private = module_function_view(original)
    namespace = vars(private)

    def rebind(function):
        clone = FunctionType(function.__code__, namespace, function.__name__, function.__defaults__, function.__closure__)
        clone.__kwdefaults__ = function.__kwdefaults__
        clone.__dict__.update(vars(function))
        clone.__doc__, clone.__module__, clone.__qualname__ = function.__doc__, function.__module__, function.__qualname__
        if getattr(function, "__annotate__", None) is not None:
            clone.__annotate__ = function.__annotate__
        else:
            clone.__annotations__ = function.__annotations__.copy()
        if hasattr(function, "__type_params__"):
            clone.__type_params__ = function.__type_params__
        return clone

    clones = {}
    for name, value in list(namespace.items()):
        if isinstance(value, FunctionType) and value.__module__ == tempfile.__name__ and value.__globals__ is not namespace:
            if id(value) not in clones:
                clones[id(value)] = rebind(value)
            namespace[name] = clones[id(value)]
    directory = private.TemporaryDirectory
    if isinstance(directory, type) and isinstance(directory.__init__, FunctionType) and directory.__init__.__module__ == tempfile.__name__:
        private.TemporaryDirectory = type(directory.__name__, (directory,), {
            "__init__": rebind(directory.__init__), "__module__": directory.__module__,
        })
    # File-name generation and its lazy-init lock belong to this view too.
    private._name_sequence = None
    private._once_lock = threading.Lock()
    return private

"""Keep incidental stdlib mocks on the module that consumes them."""
from contextlib import contextmanager
from types import ModuleType


def _private_binding(consumer, binding):
    """Build an unpublished copy of every module in a dotted binding."""
    try:
        borrowed = getattr(consumer, binding)
    except AttributeError:
        if "." not in binding:
            raise
        parts = binding.split(".")
        key = parts[0]
        borrowed = getattr(consumer, key)
    else:
        # scoped_function_imports owns literal keys such as "importlib.metadata".
        # Preserve those keys, including lazy ones, before interpreting a path.
        parts = [binding]
        key = binding
    current = consumer
    root = parent = None
    for index, part in enumerate(parts):
        if index:
            borrowed = getattr(current, part)
        if not isinstance(current, ModuleType) or not isinstance(borrowed, ModuleType):
            raise TypeError("consumer and borrowed binding must be modules")
        private = ModuleType(borrowed.__name__)
        vars(private).update(vars(borrowed))
        if parent is None:
            root = private
        else:
            vars(parent)[part] = private
        parent = private
        current = borrowed
    return key, root, private



def patch_module_attribute(monkeypatch, consumer, binding, name, value, *, raising=True):
    """Patch an attribute through a fresh consumer-local module namespace.

    A dotted binding such as ``os.path`` copies every module along that path.
    Existing literal bindings, including dotted import keys, take priority.
    Shallow copies retain real constants, exception classes and unmodified
    functions. Repeated patches copy the current view, keeping earlier mocks.
    The supplied monkeypatch owns publication and restores the exact original
    root binding, including absence when a module exposes a lazy binding.
    Build and validate the full private path before publishing any change.
    """
    key, root, private = _private_binding(consumer, binding)
    monkeypatch.setattr(private, name, value, raising=raising)
    # setitem registers the borrowed namespace entry before publication and
    # preserves raw absence rather than freezing a lazy __getattr__ result.
    monkeypatch.setitem(vars(consumer), key, root)
    return private


@contextmanager
def mock_module_attribute(consumer, binding, name, *args, **kwargs):
    """Yield a unittest mock through a private consumer module binding.

    Dotted bindings own each module in the selected path. Preserve
    patch.object's mock configuration and yielded object while restoring
    the borrowed root binding after normal, error or interrupt exits.
    """
    from pytest import MonkeyPatch
    from unittest.mock import patch

    with MonkeyPatch.context() as scope:
        key, root, private = _private_binding(consumer, binding)
        scope.setitem(vars(consumer), key, root)
        with patch.object(private, name, *args, **kwargs) as mocked:
            yield mocked

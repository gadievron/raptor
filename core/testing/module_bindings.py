"""Keep incidental stdlib mocks on the module that consumes them."""
from contextlib import contextmanager
from types import ModuleType


def patch_module_attribute(monkeypatch, consumer, binding, name, value, *, raising=True):
    """Patch an attribute through a fresh consumer-local module namespace.

    Shallow copies retain real constants, exception classes and unmodified
    functions. Repeated patches copy the current view, keeping earlier mocks.
    The supplied monkeypatch owns publication and restores the exact original
    binding, including absence when a module exposes a lazy binding.
    """
    original = getattr(consumer, binding)
    if not isinstance(consumer, ModuleType) or not isinstance(original, ModuleType):
        raise TypeError("consumer and borrowed binding must be modules")
    private = ModuleType(original.__name__)
    vars(private).update(vars(original))
    monkeypatch.setattr(private, name, value, raising=raising)
    # setitem registers the borrowed namespace entry before publication and
    # preserves raw absence rather than freezing a lazy __getattr__ result.
    monkeypatch.setitem(vars(consumer), binding, private)
    return private


@contextmanager
def mock_module_attribute(consumer, binding, name, *args, **kwargs):
    """Yield a unittest mock through a private consumer module binding.

    Preserve patch.object's mock configuration and yielded object while
    restoring the borrowed binding after normal, error or interrupt exits.
    """
    from pytest import MonkeyPatch
    from unittest.mock import patch

    with MonkeyPatch.context() as scope:
        borrowed = getattr(consumer, binding)
        private = patch_module_attribute(
            scope, consumer, binding, "__name__", borrowed.__name__,
        )
        with patch.object(private, name, *args, **kwargs) as mocked:
            yield mocked

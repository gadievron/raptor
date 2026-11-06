"""Keep incidental stdlib mocks on the module that consumes them."""
from types import ModuleType


def patch_module_attribute(monkeypatch, consumer, binding, name, value):
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
    monkeypatch.setattr(private, name, value)
    # setitem registers the borrowed namespace entry before publication and
    # preserves raw absence rather than freezing a lazy __getattr__ result.
    monkeypatch.setitem(vars(consumer), binding, private)
    return private

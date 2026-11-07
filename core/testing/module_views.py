"""Private function globals for tests that exercise local imports or helpers."""

import builtins
from types import FunctionType, ModuleType


def module_function_view(module, *, bindings=None, import_hook=None):
    """Copy a module and rebind its Python functions to the copied globals.

    Functions defined in this namespace retain their code, defaults, closures
    and metadata. Aliases share one cloned function. Foreign functions and
    classes retain their identities; mutable globals are shallow borrowed
    values unless replaced explicitly in bindings. This is a lookup seam,
    not an independent import or a deep copy of module state.

    An optional import hook belongs only to the cloned functions' builtins.
    Publish the view through monkeypatch or a context manager at its owner.
    No shared module, function globals, builtins or sys.modules are changed.
    """
    if not isinstance(module, ModuleType):
        raise TypeError("module must be a module")
    private = ModuleType(module.__name__)
    namespace = vars(private)
    namespace.update(vars(module))
    namespace.update(bindings or {})
    if import_hook is not None:
        inherited = namespace.get("__builtins__", builtins)
        namespace["__builtins__"] = dict(
            vars(inherited) if isinstance(inherited, ModuleType) else inherited,
            __import__=import_hook,
        )
    clones = {}
    for name, value in list(namespace.items()):
        if not isinstance(value, FunctionType) or value.__globals__ is not vars(module):
            continue
        if id(value) not in clones:
            clone = FunctionType(value.__code__, namespace, value.__name__, value.__defaults__, value.__closure__)
            clone.__kwdefaults__ = value.__kwdefaults__
            if getattr(value, "__annotate__", None) is not None:
                clone.__annotate__ = value.__annotate__
            else:
                clone.__annotations__ = value.__annotations__.copy()
            clone.__dict__.update(vars(value))
            clone.__doc__ = value.__doc__
            clone.__module__ = value.__module__
            clone.__qualname__ = value.__qualname__
            if hasattr(value, "__type_params__"):
                clone.__type_params__ = value.__type_params__
            clones[id(value)] = clone
        namespace[name] = clones[id(value)]
    return private

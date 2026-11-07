"""Private function graphs preserve execution semantics and borrowed state."""
import builtins
import inspect
from types import ModuleType

import pytest

from core.testing.module_views import module_function_view


@pytest.mark.parametrize("builtins_shape", ["module", "dict", "absent"])
@pytest.mark.parametrize("import_style", ["plain", "from", "relative"])
@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_function_graph_keeps_local_imports_private(builtins_shape, import_style, outcome):
    owner = ModuleType("owned_view_source")
    owner.__package__ = "owned_view_package"
    source = {
        "plain": "import os\n    return os.getpid()",
        "from": "from os import getpid\n    return getpid()",
        "relative": "from .dependency import getpid\n    return getpid()",
    }[import_style]
    exec("def lookup():\n    " + source + "\ndef caller(value=17, *, named=23):\n    return lookup(), value, named\nalias = caller\n", vars(owner))
    owner.caller.marker = object()
    if builtins_shape == "module":
        owner.__builtins__ = builtins
    elif builtins_shape == "dict":
        owner.__builtins__ = vars(builtins).copy()
    else:
        del owner.__builtins__
    before = vars(owner).copy()
    real_import = builtins.__import__
    seen = []
    dependency = ModuleType("owned_dependency")
    dependency.getpid = lambda: 424242

    def imported(name, globals=None, locals=None, fromlist=(), level=0):
        seen.append((name, tuple(fromlist or ()), level))
        return dependency

    view = module_function_view(owner, import_hook=imported)
    assert view.caller is view.alias
    assert view.caller.__code__ is owner.caller.__code__
    assert view.caller.__defaults__ is owner.caller.__defaults__
    assert view.caller.__kwdefaults__ is owner.caller.__kwdefaults__
    assert view.caller.marker is owner.caller.marker
    assert inspect.signature(view.caller) == inspect.signature(owner.caller)
    failure = RuntimeError("owned lookup") if outcome == "error" else KeyboardInterrupt("owned lookup")
    try:
        assert view.caller(named=29) == (424242, 17, 29)
        assert len(seen) == 1
        if outcome != "normal":
            raise failure
    except BaseException as error:
        assert outcome != "normal" and error is failure
    assert vars(owner).keys() == before.keys()
    assert all(vars(owner)[key] is value for key, value in before.items())
    assert builtins.__import__ is real_import
    assert view.lookup.__globals__ is vars(view)
    assert view.caller.__globals__ is vars(view)


@pytest.mark.parametrize("outcome", ["normal", "error", "interrupt"])
def test_closures_foreign_functions_and_explicit_state(outcome):
    import os

    owner = ModuleType("owned_closure_source")
    exec("cache = {'borrowed': 1}\ndef factory(value):\n    def inner(*, suffix=3):\n        return value, cache, suffix\n    return inner\nclosure = factory(11)\n", vars(owner))
    owner.foreign = os.walk
    owner.foreign_class = dict
    before = owner.cache.copy()
    private_cache = {}
    view = module_function_view(owner, bindings={"cache": private_cache})
    assert view.foreign is os.walk and view.foreign_class is dict
    assert view.closure.__closure__ is owner.closure.__closure__
    assert view.closure()[0] == 11 and view.closure()[1] is private_cache
    assert owner.closure()[1] is owner.cache
    failure = RuntimeError("closure") if outcome == "error" else KeyboardInterrupt("closure")
    try:
        view.closure()[1]["owned"] = 2
        if outcome != "normal":
            raise failure
    except BaseException as error:
        assert outcome != "normal" and error is failure
    assert owner.cache == before
    assert private_cache == {"owned": 2}


@pytest.mark.parametrize("invalid", [None, {}, object(), 1])
def test_non_module_input_is_refused(invalid):
    with pytest.raises(TypeError, match="must be a module"):
        module_function_view(invalid)


def test_lazy_annotations_are_not_evaluated_while_copying():
    owner = ModuleType("owned_annotation_source")
    exec("calls = []\ndef annotation():\n    calls.append('evaluated')\n    return int\ndef function(value: annotation()):\n    return value\n", vars(owner))
    if getattr(owner.function, "__annotate__", None) is None:
        pytest.skip("interpreter does not provide lazy function annotations")
    assert owner.calls == []
    view = module_function_view(owner)
    assert owner.calls == []
    assert view.function.__annotate__ is owner.function.__annotate__
    assert view.function.__annotations__ == {"value": int}
    assert owner.calls == ["evaluated"]

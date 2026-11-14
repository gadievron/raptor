"""Type aliases bind ordinary names while their RHS remains deferred."""
import ast

from core.analysis.python_module_callgraph import (
    _module_rebound_names,
    local_binding_names,
    module_distrusted_roots,
)


def test_type_alias_names_are_bindings_in_their_own_scope():
    source = (
        "import html\n"
        "type html = str\n"
        "def handle():\n"
        "    type escape = str\n"
        "    return escape\n"
    )
    namespace = {}
    exec(compile(source, "owned_alias_bindings.py", "exec"), namespace)
    assert namespace["html"].__name__ == "html"
    assert "escape" in namespace["handle"].__code__.co_varnames
    tree = ast.parse(source)
    assert "escape" in local_binding_names(tree.body[2])
    assert "html" in module_distrusted_roots(tree)
    assert "html" in _module_rebound_names(tree)
    assert "escape" not in module_distrusted_roots(tree)


def test_alias_type_parameters_do_not_bind_the_enclosing_scope():
    tree = ast.parse("def handle():\n    type Alias[T] = list[T]\n    return Alias\n")
    assert local_binding_names(tree.body[0]) == frozenset({"Alias"})
    ordinary = ast.parse("import html\ndef handle():\n    return html.escape('safe')\n")
    assert "html" not in module_distrusted_roots(ordinary)
    assert local_binding_names(ordinary.body[1]) == frozenset()

"""Executed class namespaces need a value-transfer model for summaries."""

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<class-namespace-value>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def test_class_attribute_retaining_input_refuses_a_known_summary():
    result = summaries(
        "def handle(raw):\n    class Record:\n        value = raw\n    return Record.value\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "class namespace value transfer is not modelled"


def test_class_value_helper_wrapper_keeps_input_flow():
    result = summaries(
        "def helper(raw):\n    class Record:\n        value = raw\n    return Record.value\n"
        "def handle(raw):\n    return helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)


def test_unused_constant_local_class_is_conservatively_unknown():
    result = summaries(
        "def handle(raw):\n    class Record:\n        value = 0\n    return raw\n"
    )["handle"]
    assert result.summary_unknown


def test_class_in_unused_nested_function_does_not_poison_outer_frame():
    result = summaries(
        "def handle(raw):\n    def nested():\n        class Record:\n            value = raw\n"
        "        return Record.value\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_module_class_method_keeps_existing_direct_flow():
    result = summaries("class Container:\n    def handle(self, raw):\n        return raw\n")["Container.handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(1)

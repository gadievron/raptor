"""Named exception objects require exceptional value-flow modelling."""

import pytest

from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def summaries(source):
    compile(source, "<exception-payload-fixture>", "exec")
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


@pytest.mark.parametrize("handler", ["except ValueError as err:", "except Exception as err:"])
def test_caught_exception_text_refuses_a_known_summary(handler):
    result = summaries(
        "def handle(raw):\n    try:\n        raise ValueError(raw)\n"
        f"    {handler}\n        return str(err)\n"
    )["handle"]
    assert result.summary_unknown
    assert result.summary_unknown_reason == "caught exception payload is not modelled"


def test_named_exception_group_handler_also_refuses():
    result = summaries(
        "def handle(raw):\n    try:\n        process(raw)\n"
        "    except* ValueError as errors:\n        rendered = str(errors)\n"
        "    return raw\n"
    )["handle"]
    assert result.summary_unknown


def test_unknown_exception_summary_keeps_wrapper_input_flow():
    result = summaries(
        "def helper(raw):\n    try:\n        raise ValueError(raw)\n"
        "    except ValueError as err:\n        return str(err)\n"
        "def handle(raw):\n    return helper(raw)\n"
    )
    assert result["helper"].summary_unknown
    assert result["handle"].param_taints_return(0)


def test_unbound_handler_keeps_existing_direct_input_flow():
    result = summaries(
        "def handle(raw):\n    try:\n        process(raw)\n"
        "    except ValueError:\n        pass\n    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)


def test_nested_handler_binding_does_not_poison_outer_frame():
    result = summaries(
        "def handle(raw):\n    def nested():\n        try:\n            process()\n"
        "        except ValueError as err:\n            return str(err)\n"
        "    return raw\n"
    )["handle"]
    assert not result.summary_unknown
    assert result.param_taints_return(0)

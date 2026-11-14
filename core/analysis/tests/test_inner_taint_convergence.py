"""One CFG node can contain more taint states than the node-based budget."""

import ast

from core.analysis.cfg_builder import _PythonCFGBuilder
from core.analysis.interproc import _param_cleanly_sanitized
from core.analysis.python_module_callgraph import build_python_module_callgraph
from core.analysis.taint_summaries import build_taint_summaries


def loop_source(size):
    names = [f"v{i:03d}" for i in range(size)]

    def source(values, returned):
        return (
            "import html\ndef handle(raw, count):\n    "
            + " = ".join(names) + " = 0\n    while count:\n        ("
            + ", ".join(f"({name} := {values[name]})" for name in names)
            + ")\n        count -= 1\n    return html.escape(raw) + " + returned + "\n"
        )

    scaffold = source(dict.fromkeys(names, "0"), names[0])
    cfg = _PythonCFGBuilder("handle", "owned.py").build(ast.parse(scaffold).body[1])
    body = next(node for node in cfg.nodes() if node.lineno == 5)
    order = list(body.defs)
    assert set(order) == set(names)
    # Keep target order fixed, but make each definition depend on one
    # processed later in this process's frozenset order. This needs one
    # backwards propagation step per pass, independent of hash seed.
    values = {order[i]: order[i + 1] for i in range(len(order) - 1)}
    values[order[-1]] = "raw"
    result = source(values, order[0])
    final_cfg = _PythonCFGBuilder("handle", "owned.py").build(ast.parse(result).body[1])
    assert list(next(n for n in final_cfg.nodes() if n.lineno == 5).defs) == order
    compile(result, "<inner-taint-budget>", "exec")
    return result


def summaries(source):
    graph = build_python_module_callgraph(source)
    assert graph is not None
    return build_taint_summaries(graph, source)


def test_inner_budget_exhaustion_qualifies_partial_effects():
    result = summaries(loop_source(128))["handle"]
    assert not result.summary_unknown
    assert result.summary_unconverged
    assert (0, "html.escape", 0) in result.return_effects
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_unconverged_callee_cannot_erase_wrapper_argument_flow():
    result = summaries(
        loop_source(128)
        + "def wrapper(raw, count):\n    return html.escape(raw) + handle(raw, count)\n"
    )
    assert result["handle"].summary_unconverged
    wrapper = result["wrapper"]
    assert not wrapper.summary_unconverged
    assert wrapper.param_taints_return(0)
    assert any(pi == 0 and name == "<shadowed:handle>" for pi, name, _ in wrapper.return_effects)
    assert not _param_cleanly_sanitized(wrapper, 0, {"html.escape"})


def test_small_loop_still_converges_with_direct_raw_flow():
    result = summaries(loop_source(4))["handle"]
    assert not result.summary_unknown
    assert not result.summary_unconverged
    assert (0, "", -1) in result.return_effects
    assert not _param_cleanly_sanitized(result, 0, {"html.escape"})


def test_complete_sanitizer_summary_keeps_existing_precision():
    result = summaries("import html\ndef handle(raw):\n    return html.escape(raw)\n")["handle"]
    assert not result.summary_unconverged
    assert _param_cleanly_sanitized(result, 0, {"html.escape"})

"""Phase 13 — per-function taint summary tests."""
from __future__ import annotations

from core.inventory.callgraph import (
    build_python_module_callgraph,
)
from core.inventory.taint_summaries import (
    build_taint_summaries,
)


def _summaries(src: str):
    cg = build_python_module_callgraph(src)
    assert cg is not None
    return cg, build_taint_summaries(cg, src)


# ---------------------------------------------------------------------------
# Identity, transform, branching
# ---------------------------------------------------------------------------


class TestPrimitives:
    def test_identity_function(self):
        _, summaries = _summaries("def f(x):\n    return x\n")
        s = summaries["f"]
        assert s.param_taints_return(0)
        # Direct return — no callable in the chain
        assert s.return_sanitizers_for_param(0) == frozenset()

    def test_no_param_taints_when_return_is_constant(self):
        _, summaries = _summaries("def f(x):\n    return 1\n")
        s = summaries["f"]
        assert not s.param_taints_return(0)

    def test_transform_records_callable_in_chain(self):
        _, summaries = _summaries(
            "def f(x):\n    return html.escape(x)\n"
        )
        s = summaries["f"]
        assert s.param_taints_return(0)
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)

    def test_branching_both_paths_recorded(self):
        _, summaries = _summaries(
            "def f(x, cond):\n"
            "    if cond:\n"
            "        return html.escape(x)\n"
            "    else:\n"
            "        return x\n"
        )
        s = summaries["f"]
        # Param 0 (x) taints return via two paths: direct and via html.escape
        assert s.param_taints_return(0)
        sanitizers = s.return_sanitizers_for_param(0)
        # ``html.escape, arg 0`` is one of them; the direct path is
        # captured implicitly by the empty-effect atom contributing
        # to param_taints_return without surfacing in the
        # sanitizer-set helper.
        assert ("html.escape", 0) in sanitizers

    def test_param_does_not_taint_return_when_unused(self):
        _, summaries = _summaries(
            "def f(x, y):\n    return y\n"
        )
        s = summaries["f"]
        assert not s.param_taints_return(0)
        assert s.param_taints_return(1)

    def test_intermediate_assignment_preserves_taint(self):
        _, summaries = _summaries(
            "def f(x):\n"
            "    y = x\n"
            "    return y\n"
        )
        s = summaries["f"]
        assert s.param_taints_return(0)


# ---------------------------------------------------------------------------
# call_arg_taint — flows into call arguments
# ---------------------------------------------------------------------------


class TestCallArgTaint:
    def test_taint_flows_into_external_call_arg(self):
        _, summaries = _summaries(
            "def f(x):\n"
            "    render(x)\n"
        )
        s = summaries["f"]
        # render's arg 0 (lexicographic sort: 'x' is the only arg) is
        # tainted by param 0.
        assert 0 in s.params_tainting_call_arg("render", 0)

    def test_taint_via_intermediate_variable(self):
        _, summaries = _summaries(
            "def f(x):\n"
            "    y = x\n"
            "    render(y)\n"
        )
        s = summaries["f"]
        assert 0 in s.params_tainting_call_arg("render", 0)

    def test_untainted_arg_not_recorded(self):
        _, summaries = _summaries(
            "def f(x, y):\n"
            "    render(y)\n"
        )
        s = summaries["f"]
        assert s.params_tainting_call_arg("render", 0) == frozenset({1})
        assert 0 not in s.params_tainting_call_arg("render", 0)


# ---------------------------------------------------------------------------
# Inter-procedural — helper functions resolved via call graph
# ---------------------------------------------------------------------------


class TestInterprocedural:
    def test_helper_return_propagates_taint(self):
        """The sanitizer-in-helper shape from the Python corpus.

        helper(x) returns html.escape(x). caller(x) does y =
        helper(x); render(y). caller's summary should show that
        param 0's taint reaches render's arg 0 via html.escape —
        which Phase 14's gate will detect as a sanitizer-for-CWE-79
        match."""
        _, summaries = _summaries(
            "def helper(s):\n"
            "    return html.escape(s)\n"
            "def caller(x):\n"
            "    y = helper(x)\n"
            "    render(y)\n"
        )
        helper = summaries["helper"]
        caller = summaries["caller"]
        # helper records (param 0, html.escape, 0)
        assert ("html.escape", 0) in helper.return_sanitizers_for_param(0)
        # caller's param 0 reaches render's arg 0 — and the chain
        # should include both helper@arg0 and html.escape@arg0
        # because helper's return-effect was stamped into caller's
        # y.
        render_arg_params = caller.params_tainting_call_arg("render", 0)
        assert 0 in render_arg_params

    def test_helper_passthrough_no_effect(self):
        """Helper that returns its arg unchanged — caller's param
        taint reaches the sink with no sanitizer in the chain."""
        _, summaries = _summaries(
            "def passthrough(s):\n"
            "    return s\n"
            "def caller(x):\n"
            "    y = passthrough(x)\n"
            "    render(y)\n"
        )
        caller = summaries["caller"]
        assert 0 in caller.params_tainting_call_arg("render", 0)

    def test_two_param_helper_picks_right_param(self):
        """``helper(a, b): return html.escape(b)`` — caller's
        param taint must follow the b-channel, not the a-channel."""
        _, summaries = _summaries(
            "def helper(a, b):\n"
            "    return html.escape(b)\n"
            "def caller(x, y):\n"
            "    z = helper(x, y)\n"
            "    render(z)\n"
        )
        helper = summaries["helper"]
        caller = summaries["caller"]
        assert not helper.param_taints_return(0)
        assert helper.param_taints_return(1)
        # caller param 1 (y) reaches render via z
        assert 1 in caller.params_tainting_call_arg("render", 0)


# ---------------------------------------------------------------------------
# Cycles — recursion and mutual recursion
# ---------------------------------------------------------------------------


class TestCycles:
    def test_recursion_converges(self):
        """A self-recursive identity converges to the same fixed
        point as a plain identity: param taints return."""
        _, summaries = _summaries(
            "def f(n):\n"
            "    if n <= 0:\n"
            "        return n\n"
            "    return f(n - 1)\n"
        )
        s = summaries["f"]
        # Whether base case is reached or recurses, param 0 taints
        # return.
        assert s.param_taints_return(0)
        assert s.summary_unconverged is False

    def test_mutual_recursion_does_not_crash(self):
        """f calls g, g calls f. Convergence isn't guaranteed in
        general but the builder must terminate."""
        _, summaries = _summaries(
            "def f(x):\n"
            "    if x:\n"
            "        return g(x)\n"
            "    return x\n"
            "def g(y):\n"
            "    if y:\n"
            "        return f(y)\n"
            "    return y\n"
        )
        # Just assert both summaries exist and we didn't hang.
        assert "f" in summaries
        assert "g" in summaries


# ---------------------------------------------------------------------------
# summary_unknown — dynamic dispatch
# ---------------------------------------------------------------------------


class TestSummaryUnknown:
    def test_getattr_call_marks_unknown(self):
        _, summaries = _summaries(
            "def f(o, name, x):\n"
            "    return getattr(o, name)(x)\n"
        )
        s = summaries["f"]
        assert s.summary_unknown
        assert "getattr" in s.summary_unknown_reason

    def test_eval_call_marks_unknown(self):
        _, summaries = _summaries(
            "def f(code):\n"
            "    return eval(code)\n"
        )
        s = summaries["f"]
        assert s.summary_unknown
        assert "eval" in s.summary_unknown_reason

    def test_exec_call_marks_unknown(self):
        _, summaries = _summaries(
            "def f(code):\n"
            "    exec(code)\n"
            "    return None\n"
        )
        assert summaries["f"].summary_unknown

    def test_kwargs_forwarding_marks_unknown(self):
        _, summaries = _summaries(
            "def f(**kwargs):\n"
            "    return g(**kwargs)\n"
        )
        assert summaries["f"].summary_unknown
        assert "kwargs" in summaries["f"].summary_unknown_reason

    def test_nested_dynamic_does_not_poison_outer(self):
        """A nested function with dynamic dispatch doesn't infect
        the outer function's summary."""
        _, summaries = _summaries(
            "def outer(x):\n"
            "    def inner(o, name):\n"
            "        return getattr(o, name)\n"
            "    return x\n"
        )
        outer = summaries["outer"]
        inner = summaries["outer.inner"]
        assert outer.summary_unknown is False
        assert inner.summary_unknown is True

    def test_normal_function_is_not_unknown(self):
        _, summaries = _summaries(
            "def f(x):\n    return x + 1\n"
        )
        assert summaries["f"].summary_unknown is False


# ---------------------------------------------------------------------------
# Coverage of all in-module functions; module entry not summarised
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_all_in_module_functions_summarised(self):
        _, summaries = _summaries(
            "def a(): pass\n"
            "def b(): pass\n"
            "class C:\n"
            "    def m(self): pass\n"
        )
        assert {"a", "b", "C.m"} <= set(summaries.keys())

    def test_module_entry_not_in_summaries(self):
        _, summaries = _summaries("def f(): pass\n")
        assert "<module>" not in summaries

    def test_lambda_summary_is_unknown(self):
        """A named lambda gets a summary but it's marked
        unknown (the AST shape isn't a FunctionDef so the CFG
        builder doesn't apply)."""
        _, summaries = _summaries(
            "compute = lambda x: x + 1\n"
        )
        assert "compute" in summaries
        assert summaries["compute"].summary_unknown

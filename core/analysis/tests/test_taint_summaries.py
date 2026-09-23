"""Phase 13 — per-function taint summary tests."""
from __future__ import annotations

import inspect
from pathlib import Path

from core.analysis.python_module_callgraph import (
    build_python_module_callgraph,
)
from core.analysis.taint_summaries import (
    _compute_one_summary,
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
# Merge soundness — the direct-return sentinel is absorbing (U09-F21)
# ---------------------------------------------------------------------------


class TestMergeSentinelAbsorbing:
    """The per-param effect-chain union must never absorb the empty
    chain: it is the "reached here unsanitized" sentinel Phase 14's
    clean-sanitizer check keys on. Pre-fix, ``escape(x) + x`` merged
    the raw pass-through atom into the sanitized chain and the helper
    read as a clean sanitizer wrapper — the ENFORCED sanitizer-cut
    then suppressed real findings routed through it."""

    def test_mixed_same_param_expression_keeps_direct_sentinel(self):
        _, summaries = _summaries(
            "def h(x):\n"
            "    return html.escape(x) + x\n"
        )
        s = summaries["h"]
        assert s.param_taints_return(0)
        # Both the sanitized chain AND the direct pass-through must
        # be recorded — the sentinel is ("", -1).
        assert (0, "", -1) in s.return_effects
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)

    def test_branch_join_single_return_keeps_direct_sentinel(self):
        # Same collapse class at the reaching-defs join: sanitize on
        # one branch, return the joined variable. Unlike the
        # two-return variant (collected per return), this joins
        # states through _merge_states before collection.
        _, summaries = _summaries(
            "def h(s):\n"
            "    if len(s) > 3:\n"
            "        s = html.escape(s)\n"
            "    return s\n"
        )
        s = summaries["h"]
        assert (0, "", -1) in s.return_effects
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)

    def test_downstream_call_stamps_all_merged_atoms(self):
        # After the mixed expression flows through a further callable,
        # the direct path is no longer direct: every surviving chain
        # carries the downstream callable, and the sentinel is gone.
        _, summaries = _summaries(
            "def h(x):\n"
            "    t = html.escape(x) + x\n"
            "    return clean(t)\n"
        )
        s = summaries["h"]
        assert (0, "", -1) not in s.return_effects
        assert ("clean", 0) in s.return_sanitizers_for_param(0)

    def test_merge_states_unit(self):
        from core.analysis.taint_summaries import _merge_states
        chain = frozenset([("html.escape", 0)])
        a = frozenset([(0, chain)])
        b = frozenset([(0, frozenset())])
        merged = _merge_states(a, b)
        assert (0, frozenset()) in merged
        assert (0, chain) in merged
        # Non-empty chains for the same param still union (the
        # over-approximation the consumer's all()-check tolerates).
        c = frozenset([(0, frozenset([("other", 1)]))])
        merged2 = _merge_states(a, c)
        assert merged2 == frozenset(
            [(0, chain | frozenset([("other", 1)]))]
        )


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

    def test_global_declaration_marks_unknown(self):
        # ``tmp`` binds the MODULE slot: ``other()`` can rewrite it
        # between the tracked assignment and the return, so the
        # straight-line-locals premise is void — a clean-sanitizer
        # summary here suppressed a live flow end-to-end.
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    global tmp\n"
            "    tmp = html.escape(s)\n"
            "    other()\n"
            "    return tmp\n"
        )
        s = summaries["_clean"]
        assert s.summary_unknown
        assert "global" in s.summary_unknown_reason

    def test_nonlocal_declaration_marks_unknown(self):
        _, summaries = _summaries(
            "def outer():\n"
            "    tmp = ''\n"
            "    def _clean(s):\n"
            "        nonlocal tmp\n"
            "        tmp = html.escape(s)\n"
            "        other()\n"
            "        return tmp\n"
            "    return _clean\n"
        )
        s = summaries["outer._clean"]
        assert s.summary_unknown
        assert "nonlocal" in s.summary_unknown_reason

    def test_nested_def_global_does_not_poison_outer(self):
        _, summaries = _summaries(
            "def outer(s):\n"
            "    def inner():\n"
            "        global tmp\n"
            "        tmp = 1\n"
            "    return html.escape(s)\n"
        )
        assert summaries["outer"].summary_unknown is False
        assert summaries["outer.inner"].summary_unknown is True

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


# ---------------------------------------------------------------------------
# The ``source`` argument is compatibility-only — never read
# ---------------------------------------------------------------------------


SANITIZER_HELPER_SRC = (
    "def helper(v):\n"
    "    return html.escape(v)\n"
    "\n"
    "def handle(x):\n"
    "    y = helper(x)\n"
    "    return y\n"
)


class TestDeadSourceTextRemoved:
    """AST and file path both come from the call graph;
    ``build_taint_summaries``'s ``source`` argument is
    compatibility-only and never read."""

    def test_compute_one_summary_has_no_source_text_param(self):
        params = inspect.signature(_compute_one_summary).parameters
        assert "source_text" not in params

    def test_source_argument_not_read(self):
        # A Path that does not exist proves the argument is never
        # dereferenced (it used to be read_text'd and discarded).
        cg = build_python_module_callgraph(SANITIZER_HELPER_SRC)
        assert cg is not None
        summaries = build_taint_summaries(
            cg, Path("/nonexistent/taint-summaries.py"),
        )
        assert "handle" in summaries

    def test_summaries_behaviour_unchanged(self):
        _, summaries = _summaries(SANITIZER_HELPER_SRC)
        helper = summaries["helper"]
        assert helper.param_taints_return(0)
        assert ("html.escape", 0) in helper.return_sanitizers_for_param(0)
        handle = summaries["handle"]
        assert handle.param_taints_return(0)


class TestFormatForContext:
    """The audit context renderer duck-types callee summaries on
    format_for_context — TaintSummary must satisfy the contract."""

    def _summary(self, **kw):
        from core.analysis.taint_summaries import TaintSummary
        base = dict(
            function="helper",
            params=("data", "size"),
            return_effects=frozenset({(0, "", -1), (0, "clean", 0)}),
            call_arg_taint=frozenset({("os.system", 0, 0)}),
        )
        base.update(kw)
        return TaintSummary(**base)

    def test_oneline_names_tainting_params(self):
        text = self._summary().format_for_context("oneline")
        assert text.startswith("`helper()`:")
        assert "`data`" in text
        assert "taint return" in text
        assert "1 call-arg propagation" in text

    def test_full_renders_via_callables_and_call_args(self):
        text = self._summary().format_for_context("full")
        assert "Taint summary: `helper()`" in text
        assert "`data` taints the return value via `clean`" in text
        assert "`data` → `os.system()` arg #0" in text

    def test_full_empty_summary_renders_nothing(self):
        s = self._summary(
            return_effects=frozenset(), call_arg_taint=frozenset(),
        )
        assert s.format_for_context("full") == ""

    def test_caveats_surface_in_both_depths(self):
        s = self._summary(
            summary_unknown=True, summary_unknown_reason="calls getattr",
        )
        assert "summary unknown (calls getattr)" in s.format_for_context("oneline")
        assert "caveat: summary unknown (calls getattr)" in s.format_for_context("full")

    def test_out_of_range_param_index_degrades(self):
        s = self._summary(return_effects=frozenset({(7, "", -1)}))
        assert "`arg7`" in s.format_for_context("oneline")


class TestAugmentedAssignKeepsEstablishedTaint:
    """``q += rhs`` reads q too — the pre-assignment state must
    survive the augmented write. Erasing it makes a param read as
    "does not taint return", which the sanitizer-cut consumer can
    turn into a false clean-wrapper binding (suppression of a real
    finding via the unsanitized-symbol check)."""

    def test_aug_assign_with_literal_keeps_sanitized_chain(self):
        _, summaries = _summaries(
            "def f(a):\n"
            "    q = escape(a)\n"
            "    q += 'suffix'\n"
            "    return q\n"
        )
        s = summaries["f"]
        assert s.param_taints_return(0)
        assert ("escape", 0) in s.return_sanitizers_for_param(0)

    def test_aug_assign_with_name_unions_both_flows(self):
        _, summaries = _summaries(
            "def f(a, b):\n"
            "    q = escape(a)\n"
            "    q += b\n"
            "    return q\n"
        )
        s = summaries["f"]
        assert ("escape", 0) in s.return_sanitizers_for_param(0)
        # b reaches the return directly (no sanitizer chain)
        assert (1, "", -1) in s.return_effects

    def test_plain_reassign_still_kills_prior_taint(self):
        # Direction check: a NON-augmented rewrite must keep killing
        # the old state — only ``+=`` unions the target's own IN.
        _, summaries = _summaries(
            "def f(a):\n"
            "    q = a\n"
            "    q = 'constant'\n"
            "    return q\n"
        )
        assert not summaries["f"].param_taints_return(0)


class TestFStringCarriesTaint:
    def test_fstring_interpolation_is_direct_flow(self):
        _, summaries = _summaries(
            "def f(a):\n"
            "    return f'<{a}>'\n"
        )
        s = summaries["f"]
        assert s.param_taints_return(0)
        assert (0, "", -1) in s.return_effects

    def test_mixed_sanitized_and_fstring_param_stays_dirty(self):
        # The false clean-wrapper scenario: b's f-string flow must
        # not vanish while a's sanitized flow is recorded.
        _, summaries = _summaries(
            "def f(a, b):\n"
            "    return escape(a) + f'<{b}>'\n"
        )
        s = summaries["f"]
        assert ("escape", 0) in s.return_sanitizers_for_param(0)
        assert (1, "", -1) in s.return_effects

    def test_fstring_without_interpolation_carries_nothing(self):
        _, summaries = _summaries(
            "def f(a):\n"
            "    return f'static'\n"
        )
        assert not summaries["f"].param_taints_return(0)


class TestKeywordAndStarredArgs:
    def test_external_keyword_arg_survives_with_opaque_position(self):
        from core.analysis.taint_summaries import _OPAQUE_ARG
        _, summaries = _summaries(
            "def f(a):\n"
            "    return inner(data=a)\n"
        )
        s = summaries["f"]
        assert s.param_taints_return(0)
        assert (0, "inner", _OPAQUE_ARG) in s.return_effects

    def test_in_module_keyword_maps_to_named_param(self):
        _, summaries = _summaries(
            "def ident(x):\n"
            "    return x\n"
            "def f(a):\n"
            "    return ident(x=a)\n"
        )
        s = summaries["f"]
        # Mapped through the callee summary: direct passthrough.
        assert (0, "", -1) in s.return_effects

    def test_starred_arg_taint_survives_opaque(self):
        from core.analysis.taint_summaries import _OPAQUE_ARG
        _, summaries = _summaries(
            "def f(a):\n"
            "    return joiner(*a)\n"
        )
        assert (0, "joiner", _OPAQUE_ARG) in summaries["f"].return_effects

    def test_positions_after_star_go_opaque(self):
        from core.analysis.taint_summaries import _OPAQUE_ARG
        _, summaries = _summaries(
            "def f(a, b):\n"
            "    return fmt(*a, b)\n"
        )
        s = summaries["f"]
        # b's real position is unknowable after the unpack — it must
        # NOT be stamped at a trusted concrete index.
        assert (1, "fmt", _OPAQUE_ARG) in s.return_effects
        assert all(
            not (pi == 1 and c == "fmt" and ai >= 0)
            for pi, c, ai in s.return_effects
        )

    def test_positional_args_still_map_by_index(self):
        # Direction check: without keywords/stars the concrete
        # positional stamping is unchanged.
        _, summaries = _summaries(
            "def f(a):\n"
            "    return clean(a)\n"
        )
        assert (0, "clean", 0) in summaries["f"].return_effects


class TestDirtySiblingShapesStayDirty:
    """A wrapper mixing a sanitized flow with a dirty sibling flow of
    the SAME param must never read as cleanly sanitized — dropping the
    sibling atom mints a false clean-sanitizer binding the enforced
    sanitizer-cut consumes to suppress real findings (the JoinedStr
    hazard restated on the receiver/element/container shapes)."""

    @staticmethod
    def _cleanly_sanitized(ret: str) -> bool:
        from core.analysis.interproc import _param_cleanly_sanitized
        _, summaries = _summaries(
            f"import html\n\ndef h(a):\n    return {ret}\n"
        )
        return _param_cleanly_sanitized(
            summaries["h"], 0, {"html.escape"},
        )

    def test_method_receiver_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "html.escape(a) + a.strip()"
        )

    def test_subscript_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized("html.escape(a) + a[0]")

    def test_subscript_index_taint_survives(self):
        assert not self._cleanly_sanitized(
            "html.escape(a) + table[a]"
        )

    def test_comprehension_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            'html.escape(a) + "".join(c for c in a)'
        )

    def test_dict_comprehension_value_taint_survives(self):
        assert not self._cleanly_sanitized(
            "html.escape(a) + str({k: a for k in (1,)})"
        )

    def test_container_literal_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "html.escape(a) + str([a])"
        )

    def test_dict_literal_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "html.escape(a) + str({1: a})"
        )

    def test_receiver_taint_is_stamped_not_direct(self):
        # The receiver flow survives WITH the method chain stamped
        # opaque — a non-catalog callable on the chain, so the
        # consumer refuses; it is not collapsed into the clean atom.
        from core.analysis.taint_summaries import _OPAQUE_ARG
        _, summaries = _summaries(
            "def h(a):\n    return a.strip()\n"
        )
        assert (0, "a.strip", _OPAQUE_ARG) in (
            summaries["h"].return_effects
        )

    def test_clean_wrapper_still_reads_clean(self):
        # Direction check: the pure sanitizer wrapper keeps minting.
        assert self._cleanly_sanitized("html.escape(a)")


class TestUnmodelledShapesFallBackConservatively:
    """Round-2 closure of the dirty-sibling-drop class: expression
    kinds without a structural model must PROPAGATE contained-name
    taint (unstamped — the consumer refuses), never return empty."""

    @staticmethod
    def _cleanly_sanitized(src_body: str) -> bool:
        from core.analysis.interproc import _param_cleanly_sanitized
        _, summaries = _summaries(f"import html\n\n{src_body}")
        return _param_cleanly_sanitized(
            summaries["h"], 0, {"html.escape"},
        )

    def test_non_name_rooted_attribute_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "def h(a):\n    return html.escape(a) + a[0].b\n"
        )

    def test_namedexpr_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "def h(a):\n    return html.escape(a) + (t := a)\n"
        )

    def test_iife_lambda_body_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "def h(a):\n    return html.escape(a) + (lambda: a)()\n"
        )

    def test_await_sibling_stays_dirty(self):
        assert not self._cleanly_sanitized(
            "async def h(a):\n    return html.escape(a) + await a\n"
        )

    def test_slice_bound_taint_survives(self):
        assert not self._cleanly_sanitized(
            "def h(a):\n    return html.escape(a) + d[a:2]\n"
        )

    def test_compare_operand_taint_survives(self):
        assert not self._cleanly_sanitized(
            "def h(a):\n    return html.escape(a) + str(a == 'x')\n"
        )

    def test_format_spec_taint_survives(self):
        assert not self._cleanly_sanitized(
            'def h(a):\n    return html.escape(a) + f"{1:{a}}"\n'
        )

    def test_walrus_wrapped_sanitizer_stays_clean(self):
        # Precision pins: explicit NamedExpr/Await arms keep chains
        # intact rather than degrading to direct atoms.
        assert self._cleanly_sanitized(
            "def h(a):\n    return (t := html.escape(a))\n"
        )

    def test_fstring_wrapped_sanitizer_stays_clean(self):
        assert self._cleanly_sanitized(
            'def h(a):\n    return f"{html.escape(a)}"\n'
        )


class TestIifeDefaultArgsStayDirty:
    """Lambda parameter defaults evaluate in the enclosing scope, so
    an IIFE routing taint through a default (``(lambda z=a: z)()``)
    carries it into the result — dropping it minted a false clean
    binding (same class as the IIFE body)."""

    @staticmethod
    def _clean(body: str) -> bool:
        from core.analysis.interproc import _param_cleanly_sanitized
        _, summaries = _summaries(f"import html\n\n{body}")
        return _param_cleanly_sanitized(
            summaries["h"], 0, {"html.escape"},
        )

    def test_positional_default_stays_dirty(self):
        assert not self._clean(
            "def h(a):\n    return html.escape(a) + (lambda z=a: z)()\n"
        )

    def test_keyword_only_default_stays_dirty(self):
        assert not self._clean(
            "def h(a):\n"
            "    return html.escape(a) + (lambda *, z=a: z)()\n"
        )

    def test_untainted_default_control_stays_clean(self):
        assert self._clean(
            "def h(a):\n"
            "    return html.escape(a) + (lambda z=1: str(z))()\n"
        )


# ---------------------------------------------------------------------------
# Vararg / kwonly / kwarg positional-binding boundary
# ---------------------------------------------------------------------------


class TestVarargPositionalBinding:
    """``params`` lists the ``*vararg``, keyword-only and ``**kwarg``
    names as ordinary entries, so index-based positional mapping is
    only trustworthy below the vararg boundary: an exact-params-length
    call to ``def h(a, *rest, key=...)`` used to map its third arg
    onto ``key`` (it lands in ``rest`` at runtime) — minting the
    keyword-only param's sanitizer chain for a value that never
    passed through it."""

    def test_exact_length_call_does_not_map_through_vararg_slot(self):
        _, summaries = _summaries(
            "def helper(a, *rest, key=''):\n"
            "    return html.escape(a) + html.escape(key) + str(rest)\n"
            "def outer(x, y, z):\n"
            "    return helper(x, y, z)\n"
        )
        from core.analysis.taint_summaries import _OPAQUE_ARG
        s = summaries["outer"]
        # x maps to ``a`` — the clean chain is preserved.
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)
        # z rides the vararg tuple at runtime (key keeps its default):
        # it must NOT inherit key's html.escape chain, and its taint
        # must stay alive with the helper stamped opaque (consumer
        # refuses rather than suppresses).
        for pi in (1, 2):
            chains = s.return_sanitizers_for_param(pi)
            assert ("html.escape", 0) not in chains
            assert s.param_taints_return(pi)
            assert ("helper", _OPAQUE_ARG) in chains

    def test_vararg_at_position_zero(self):
        _, summaries = _summaries(
            "def h(*rest, key=''):\n"
            "    return html.escape(key) + str(rest)\n"
            "def outer(x, y):\n"
            "    return h(x, y)\n"
        )
        s = summaries["outer"]
        for pi in (0, 1):
            assert s.param_taints_return(pi)
            assert ("html.escape", 0) not in s.return_sanitizers_for_param(pi)

    def test_vararg_at_position_two_maps_leading_params(self):
        _, summaries = _summaries(
            "def h(a, b, *rest):\n"
            "    return html.escape(a) + html.escape(b) + str(rest)\n"
            "def outer(x, y, z):\n"
            "    return h(x, y, z)\n"
        )
        s = summaries["outer"]
        # Below the boundary: index mapping preserved.
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)
        assert ("html.escape", 0) in s.return_sanitizers_for_param(1)
        # At the boundary: opaque, alive.
        assert s.param_taints_return(2)
        assert ("html.escape", 0) not in s.return_sanitizers_for_param(2)

    def test_positional_overflow_to_no_vararg_callee_stays_alive(self):
        # A call passing MORE positional args than the callee binds
        # (a latent runtime TypeError, but summaries are static): the
        # overflow arg's taint used to be dropped silently; past the
        # binding boundary it now reads opaque with taint ALIVE —
        # refusal-ward, consumers refuse rather than suppress.
        _, summaries = _summaries(
            "def h(a):\n"
            "    return html.escape(a)\n"
            "def outer(x, y):\n"
            "    return h(x, y)\n"
        )
        s = summaries["outer"]
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)
        assert s.param_taints_return(1)
        assert ("html.escape", 0) not in s.return_sanitizers_for_param(1)

    def test_no_vararg_exact_length_mapping_unchanged(self):
        _, summaries = _summaries(
            "def h(a, b):\n"
            "    return html.escape(a) + html.escape(b)\n"
            "def outer(x, y):\n"
            "    return h(x, y)\n"
        )
        s = summaries["outer"]
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)
        assert ("html.escape", 0) in s.return_sanitizers_for_param(1)

    def test_keyword_matching_kwarg_slot_name_does_not_bind(self):
        # ``h(kw=x)`` against ``def h(a, **kw)`` lands INSIDE the kw
        # dict; mapping it onto the ``kw`` params slot (whose summary
        # says "does not taint return") silently DROPPED x's taint.
        _, summaries = _summaries(
            "def h(a='', **kw):\n"
            "    return html.escape(a)\n"
            "def outer(x):\n"
            "    return h(kw=x)\n"
        )
        s = summaries["outer"]
        assert s.param_taints_return(0)

    def test_keyword_to_kwonly_param_still_maps(self):
        _, summaries = _summaries(
            "def h(a, *rest, key=''):\n"
            "    return html.escape(a) + html.escape(key)\n"
            "def outer(x, z):\n"
            "    return h(x, key=z)\n"
        )
        s = summaries["outer"]
        # Keyword binding to a kwonly param is index-correct.
        assert ("html.escape", 0) in s.return_sanitizers_for_param(1)


class TestSameLineRebindCollision:
    """Two writes to one name on ONE physical line collide on the
    assignment map's ``(lineno, name)`` key. A first-match map
    resolved BOTH CFG defs to the first RHS, losing the killing raw
    rebind's direct-return atom — the enforced sanitizer-cut then
    consumed the minted clean-sanitizer wrapper and dropped a real
    finding from the SARIF. Direction pins: the direct atom must
    SURVIVE the collision (refusal), and the semantically identical
    multi-line forms must keep their existing behaviour."""

    def test_same_line_rebind_keeps_direct_return_atom(self):
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    t = html.escape(s); t = s\n"
            "    return t\n"
        )
        s = summaries["_clean"]
        # The raw pass-through survives: direct-return atom present.
        assert (0, "", -1) in s.return_effects

    def test_same_line_augassign_keeps_direct_return_atom(self):
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    t = html.escape(s); t += s\n"
            "    return t\n"
        )
        s = summaries["_clean"]
        assert (0, "", -1) in s.return_effects

    def test_multiline_rebind_unchanged(self):
        # Control: distinct linenos never collided; behaviour pinned.
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    t = html.escape(s)\n"
            "    t = s\n"
            "    return t\n"
        )
        s = summaries["_clean"]
        assert (0, "", -1) in s.return_effects

    def test_clean_wrapper_still_certifies(self):
        # Control: a genuinely clean one-line wrapper keeps its
        # rescue — the collision handling must not over-refuse.
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    t = html.escape(s)\n"
            "    return t\n"
        )
        s = summaries["_clean"]
        assert (0, "", -1) not in s.return_effects
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)

    def test_same_line_distinct_names_do_not_collide(self):
        # ``a = escape(s); b = s`` — different names on one line keep
        # their own bindings (no spurious cross-name merge).
        _, summaries = _summaries(
            "def _clean(s):\n"
            "    a = html.escape(s); b = 1\n"
            "    return a\n"
        )
        s = summaries["_clean"]
        assert (0, "", -1) not in s.return_effects
        assert ("html.escape", 0) in s.return_sanitizers_for_param(0)

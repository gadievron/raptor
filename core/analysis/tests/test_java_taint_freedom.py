"""Unit battery for the b42 taint-free union machinery.

Covers the three seams the corpus exercises end-to-end:

* returns-taint-free helper summary derivation (acceptances and every
  named refusal);
* the non-agreeing definer union in the point resolver — tier-on
  yields TAINT_FREE, tier-off keeps the historical refusal
  byte-for-byte;
* the same-line multi-write refusal in ``JavaConstIndex.rhs_at`` (the
  pre-existing collapse hazard the b42 value-position trap exposed:
  a one-liner ``if/else`` discriminant folded to its first arm and
  pruned the tainted switch arm).
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_java")

from core.analysis.java_taint_freedom import (  # noqa: E402
    derive_tf_helpers,
    make_tf_helper_resolver,
)


def _cls(body: str) -> str:
    return "public class T {\n" + body + "\n}\n"


class TestHelperSummaries:
    def test_flag_gated_all_literal_branches_qualifies(self):
        # The Juliet _21 shape: the field flag selects the branch but
        # every branch writes a literal — union taint-free, no
        # reasoning about the flag.
        src = _cls(
            "    private boolean flag = false;\n"
            "    private String src() {\n"
            "        String d;\n"
            "        if (flag) { d = null; } else { d = \"foo\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert idx.ok
        assert ("src", 0) in idx.taint_free

    def test_single_literal_return_qualifies(self):
        src = _cls("    private String v() { return \"x\"; }\n")
        assert ("v", 0) in derive_tf_helpers(src).taint_free

    def test_parameter_flow_refuses(self):
        src = _cls(
            "    private String pick(String p) {\n"
            "        if (p.isEmpty()) { return p; }\n"
            "        return \"x\";\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("pick", 1) not in idx.taint_free
        assert idx.refused.get("return-not-taint-free")

    def test_field_value_refuses(self):
        src = _cls(
            "    private String stash = \"d\";\n"
            "    private String src() {\n"
            "        String d;\n"
            "        if (stash.isEmpty()) { d = stash; }\n"
            "        else { d = \"foo\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 0) not in derive_tf_helpers(src).taint_free

    def test_unknown_call_refuses(self):
        src = _cls(
            "    private String src() {\n"
            "        String d = System.console().readLine();\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 0) not in derive_tf_helpers(src).taint_free

    def test_compound_write_refuses(self):
        src = _cls(
            "    private String src(String p) {\n"
            "        String d = \"foo\";\n"
            "        d += p;\n"
            "        return d;\n"
            "    }\n"
        )
        assert ("src", 1) not in derive_tf_helpers(src).taint_free

    def test_overload_ambiguity_refuses(self):
        src = _cls(
            "    private String v(int a) { return \"x\"; }\n"
            "    private String v(int a, int b) { return \"y\"; }\n"
            "    private String v(int a) { return \"z\"; }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("v", 1) not in idx.taint_free
        # the unambiguous 2-arity overload still qualifies
        assert ("v", 2) in idx.taint_free

    def test_varargs_refuses(self):
        src = _cls(
            "    private String v(String... a) { return \"x\"; }\n"
        )
        assert not derive_tf_helpers(src).taint_free

    def test_void_helper_refuses(self):
        src = _cls("    private void v() { return; }\n")
        assert ("v", 0) not in derive_tf_helpers(src).taint_free

    def test_recursive_helper_refuses(self):
        src = _cls(
            "    private String v() {\n"
            "        String d = w();\n"
            "        return d;\n"
            "    }\n"
            "    private String w() { return v(); }\n"
        )
        idx = derive_tf_helpers(src)
        # v's body calls w() — an unknown call to the folder (no
        # helper-of-helper summaries in v1), so both refuse.
        assert ("v", 0) not in idx.taint_free
        assert ("w", 0) not in idx.taint_free


class TestHelperResolver:
    def test_resolver_none_when_no_helpers(self):
        src = _cls("    private String v(String p) { return p; }\n")
        assert make_tf_helper_resolver(src) is None

    def test_resolver_claims_bare_call_only(self):
        src = _cls(
            "    private String v() { return \"x\"; }\n"
        )
        res = make_tf_helper_resolver(
            src, member_check=lambda strs: True)
        assert res is not None
        from core.analysis.cfg_builder_java import _get_parser
        from core.analysis.const_fold_java import TAINT_FREE
        tree = _get_parser().parse(
            b"class U { void m(T t) { String a = v(); "
            b"String b = t.v(); } }"
        )
        calls = []
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation":
                calls.append(n)
            stack.extend(n.children)
        got = {}
        for c in calls:
            got[c.text.decode()] = res(c, None, 0)
        assert got["v()"] is TAINT_FREE
        assert got["t.v()"] is None  # receiver: no claim

    def test_resolver_string_members_need_danger_authority(self):
        # b40 composition: the helper's concrete string return members
        # must clear the caller's danger predicate — no predicate or a
        # failing one means no claim (the constant itself can violate
        # a value-based finding class).
        src = _cls(
            "    private String v() { return \"x\"; }\n"
        )
        from core.analysis.cfg_builder_java import _get_parser
        tree = _get_parser().parse(b"class U { void m() { use(v()); } }")
        call = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "method_invocation" and \
                    n.text.decode().startswith("v("):
                call = n
            stack.extend(n.children)
        assert call is not None
        no_auth = make_tf_helper_resolver(src)
        assert no_auth is None or no_auth(call, None, 0) is None
        danger = make_tf_helper_resolver(
            src, member_check=lambda strs: False)
        assert danger is None or danger(call, None, 0) is None

    def test_summary_records_string_members(self):
        from core.analysis.java_taint_freedom import derive_tf_helpers
        src = _cls(
            "    private boolean f = false;\n"
            "    private String v() {\n"
            "        String d;\n"
            "        if (f) { d = null; } else { d = \"foo\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("v", 0) in idx.taint_free
        assert idx.str_members[("v", 0)] == frozenset({"foo"})


class TestDefinerUnion:
    SRC = (
        "public class T {\n"
        "    public void handle(String cond) {\n"
        "        String data;\n"
        "        if (cond.isEmpty()) {\n"
        "            data = null;\n"
        "        } else {\n"
        "            data = \"foo\";\n"
        "        }\n"
        "        use(data);\n"
        "    }\n"
        "    void use(String s) {}\n"
        "}\n"
    )

    def _rd_and_index(self):
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import JavaConstIndex
        from core.analysis.dataflow import reaching_defs
        g = build_java_intraproc_cfg(self.SRC, "handle")
        assert g is not None
        rd = reaching_defs(g)
        sink = [n for n in g.nodes() if getattr(n, "lineno", 0) == 9][0]
        idx = JavaConstIndex(self.SRC, (1, 12))
        return rd, sink, idx

    def test_union_tier_on_yields_taint_free_reason(self):
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, idx = self._rd_and_index()
        reason = all_definers_constant(
            rd, sink, "data", idx,
            union_member_check=lambda strs: True)
        assert reason is not None
        assert "non-agreeing taint-free union" in reason

    def test_union_refuses_without_member_check(self):
        # b40 composition: a merge containing a concrete string member
        # needs a danger authority — no predicate, no claim.
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, idx = self._rd_and_index()
        assert all_definers_constant(rd, sink, "data", idx) is None

    def test_union_refuses_on_danger_member(self):
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, idx = self._rd_and_index()
        assert all_definers_constant(
            rd, sink, "data", idx,
            union_member_check=lambda strs: False) is None

    def test_union_tier_off_refuses(self):
        # The value-only entry point keeps the historical refusal:
        # a disagreeing merge must never produce a usable value.
        from core.analysis.const_fold_java import (
            REFUSE,
            fold_expr_at,
        )
        from core.analysis.cfg_builder_java import _get_parser
        rd, sink, idx = self._rd_and_index()
        tree = _get_parser().parse(b"class Q { void m() { use(data); } }")
        ident = None
        stack = [tree.root_node]
        while stack:
            n = stack.pop()
            if n.type == "identifier" and n.text == b"data":
                ident = n
            stack.extend(n.children)
        val = fold_expr_at(rd, sink, ident, idx,
                           allow_taint_free=False)
        assert val is REFUSE


class TestMultiWriteLineRefusal:
    def test_one_liner_if_else_discriminant_never_prunes(self):
        # The trap that caught a live false suppression: both writes
        # to the discriminant share one line, so the line-keyed RHS
        # lookup used to serve the first arm to BOTH definers and the
        # switch pruned its tainted default arm.
        src = (
            "public class T {\n"
            "    public void handle(String param) {\n"
            "        String s;\n"
            "        if (param.length() > 2) { s = \"a\"; } "
            "else { s = \"b\"; }\n"
            "        use(s);\n"
            "    }\n"
            "    void use(String x) {}\n"
            "}\n"
        )
        from core.analysis.const_fold_java import JavaConstIndex
        idx = JavaConstIndex(src, (1, 8))
        assert idx.rhs_at(4, "s") is None

    def test_single_write_line_still_serves(self):
        src = (
            "public class T {\n"
            "    public void handle() {\n"
            "        String s = \"a\";\n"
            "        use(s);\n"
            "    }\n"
            "    void use(String x) {}\n"
            "}\n"
        )
        from core.analysis.const_fold_java import JavaConstIndex
        idx = JavaConstIndex(src, (1, 7))
        assert idx.rhs_at(3, "s") is not None


class TestBanThreadingComposedSurfaces:
    """The b42 circularity ban must reach EVERY taint-free-enabled
    fold entry the gate's suppress paths consume — the constant
    pre-check (pinned in the postpass tests) AND the b41 sibling /
    whole-array surfaces, which fold through ``definers_all_fold``
    and ``fold_expr_at``."""

    def _rd_setup(self, decls: str, use: str):
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import JavaConstIndex
        from core.analysis.dataflow import reaching_defs

        src = ("public class T {\n"
               "    public void m(String x) {\n"
               + decls
               + f"        sink({use});\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        n_lines = src.count("\n") + 1
        index = JavaConstIndex(src, (1, n_lines))
        rd = reaching_defs(graph)
        sink_node = None
        for n in graph.nodes():
            if getattr(n, "lineno", 0) == src.count("\n") - 2:
                sink_node = n
        assert sink_node is not None
        return rd, sink_node, index

    def test_definers_all_fold_ban_never_fires(self):
        # b45 re-pin: the threat-model authority's non-source set is
        # empty, so system reads refuse BEFORE the b42 ban can act —
        # both legs read False and the ban is structurally
        # never-firing (kept as defense-in-depth threading).
        from core.analysis.const_fold_java import definers_all_fold

        rd, sink, index = self._rd_setup(
            '        String v = System.getenv("HOME");\n', "v")
        assert not definers_all_fold(rd, sink, "v", index)
        assert not definers_all_fold(
            rd, sink, "v", index, ban_tf_system_reads=True)

    def test_definers_all_fold_ban_spares_non_system_tf(self):
        from core.analysis.const_fold_java import definers_all_fold

        rd, sink, index = self._rd_setup(
            '        String v = java.io.File.separator;\n', "v")
        assert definers_all_fold(
            rd, sink, "v", index, ban_tf_system_reads=True)

    def test_fold_expr_at_honours_ban(self):
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import (
            REFUSE,
            TAINT_FREE,
            JavaConstIndex,
            fold_expr_at,
        )
        from core.analysis.dataflow import reaching_defs

        src = ("public class T {\n"
               "    public void m(String x) {\n"
               '        String v = System.getenv("HOME");\n'
               "        sink(v);\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        index = JavaConstIndex(src, (1, 6))
        rd = reaching_defs(graph)
        sink = None
        for n in graph.nodes():
            if getattr(n, "lineno", 0) == 4:
                sink = n
        assert sink is not None
        expr = index.rhs_at(3, "v")
        assert expr is not None
        # b45 re-pin: the authority refuses system reads before the
        # ban acts — both legs REFUSE (never-firing threading pin).
        assert fold_expr_at(
            rd, sink, expr, index, allow_taint_free=True) is REFUSE
        assert fold_expr_at(
            rd, sink, expr, index, allow_taint_free=True,
            ban_tf_system_reads=True) is REFUSE
        assert TAINT_FREE is not REFUSE  # keep both imports honest
class TestFieldStoreScopeDiscipline:
    """Bare-name FIELD stores must never count as helper-local writes:
    the flow-insensitive union is sound only for locals (definite
    assignment guarantees a body write precedes any read); a field's
    ambient — possibly tainted — value on the un-written path is an
    invisible union member."""

    def test_field_write_helper_refuses(self):
        # The confirmed shape: `data` is a FIELD tainted elsewhere;
        # `get(false)` returns the ambient attacker value while the
        # union folds only the body write ("safe").
        src = _cls(
            "    private String data;\n"
            "    public void seed(String req) { data = req; }\n"
            "    private String get(boolean flag) {\n"
            "        if (flag) { data = \"safe\"; }\n"
            "        return data;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert idx.ok
        assert ("get", 1) not in idx.taint_free, (
            "field store counted as a local write — returns-taint-free "
            "claim on a helper that returns ambient field state"
        )

    def test_declared_local_control_still_qualifies(self):
        src = _cls(
            "    private boolean flag = false;\n"
            "    private String get() {\n"
            "        String d = \"other\";\n"
            "        if (flag) { d = \"safe\"; }\n"
            "        return d;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("get", 0) in idx.taint_free

    def test_field_shadowing_local_refuses(self):
        # A local sharing a FIELD's name is a shadow-collision hazard:
        # a bare read before the declarator binds the field. The name
        # refuses outright.
        src = _cls(
            "    private String d;\n"
            "    private String get(boolean flag) {\n"
            "        String r = d;\n"
            "        String d = \"safe\";\n"
            "        return flag ? r : d;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("get", 1) not in idx.taint_free

    def test_inherited_field_shadow_read_refuses(self):
        # Read direction, INHERITED field: the block-local declarator
        # writes "safe" (a vouched store), but the OUTER `return data`
        # read binds the superclass field — invisible to the
        # directly-enclosing-class field scan, caught by vouching the
        # read site positionally (no superclass resolution needed).
        src = (
            "class Base {\n"
            "    protected String data;\n"
            "    public void seed(String req) { data = req; }\n"
            "}\n"
            "class T extends Base {\n"
            "    private String get(boolean f) {\n"
            "        if (f) { String data = \"safe\"; return data; }\n"
            "        return data;\n"
            "    }\n"
            "}\n"
        )
        idx = derive_tf_helpers(src)
        assert idx.ok
        assert ("get", 1) not in idx.taint_free, (
            "un-vouched read bound the inherited field — "
            "returns-taint-free claim on ambient superclass state"
        )

    def test_inherited_field_shadow_rhs_read_refuses(self):
        # Same mechanism one hop removed: the returned local is
        # vouched everywhere, but one of its RHS reads binds the
        # inherited field outside the shadow declarator's window.
        src = (
            "class Base {\n"
            "    protected String data;\n"
            "    public void seed(String req) { data = req; }\n"
            "}\n"
            "class T extends Base {\n"
            "    private String get(boolean f) {\n"
            "        String out = \"init\";\n"
            "        if (f) { String data = \"safe\"; out = data; }\n"
            "        else { out = data; }\n"
            "        return out;\n"
            "    }\n"
            "}\n"
        )
        idx = derive_tf_helpers(src)
        assert idx.ok
        assert ("get", 1) not in idx.taint_free

    def test_vouched_reads_still_qualify(self):
        # The read vouch must not refuse genuinely local flow: every
        # read of `d` sits inside its method-level declarator window.
        src = _cls(
            "    private String get(boolean f) {\n"
            "        String d = \"other\";\n"
            "        if (f) { d = \"safe\"; }\n"
            "        String e = d;\n"
            "        return e;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("get", 1) in idx.taint_free

    def test_block_scoped_declarator_does_not_vouch_outer_store(self):
        # Positional rule: a declarator inside a nested block must not
        # vouch a store OUTSIDE its window.
        src = _cls(
            "    private String data;\n"
            "    private String get(boolean flag) {\n"
            "        if (flag) { String data = \"x\"; use(data); }\n"
            "        data = \"safe\";\n"
            "        return data;\n"
            "    }\n"
        )
        idx = derive_tf_helpers(src)
        assert ("get", 1) not in idx.taint_free


class TestTaintFreeMintDangerDiscipline:
    """Every TAINT_FREE-minting arm that has SEEN a concrete string
    member holds itself to the _tf_union bar: the member must clear
    the caller's danger predicate, and no predicate means no danger
    authority (refuse). A value-based finding class is violated by the
    constant itself, however attacker-free — "'" + File.separator is
    exactly a quote reaching a SQL sink."""

    def _rd_setup(self, decl_line: str):
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import JavaConstIndex
        from core.analysis.dataflow import reaching_defs
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               f"{decl_line}"
               "        sink(v);\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        rd = reaching_defs(graph)
        sink = next(n for n in graph.nodes()
                    if getattr(n, "lineno", 0) == 4)
        index = JavaConstIndex(src, (1, src.count("\n") + 1))
        return rd, sink, index

    def _adc(self, decl_line: str, **kw):
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, index = self._rd_setup(decl_line)
        return all_definers_constant(rd, sink, "v", index, **kw)

    def test_concat_plus_danger_member_refuses(self):
        line = '        String v = "\'" + java.io.File.separator;\n'
        assert self._adc(
            line, union_member_check=lambda s: False) is None
        assert self._adc(line) is None  # no predicate = no authority

    def test_concat_plus_clear_member_still_mints(self):
        line = '        String v = "safe" + java.io.File.separator;\n'
        seen: list = []
        reason = self._adc(
            line,
            union_member_check=lambda s: not seen.extend([s]) and True)
        assert reason is not None
        assert any("safe" in m for batch in seen for m in batch)

    def test_concat_call_danger_member_refuses(self):
        line = ('        String v = '
                '"\'".concat(java.io.File.separator);\n')
        assert self._adc(
            line, union_member_check=lambda s: False) is None
        assert self._adc(line) is None

    def test_concat_call_clear_member_still_mints(self):
        line = ('        String v = '
                '"safe".concat(java.io.File.separator);\n')
        assert self._adc(
            line, union_member_check=lambda s: True) is not None

    def test_ternary_danger_member_refuses(self):
        line = ('        String v = x.isEmpty() ? "\'" '
                ': java.io.File.separator;\n')
        assert self._adc(
            line, union_member_check=lambda s: False) is None
        assert self._adc(line) is None

    def test_ternary_clear_members_still_mint(self):
        line = ('        String v = x.isEmpty() ? "a" '
                ': java.io.File.separator;\n')
        assert self._adc(
            line, union_member_check=lambda s: True) is not None

    def test_agreed_value_arm_runs_member_check(self):
        # Two definers AGREEING on a danger constant minted the
        # "same compile-time str constant" reason with no member
        # check, while the identical constants DISAGREEING refused
        # via _tf_union — the single-value arm now holds the same bar.
        from core.analysis.const_fold_java import all_definers_constant
        from core.analysis.cfg_builder_java import (
            build_java_intraproc_cfg,
        )
        from core.analysis.const_fold_java import JavaConstIndex
        from core.analysis.dataflow import reaching_defs
        src = ("public class T {\n"
               "    public void m(String x) {\n"
               "        String v;\n"
               "        if (x.isEmpty()) {\n"
               "            v = \"x' OR 1=1\";\n"
               "        } else {\n"
               "            v = \"x' OR 1=1\";\n"
               "        }\n"
               "        sink(v);\n"
               "    }\n"
               "}\n")
        graph = build_java_intraproc_cfg(src, "m")
        assert graph is not None
        rd = reaching_defs(graph)
        sink = next(n for n in graph.nodes()
                    if getattr(n, "lineno", 0) == 9)
        index = JavaConstIndex(src, (1, src.count("\n") + 1))
        assert all_definers_constant(
            rd, sink, "v", index,
            union_member_check=lambda s: False) is None
        assert all_definers_constant(rd, sink, "v", index) is None
        # Control: the check clearing keeps the constant proof.
        reason = all_definers_constant(
            rd, sink, "v", index, union_member_check=lambda s: True)
        assert reason is not None and "constant" in reason

    def test_agreed_value_with_production_predicate(self):
        # The real danger authority (the value gate's per-CWE member
        # check, a strs-list -> bool predicate): a benign agreed
        # constant keeps minting through it; a quote-carrying one
        # refuses. Pins the production API shape end-to-end so a
        # predicate-signature drift cannot silently flip either
        # direction.
        from core.analysis.const_fold_java import all_definers_constant
        from core.analysis.sanitizer_cut import _union_member_check
        chk = _union_member_check("CWE-89")
        assert chk is not None
        benign = self._rd_setup('        String v = "abc";\n')
        reason = all_definers_constant(
            benign[0], benign[1], "v", benign[2],
            union_member_check=chk)
        assert reason is not None and "constant" in reason
        danger = self._rd_setup(
            "        String v = \"x' OR 1=1\";\n")
        assert all_definers_constant(
            danger[0], danger[1], "v", danger[2],
            union_member_check=chk) is None

    def test_agreed_int_value_needs_no_member_check(self):
        # ints cannot carry a danger charset — the member discipline
        # is strings-only (no over-refusal on numeric constants).
        line = "        int v = 41 + 1;\n"
        from core.analysis.const_fold_java import all_definers_constant
        rd, sink, index = self._rd_setup(line)
        assert all_definers_constant(rd, sink, "v", index) is not None

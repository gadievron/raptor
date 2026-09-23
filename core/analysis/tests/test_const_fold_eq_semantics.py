"""Reference semantics for folded ``==`` / ``!=`` (Java value gate).

Java ``==`` compares references for object operands. The folder's
Python values erase that: ``_fold_pure_call`` yields strs for
``substring``/``concat``/``toLowerCase``/``String.valueOf`` whose
runtime results are NEW String objects, so a by-value fold of
``t == "a"`` selects the branch OPPOSITE to runtime — and through the
ternary / if-refinement / all-definers machinery that prunes the LIVE
(tainted) branch and suppresses a real finding. Boxed
``Integer == Integer`` beyond the -128..127 cache has the same
hazard. The fold must refuse ``==``/``!=`` unless at least one
operand is syntactically primitive-producing (JLS 15.21 then unboxes
the other side).

Both directions are pinned: the hostile shapes refuse, and the
primitive shapes (int literals, arithmetic, char literals, booleans,
null tests) keep folding — the if/switch refinements and the
constant-definers gate depend on them.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import (  # noqa: E402
    REFUSE,
    JavaConstIndex,
    all_definers_constant,
    fold_expr,
)


def _expr_node(expr: str):
    """Parse ``expr`` as a Java initializer and return its node."""
    import tree_sitter_java as tsj
    from core.inventory.call_graph import _get_ts_parser
    parser = _get_ts_parser(tsj.language)
    src = f"class T {{ void m() {{ var v = {expr}; }} }}"
    tree = parser.parse(src.encode("utf-8"))
    stack = [tree.root_node]
    while stack:
        n = stack.pop()
        if n.type == "variable_declarator":
            name = n.child_by_field_name("name")
            if name is not None and name.text.decode() == "v":
                return n.child_by_field_name("value")
        stack.extend(n.children)
    raise AssertionError("initializer not found")


def _fold(expr: str, names: dict | None = None):
    table = names or {}

    def resolve(name, _depth):
        return table.get(name, REFUSE)

    return fold_expr(_expr_node(expr), resolve)


class TestRefusedShapes:
    def test_pure_call_string_eq_literal_refuses(self):
        # runtime: new String from substring — reference-false even
        # when the characters match.
        assert _fold('"ab".substring(0, 1) == "a"') is REFUSE

    def test_concat_eq_refuses(self):
        assert _fold('"a".concat("b") == "ab"') is REFUSE

    def test_valueof_eq_refuses(self):
        assert _fold('String.valueOf(1) == "1"') is REFUSE

    def test_literal_string_eq_refuses(self):
        # Interning would make this sound in isolation, but the
        # boundary must not depend on where each side's VALUE came
        # from (an identifier resolving to a pure-call str looks
        # identical here). Refusal direction; .equals is the
        # idiomatic value comparison.
        assert _fold('"a" == "a"') is REFUSE

    def test_identifier_string_eq_refuses(self):
        assert _fold('t == "a"', {"t": "a"}) is REFUSE

    def test_identifier_pair_int_eq_refuses(self):
        # Both sides could be declared Integer — beyond the cache,
        # reference comparison. Declared types are unknown here.
        assert _fold("a == b", {"a": 1000, "b": 1000}) is REFUSE

    def test_ne_refuses_symmetrically(self):
        assert _fold('t != "a"', {"t": "a"}) is REFUSE
        assert _fold("a != b", {"a": 1, "b": 2}) is REFUSE


class TestPrimitiveShapesStillFold:
    def test_int_literal_comparisons(self):
        assert _fold("1 + 1 == 2") is True
        assert _fold("1 == 2") is False
        assert _fold("1 != 2") is True

    def test_identifier_vs_int_literal(self):
        # The literal side is primitive; the other unboxes.
        assert _fold("a == 1000", {"a": 1000}) is True
        assert _fold("a == 7", {"a": 8}) is False

    def test_identifier_vs_arithmetic(self):
        assert _fold("a == 500 + 500", {"a": 1000}) is True

    def test_parenthesized_literal_side(self):
        assert _fold("a == (7)", {"a": 7}) is True

    def test_char_literal_comparison(self):
        assert _fold("\"ab\".charAt(0) == 'a'") is True
        assert _fold("\"ab\".charAt(1) == 'a'") is False

    def test_boolean_comparison(self):
        # Autoboxing yields canonical Boolean.TRUE/FALSE — reference
        # equality agrees with value equality.
        assert _fold("f == true", {"f": True}) is True
        assert _fold("f == g", {"f": True, "g": False}) is False

    def test_null_comparison(self):
        assert _fold("x == null", {"x": None}) is True
        assert _fold("x != null", {"x": "a"}) is True


class TestThroughProductionMachinery:
    """The exact composed false-suppression trace, both stages."""

    SRC = '''public class T {
    void handle(String s, java.sql.Statement stmt) throws Exception {
        String t = s.substring(0, 1);
        String out = (t == "a") ? "safe" : s;
        stmt.execute(out);
    }
}
'''

    def _rd_sink_index(self, src):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        from core.analysis.dataflow import reaching_defs
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        rd = reaching_defs(cfg)
        sink = next(n for n in cfg.nodes() if "stmt.execute" in n.label)
        index = JavaConstIndex(src, (1, src.count("\n") + 1))
        return rd, sink, index

    def test_pure_call_eq_ternary_not_constant(self):
        # ``t`` folds to "a" via substring; ``t == "a"`` must refuse,
        # so the ternary refuses and ``out`` is NOT provably constant
        # — the tainted arm stays live.
        rd, sink, index = self._rd_sink_index(self.SRC)
        assert all_definers_constant(rd, sink, "out", index) is None

    def test_equals_free_constant_twin_still_folds(self):
        # Control: a genuinely constant assignment keeps the proof.
        src = self.SRC.replace(
            'String out = (t == "a") ? "safe" : s;',
            'String out = "safe";',
        )
        rd, sink, index = self._rd_sink_index(src)
        assert all_definers_constant(
            rd, sink, "out", index,
            union_member_check=lambda strs: True) is not None

    def test_if_refinement_keeps_both_branches(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = '''public class T {
    void handle(String s, java.io.PrintWriter w) {
        String t = s.substring(0, 1);
        if (t == "a") { w.println("x"); } else { w.println(s); }
    }
}
'''
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        assert "if:constant-resolved" not in cfg.build_notes

    def test_if_refinement_still_prunes_primitive_int(self):
        from core.analysis.cfg_builder_java import build_java_intraproc_cfg
        src = '''public class T {
    void handle(String s, java.io.PrintWriter w) {
        int n = 2;
        if (n == 1 + 1) { w.println("x"); } else { w.println(s); }
    }
}
'''
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        assert "if:constant-resolved" in cfg.build_notes


class TestUtf16CodeUnitSemantics:
    """Java length()/charAt()/substring() operate on UTF-16 code
    units; the folder uses Python code points. They agree exactly when
    every code point is BMP — astral (non-BMP) receivers must refuse,
    or the fold selects the WRONG branch downstream (live-branch
    pruning is the false-suppression direction)."""

    def test_astral_length_refuses(self):
        # Java: "😀".length() == 2 (surrogate pair); Python len == 1.
        assert _fold('"😀".length()') is REFUSE

    def test_astral_charat_refuses(self):
        assert _fold('"a😀x".charAt(1)') is REFUSE

    def test_astral_substring_refuses(self):
        assert _fold('"a😀x".substring(1)') is REFUSE

    def test_astral_ternary_condition_refuses(self):
        # The end-to-end shape: a wrong-VALUE fold in branch-selection
        # position picked the "safe" arm while Java executes the other.
        assert _fold('"😀".length() == 2 ? "T" : "safe"') is REFUSE

    def test_bmp_length_still_folds(self):
        # Controls: ASCII and BMP non-ASCII agree code-unit-for-code-
        # point; the fold must not over-refuse.
        assert _fold('"abc".length()') == 3
        assert _fold('"héllo".length()') == 5

    def test_bmp_charat_and_substring_still_fold(self):
        assert _fold('"héllo".charAt(1)') == "é"
        assert _fold('"héllo".substring(1, 3)') == "él"

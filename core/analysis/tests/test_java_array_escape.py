"""Unit tests for :mod:`core.analysis.java_array_escape` — the
tracking rules, the element-write ledger, the scalar-copy hazards,
and the per-line exemption semantics. End-to-end verdict behaviour is
pinned by the precision corpus; these tests pin the module contracts
the corpus reaches only indirectly."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.java_array_escape import build_local_array_index


def _index(body: str, span=None):
    src = (
        "import org.owasp.encoder.Encode;\n"
        "public class T {\n"
        "    public void handle(String x, int i, "
        "java.io.PrintWriter out) {\n"
        + body
        + "    }\n}\n"
    )
    n = src.count("\n")
    idx = build_local_array_index(src, span or (1, n))
    assert idx is not None and idx.ok
    return idx


class TestTracking:
    def test_fresh_local_with_literal_indices_tracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] = Encode.forHtml(x);\n"
            "        out.println(a[0]);\n"
        )
        assert idx.tracked("a")

    def test_array_initializer_tracks_and_records_element_writes(self):
        idx = _index(
            '        String[] a = {"k", "v"};\n'
            "        out.println(a[1]);\n"
        )
        assert idx.tracked("a")
        assert len(idx.element_writes("a", 0)) == 1
        assert len(idx.element_writes("a", 1)) == 1

    def test_alias_out_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String[] b = a;\n"
        )
        assert not idx.tracked("a")

    def test_realias_lhs_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String[] b = new String[2];\n"
            "        a = b;\n"
        )
        assert not idx.tracked("a")
        assert not idx.tracked("b")

    def test_call_argument_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        fill(a);\n"
        )
        assert not idx.tracked("a")

    def test_return_untracks(self):
        src = (
            "public class T {\n"
            "    public String[] handle(String x) {\n"
            "        String[] a = new String[2];\n"
            "        return a;\n"
            "    }\n}\n"
        )
        idx = build_local_array_index(src, (1, 6))
        assert idx is not None and not idx.tracked("a")

    def test_nonconstant_index_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[i] = x;\n"
        )
        assert not idx.tracked("a")

    def test_compound_element_write_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] += x;\n"
        )
        assert not idx.tracked("a")

    def test_update_expression_untracks(self):
        idx = _index(
            "        int[] a = new int[2];\n"
            "        a[0]++;\n"
        )
        assert not idx.tracked("a")

    def test_enhanced_for_iterable_untracks(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        for (String s : a) { out.println(s); }\n"
        )
        assert not idx.tracked("a")

    def test_non_fresh_initializer_never_tracks(self):
        idx = _index(
            "        String[] a = make();\n"
            "        out.println(a[0]);\n"
        )
        assert not idx.tracked("a")

    def test_second_fresh_declaration_untracks(self):
        # Shadowing / re-declaration the gate can't order.
        idx = _index(
            "        String[] a = new String[1];\n"
            "        if (i > 0) { String[] b = new String[1]; b[0] = x; }\n"
            "        String[] c = new String[1];\n"
        )
        assert idx.tracked("a") and idx.tracked("c")

    def test_nested_array_access_untracks_base(self):
        idx = _index(
            "        String[][] a = new String[2][2];\n"
            "        out.println(a[0][1]);\n"
        )
        assert not idx.tracked("a")


class TestScalarCopy:
    def test_single_writer_copy_resolves(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String bar = a[0];\n"
        )
        assert idx.scalar_copy(5, "bar") == ("a", 0)

    def test_same_line_multi_writer_drops_entry(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String bar;\n"
            "        if (i > 0) { bar = a[0]; } else { bar = x; }\n"
        )
        assert idx.scalar_copy(6, "bar") is None

    def test_plain_assignment_copy_resolves(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String bar;\n"
            "        bar = a[1];\n"
        )
        assert idx.scalar_copy(6, "bar") == ("a", 1)


class TestExemptLine:
    def test_tracked_access_line_exempt(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] = x;\n"
        )
        assert idx.exempt_line(5)

    def test_line_without_classified_trigger_not_exempt(self):
        # Positive-evidence rule: no recorded trigger on the line —
        # the may_escape trigger may live on another physical line of
        # a multi-line statement — never exempt on absence.
        idx = _index(
            "        String[] a = new String[2];\n"
        )
        assert not idx.exempt_line(3)

    def test_field_store_line_not_exempt(self):
        idx = _index(
            "        this.f = x;\n"
        )
        assert not idx.exempt_line(4)

    def test_arraycopy_line_not_exempt(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        String[] b = new String[2];\n"
            "        System.arraycopy(a, 0, b, 0, 1);\n"
        )
        assert not idx.exempt_line(6)

    def test_untracked_array_line_not_exempt(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        fill(a);\n"
            "        a[0] = x;\n"
        )
        assert not idx.exempt_line(6)


class TestWriteIsCatalogCall:
    CATALOG = {"org.owasp.encoder.Encode.forHtml"}

    def test_direct_sanitizer_rhs_counts(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] = Encode.forHtml(x);\n"
        )
        (w,) = idx.element_writes("a", 0)
        assert idx.write_is_catalog_call(w, self.CATALOG)

    def test_wrapped_sanitizer_rhs_refuses(self):
        # The OUTERMOST call decides: wrap(Encode.forHtml(x)) could
        # re-taint the sanitizer's output.
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] = wrap(Encode.forHtml(x));\n"
        )
        (w,) = idx.element_writes("a", 0)
        assert not idx.write_is_catalog_call(w, self.CATALOG)

    def test_concat_rhs_refuses(self):
        idx = _index(
            "        String[] a = new String[2];\n"
            "        a[0] = Encode.forHtml(x) + x;\n"
        )
        (w,) = idx.element_writes("a", 0)
        assert not idx.write_is_catalog_call(w, self.CATALOG)

    def test_literal_rhs_refuses(self):
        # Constant writes belong to the const-folding direction, not
        # the sanitizer-exclusivity proof.
        idx = _index(
            "        String[] a = new String[2];\n"
            '        a[0] = "k";\n'
        )
        (w,) = idx.element_writes("a", 0)
        assert not idx.write_is_catalog_call(w, self.CATALOG)

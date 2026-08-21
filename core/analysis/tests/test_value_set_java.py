"""Bounded constant-table resolution (value_set_java) — qualification,
refusal-first aliasing, and the constant-gate integration."""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.const_fold_java import REFUSE, fold_expr  # noqa: E402
from core.analysis.value_set_java import (  # noqa: E402
    ArrayTableIndex,
    build_table_resolver,
)


def _index(body: str) -> ArrayTableIndex:
    src = ("public class T {\n    public void m(String x) {\n"
           + body + "    }\n}\n")
    n_lines = src.count("\n") + 1
    return ArrayTableIndex(src, (1, n_lines)), src


def _resolve(body: str, read_expr: str = "values[1]"):
    """Fold ``read_expr`` appearing on the marked read line."""
    src = ("public class T {\n    public void m(String x) {\n"
           + body
           + f"        String r = {read_expr};\n"
           + "    }\n}\n")
    n_lines = src.count("\n") + 1
    resolver = build_table_resolver(src, (1, n_lines))
    if resolver is None:
        return REFUSE
    from core.analysis.cfg_builder_java import _get_parser
    tree = _get_parser().parse(src.encode())
    reads = []

    def find(n):
        if n.type == "array_access":
            reads.append(n)
        for c in n.children:
            find(c)

    find(tree.root_node)
    assert reads, "fixture must contain an array_access"
    return fold_expr(reads[-1], lambda _n, _d: REFUSE,
                     array_resolver=resolver)


class TestQualification:
    def test_literal_table_resolves(self):
        v = _resolve('        String[] values = {"a", "b"};\n')
        assert v == "b"

    def test_new_array_initializer_resolves(self):
        v = _resolve(
            '        String[] values = new String[]{"a", "b"};\n')
        assert v == "b"

    def test_int_table_resolves(self):
        v = _resolve("        int[] values = {105, 106};\n")
        assert v == 106

    def test_element_store_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n'
                     "        values[1] = x;\n")
        assert v is REFUSE

    def test_compound_element_store_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n'
                     "        values[1] += x;\n")
        assert v is REFUSE

    def test_element_update_refuses(self):
        v = _resolve("        int[] values = {1, 2};\n"
                     "        values[1]++;\n")
        assert v is REFUSE

    def test_bare_name_as_call_argument_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n'
                     "        java.util.Arrays.fill(values, x);\n")
        assert v is REFUSE

    def test_alias_assignment_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n'
                     "        String[] other = values;\n")
        assert v is REFUSE

    def test_second_declarator_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n'
                     '        if (x.length() > 1) '
                     '{ String[] values2 = {"c"}; }\n'
                     .replace("values2", "values"))
        assert v is REFUSE

    def test_oversize_table_refuses(self):
        elems = ", ".join(f'"{i}"' for i in range(33))
        v = _resolve(f"        String[] values = {{{elems}}};\n")
        assert v is REFUSE

    def test_out_of_bounds_refuses(self):
        v = _resolve('        String[] values = {"a"};\n',
                     read_expr="values[3]")
        assert v is REFUSE

    def test_non_constant_index_refuses(self):
        v = _resolve('        String[] values = {"a", "b"};\n',
                     read_expr="values[x.length()]")
        assert v is REFUSE

    def test_identifier_element_refuses(self):
        # Elements fold literal-only.
        v = _resolve('        String[] values = {x, "b"};\n',
                     read_expr="values[0]")
        assert v is REFUSE

    def test_hits_counter_increments(self):
        src = ('public class T {\n    public void m(String x) {\n'
               '        String[] values = {"a", "b"};\n'
               '        String r = values[0];\n'
               '    }\n}\n')
        n_lines = src.count("\n") + 1
        resolver = build_table_resolver(src, (1, n_lines))
        from core.analysis.cfg_builder_java import _get_parser
        tree = _get_parser().parse(src.encode())
        reads = []

        def find(n):
            if n.type == "array_access":
                reads.append(n)
            for c in n.children:
                find(c)

        find(tree.root_node)
        assert fold_expr(reads[-1], lambda _n, _d: REFUSE,
                         array_resolver=resolver) == "a"
        assert resolver.hits == 1


class TestGateIntegration:
    def _verdict(self, tmp_path, body_lines, src_ln, sink_ln):
        from core.analysis.finding_resolver import (
            ResolvedFinding,
            resolve_finding,
        )
        from core.analysis.sanitizer_cut import evaluate_finding
        src = (
            "import javax.servlet.http.HttpServletRequest;\n"
            "public class T {\n"
            "    public void handle(HttpServletRequest request, "
            "java.io.PrintWriter out) {\n"
            + "".join(f"        {ln}\n" for ln in body_lines)
            + "    }\n}\n"
        )
        f = tmp_path / "T.java"
        f.write_text(src)
        native = {
            "cwe": "CWE-79", "file_path": str(f),
            "source_line": src_ln, "sink_line": sink_ln,
            "language": "java", "rule_id": "t", "tool": "t",
        }
        resolved = resolve_finding(native)
        assert isinstance(resolved, ResolvedFinding)
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg, java_source_text=src,
        )
        return result

    def test_table_constant_sink_suppresses_with_annotation(
            self, tmp_path):
        result = self._verdict(tmp_path, [
            'String param = request.getParameter("q");',
            'String[] values = {"safe0", "safe1"};',
            'String bar = values[1];',
            'out.println(bar);'], 4, 7)
        assert result.verdict == "suppress"
        assert "constant-table load" in result.reason

    def test_store_before_read_does_not_suppress(self, tmp_path):
        result = self._verdict(tmp_path, [
            'String param = request.getParameter("q");',
            'String[] values = {"safe0", "safe1"};',
            'values[1] = param;',
            'String bar = values[1];',
            'out.println(bar);'], 4, 8)
        assert result.verdict != "suppress"

    def test_alias_store_does_not_suppress(self, tmp_path):
        result = self._verdict(tmp_path, [
            'String param = request.getParameter("q");',
            'String[] values = {"safe0", "safe1"};',
            'String[] other = values;',
            'other[1] = param;',
            'String bar = values[1];',
            'out.println(bar);'], 4, 9)
        assert result.verdict != "suppress"

    def test_tainted_element_does_not_suppress(self, tmp_path):
        result = self._verdict(tmp_path, [
            'String param = request.getParameter("q");',
            'String[] values = {param, "safe1"};',
            'String bar = values[0];',
            'out.println(bar);'], 4, 7)
        assert result.verdict != "suppress"

    def test_table_switch_discriminant_suppresses(self, tmp_path):
        result = self._verdict(tmp_path, [
            'String param = request.getParameter("q");',
            'int[] keys = {105, 106};',
            'String bar;',
            'switch (keys[1]) {', '  case 106:', '    bar = "safe";',
            '    break;', '  default:', '    bar = param;',
            '    break;', '}',
            'out.println(bar);'], 4, 15)
        assert result.verdict == "suppress"

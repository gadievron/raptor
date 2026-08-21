"""Unit tests for the Java intra-procedural CFG builder (b13 leg).

Soundness-critical pins:

* refusal list — constructs the builder can't model faithfully must
  refuse the whole build, never produce a wrong graph;
* the do-while back edge — a missing second-iteration path is the
  unsound direction for the vertex cut;
* import-resolved callable names — catalog FQN keys only match
  through explicit imports; instance calls never resolve;
* may_escape stamps — array access, field stores, System.arraycopy.
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import (  # noqa: E402
    build_import_map,
    build_java_intraproc_cfg,
    find_enclosing_method,
)


def _cfg(body: str, *, imports: str = "import org.owasp.encoder.Encode;\n",
         params: str = "String x, java.io.PrintWriter out",
         name: str = "handle"):
    src = (f"{imports}public class T {{\n"
           f"    public void {name}({params}) {{\n"
           f"{body}    }}\n}}\n")
    return build_java_intraproc_cfg(src, name), src


class TestImportMap:
    def test_type_and_static_imports(self):
        import tree_sitter_java as tsj
        from core.inventory.call_graph import _get_ts_parser
        parser = _get_ts_parser(tsj.language)
        src = (b"import org.owasp.encoder.Encode;\n"
               b"import static org.owasp.esapi.ESAPI.encoder;\n"
               b"import java.util.*;\n"
               b"class T {}\n")
        types, statics = build_import_map(parser.parse(src).root_node)
        assert types == {"Encode": "org.owasp.encoder.Encode"}
        assert statics == {"encoder": "org.owasp.esapi.ESAPI.encoder"}
        # The wildcard import resolved nothing (conservative).
        assert "util" not in types and "*" not in types


class TestCallableResolution:
    def test_imported_static_call_resolves_to_fqn(self):
        cfg, _ = _cfg("        String y = Encode.forHtml(x);\n"
                      "        out.println(y);\n")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" in calls

    def test_unimported_name_stays_surface(self):
        cfg, _ = _cfg("        String y = Encode.forHtml(x);\n"
                      "        out.println(y);\n", imports="")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "Encode.forHtml" in calls
        assert "org.owasp.encoder.Encode.forHtml" not in calls

    def test_esapi_chain_carries_call_marker(self):
        cfg, _ = _cfg(
            "        String y = ESAPI.encoder().encodeForHTML(x);\n"
            "        out.println(y);\n",
            imports="import org.owasp.esapi.ESAPI;\n")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.esapi.ESAPI.encoder().encodeForHTML" in calls

    def test_instance_call_never_gains_fqn(self):
        # ``enc`` is a variable — without type inference the callable
        # must stay surface-form so it can never match a catalog FQN.
        cfg, _ = _cfg("        String y = enc.encodeForHTML(x);\n"
                      "        out.println(y);\n",
                      params="String x, Object enc, "
                             "java.io.PrintWriter out")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "enc.encodeForHTML" in calls
        assert not any(c.startswith("org.owasp") for c in calls)

    def test_assigned_names_only_for_plain_identifier_lhs(self):
        cfg, _ = _cfg("        String y = Encode.forHtml(x);\n"
                      "        this.f = Encode.forHtml(x);\n"
                      "        out.println(y);\n")
        assert cfg is not None
        by_assign = {
            cs.assigned_names
            for n in cfg.nodes() for cs in n.call_sites
            if cs.name.endswith("forHtml")
        }
        assert frozenset({"y"}) in by_assign
        # The field-store call must NOT claim a clean assigned name.
        assert all(
            a in (frozenset(), frozenset({"y"})) for a in by_assign
        )


class TestRefusals:
    @pytest.mark.parametrize("body", [
        "        Runnable r = () -> out.println(x);\n",
        "        java.util.function.Function<String,Integer> f = "
        "String::length;\n",
        # Statement-position switch is modelled since the switch-CFG
        # work; VALUE-position switch (result feeding an expression)
        # still refuses — pinned here and in test_cfg_builder_java_switch.
        '        String s = switch (x.length()) '
        '{ case 1 -> "a"; default -> "b"; };\n',
        "        outer: for (int i = 0; i < 2; i++) { break outer; }\n",
        "        class Local { void m() {} }\n",
    ])
    def test_refused_constructs_refuse_the_build(self, body):
        cfg, _ = _cfg(body + "        out.println(x);\n")
        assert cfg is None

    def test_plain_method_builds(self):
        cfg, _ = _cfg("        String y = Encode.forHtml(x);\n"
                      "        out.println(y);\n")
        assert cfg is not None


class TestControlFlowSoundness:
    def test_do_while_second_iteration_path_exists(self):
        # ``y = clean(x); do { out.println(y); y = x; } while (c);``
        # On iteration ≥2 the sink sees the REBOUND value — that path
        # only exists via the loop back edge. Both definitions must
        # reach the sink; with the back edge missing, only the
        # sanitizer would, and the gate would falsely suppress.
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        do {\n"
            "            out.println(y);\n"
            "            y = x;\n"
            "        } while (x.length() > 0);\n",
        )
        assert cfg is not None
        from core.analysis.dataflow import reaching_defs
        rd = reaching_defs(cfg)
        sink = next(n for n in cfg.nodes() if "println" in n.label)
        definers = rd.at(sink, "y")
        sanitize = next(n for n in cfg.nodes() if "forHtml" in n.label)
        rebind = next(
            n for n in cfg.nodes()
            if n.kind == "stmt" and n.label.startswith("y = x")
        )
        assert sanitize in definers
        assert rebind in definers, (
            "do-while back edge missing: iteration-2 rebind does not "
            "reach the sink — false-suppression hazard"
        )
        # And the gate must therefore refuse to suppress.
        from core.analysis.sanitizer_cut import (
            VERDICT_SUPPRESS,
            evaluate_finding,
        )
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink, cwe="CWE-79", language="java",
            source_symbols=frozenset(cfg.params), sink_arg="y",
        )
        assert result.verdict != VERDICT_SUPPRESS

    def test_try_body_statement_reaches_catch(self):
        cfg, _ = _cfg(
            "        try {\n"
            "            String y = Encode.forHtml(x);\n"
            "            out.println(y);\n"
            "        } catch (Exception e) {\n"
            "            out.println(x);\n"
            "        }\n",
        )
        assert cfg is not None
        decl = next(n for n in cfg.nodes() if "forHtml" in n.label)
        succ_labels = {s.label for s in cfg.successors(decl)}
        assert any(lbl.startswith("catch") for lbl in succ_labels), (
            "liberal try→catch edge missing"
        )

    def test_params_include_varargs(self):
        src = ("public class T { public void h(String a, int... rest) "
               "{ int y = a.length(); } }")
        cfg = build_java_intraproc_cfg(src, "h")
        assert cfg is not None
        assert cfg.params == ("a", "rest")

    def test_overload_selected_by_line_hint(self):
        src = ("public class T {\n"
               "    public void h(String x) {\n"
               "        sinkA(x);\n"
               "    }\n"
               "    public void h(String x, int n) {\n"
               "        sinkB(x);\n"
               "    }\n"
               "}\n")
        cfg = build_java_intraproc_cfg(src, "h", line_hint=(5, 6))
        assert cfg is not None
        labels = {n.label for n in cfg.nodes()}
        assert any("sinkB" in lbl for lbl in labels)
        assert not any("sinkA" in lbl for lbl in labels)


class TestMayEscape:
    @pytest.mark.parametrize("stmt,expect", [
        ("        a[0] = x;\n", True),
        ("        this.f = x;\n", True),
        ("        System.arraycopy(a, 0, b, 0, 2);\n", True),
        ("        String y = x;\n", False),
        ("        int n = q.w;\n", False),   # field READ is not a store
    ])
    def test_escape_stamps(self, stmt, expect):
        cfg, _ = _cfg(stmt + "        out.println(x);\n",
                      params="String x, String[] a, String[] b, T q, "
                             "java.io.PrintWriter out")
        assert cfg is not None
        # The probed statement is the method body's first line:
        # imports (1) + class header (2) + method header (3) → line 4.
        node = next(n for n in cfg.nodes() if n.lineno == 4)
        assert node.may_escape is expect


class TestEnclosingMethod:
    def test_finds_spanning_method(self):
        src = ("public class T {\n"
               "    public void a(String x) {\n"
               "        one(x);\n"
               "    }\n"
               "    public void b(String x) {\n"
               "        two(x);\n"
               "    }\n"
               "}\n")
        name, header = find_enclosing_method(src, 6, 6)
        assert (name, header) == ("b", 5)

    def test_no_spanning_method(self):
        name, header = find_enclosing_method("class T {}", 1, 1)
        assert name is None and header == 0

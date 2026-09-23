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


class TestScale:
    @pytest.mark.slow
    def test_straight_line_build_is_not_quadratic(self):
        # Twin of the C/C++ builder's bound — the per-node list scan
        # was duplicated across both legs.
        import time
        n = 16000
        body = "".join(f"        int v{i} = {i};\n" for i in range(n))
        cfg, _ = _cfg(body)
        t0 = time.monotonic()
        cfg, _ = _cfg(body)
        elapsed = time.monotonic() - t0
        assert cfg is not None
        assert elapsed < 5.0, f"CFG build took {elapsed:.1f}s at n={n}"


class TestShadowedImportIdentity:
    """Java permits variables named like imported classes (JLS 6.4.2
    obscuring) — a local receiver must never resolve through the
    import map to a catalog class's static identity."""

    SHADOW_BODY = (
        "        FakeEncoder Encode = new FakeEncoder();\n"
        "        String y = Encode.forHtml(x);\n"
        "        out.println(y);\n"
    )

    def test_local_shadowing_import_never_resolves_to_fqn(self):
        cfg, _ = _cfg(self.SHADOW_BODY)
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" not in calls, (
            "instance call through a shadowing local forged the "
            "catalog FQN"
        )

    def test_shadowing_receiver_is_a_value_use(self):
        # The receiver is a live value, not a namespace — hiding it
        # from the uses walk hid the tainted object from the gate.
        cfg, _ = _cfg(self.SHADOW_BODY)
        uses = set()
        for n in cfg.nodes():
            uses |= set(n.uses)
        assert "Encode" in uses

    def test_shadow_mints_no_sanitizer_binding(self):
        from core.dataflow.sanitizer_catalog import (
            match_sanitizers_in_cfg,
        )
        cfg, _ = _cfg(self.SHADOW_BODY)
        bindings = match_sanitizers_in_cfg(cfg, "cwe-079", "java")
        assert not bindings, bindings

    def test_same_file_method_shadowing_static_import_never_binds(self):
        # JLS 15.12.1: methods of the enclosing class shadow
        # single-static-imports for bare calls — the runtime callee is
        # the repo's method, not the catalog identity the import
        # spelling suggests.
        from core.dataflow.sanitizer_catalog import (
            match_sanitizers_in_cfg,
        )
        src = (
            "import static org.owasp.encoder.Encode.forHtml;\n"
            "public class T {\n"
            "    String forHtml(String s) { return s; }\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        String y = forHtml(x);\n"
            "        out.println(y);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" not in calls
        assert not match_sanitizers_in_cfg(cfg, "cwe-079", "java")

    def test_unshadowed_static_import_still_resolves(self):
        # Control: no same-file method of that name — the static
        # import keeps its identity.
        src = (
            "import static org.owasp.encoder.Encode.forHtml;\n"
            "public class T {\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        String y = forHtml(x);\n"
            "        out.println(y);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" in calls

    def test_member_inner_class_shadowing_import_never_binds(self):
        # JLS 6.4.1: a member type declared in the file shadows a
        # single-type import for simple-name references — the runtime
        # callee is the REPO's inner class, not the catalog class.
        from core.dataflow.sanitizer_catalog import (
            match_sanitizers_in_cfg,
        )
        src = (
            "import org.owasp.encoder.Encode;\n"
            "public class T {\n"
            "    static class Encode { static String forHtml"
            "(String s) { return s; } }\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        String y = Encode.forHtml(x);\n"
            "        out.println(y);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" not in calls
        assert not match_sanitizers_in_cfg(cfg, "cwe-079", "java")

    def test_nested_inner_class_shadow_also_blocks(self):
        # File-wide type-shadow set: a doubly-nested member type
        # blocks the join too (over-broad only in the refusal
        # direction — a blocked name never GRANTS identity).
        src = (
            "import org.owasp.encoder.Encode;\n"
            "public class T {\n"
            "    static class Outer { static class Encode { "
            "static String forHtml(String s) { return s; } } }\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        String y = Encode.forHtml(x);\n"
            "        out.println(y);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" not in calls

    def test_type_parameter_shadow_also_blocks(self):
        # A type variable shadows the import as well (JLS 6.4.1).
        # Static access through a type variable does not COMPILE, but
        # semgrep-lane findings ride non-compiling hostile source, so
        # the analysis-level join is blocked anyway (belt and braces).
        src = (
            "import org.owasp.encoder.Encode;\n"
            "public class T<Encode> {\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        String y = Encode.forHtml(x);\n"
            "        out.println(y);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "org.owasp.encoder.Encode.forHtml" not in calls

    def test_shadowing_creation_type_never_resolves(self):
        # 'new Encode(...)' with the member inner class in scope must
        # not surface as the catalog class's constructor either.
        src = (
            "import org.owasp.encoder.Encode;\n"
            "public class T {\n"
            "    static class Encode { }\n"
            "    public void handle(String x, "
            "java.io.PrintWriter out) {\n"
            "        Object o = new Encode();\n"
            "        out.println(x);\n"
            "    }\n"
            "}\n"
        )
        cfg = build_java_intraproc_cfg(src, "handle")
        assert cfg is not None
        calls = {cs.name for n in cfg.nodes() for cs in n.call_sites}
        assert "new org.owasp.encoder.Encode" not in calls

    def test_true_static_call_still_binds(self):
        # Control: the genuine import-resolved static call keeps its
        # catalog identity and full-strength binding.
        from core.dataflow.sanitizer_catalog import (
            match_sanitizers_in_cfg,
        )
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        out.println(y);\n")
        bindings = match_sanitizers_in_cfg(cfg, "cwe-079", "java")
        assert any(
            b.callable == "org.owasp.encoder.Encode.forHtml"
            for b in bindings)


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

    def test_do_while_continue_targets_condition(self):
        # JLS 14.16: ``continue`` in a do-while transfers to the
        # CONDITION. Linking it to the body entry instead forces every
        # modelled continue path back through the whole body — the
        # "sanitizer skipped via continue" route disappears and the
        # value gate falsely suppresses. The C/C++ leg targets the
        # condition; this pins the Java leg to the same contract.
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        do {\n"
            "            if (cond(x)) continue;\n"
            "            y = Encode.forHtml(x);\n"
            "        } while (more(x));\n"
            "        out.println(y);\n",
        )
        assert cfg is not None
        cont = next(n for n in cfg.nodes() if n.label == "continue;")
        succ = list(cfg.successors(cont))
        assert any(s.label.startswith("do-while") for s in succ), (
            "continue must link to the do-while condition"
        )
        assert not any(s.label == "do" for s in succ), (
            "continue must not re-enter the body head"
        )
        # E2E: runtime can reach the sink with the tainted initial
        # binding via continue → condition-false → exit, never running
        # the sanitizer — the gate must refuse to suppress.
        from core.analysis.sanitizer_cut import (
            VERDICT_SUPPRESS,
            evaluate_finding,
        )
        sink = next(n for n in cfg.nodes() if "println" in n.label)
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink, cwe="CWE-79", language="java",
            source_symbols=frozenset(cfg.params), sink_arg="y",
        )
        assert result.verdict != VERDICT_SUPPRESS, (
            "do-while continue→condition path missing: false suppression"
        )

    def test_do_while_break_exits_without_evaluating_condition(self):
        # JLS 14.15: ``break`` transfers past the whole do statement —
        # the tail condition is NEVER evaluated on that path. Routing
        # break through the condition node made the condition falsely
        # DOMINATE post-loop code, and dominance consumers (SMT guard
        # collection) then asserted a guard the code does not have at
        # sinks reached via break.
        cfg, _ = _cfg(
            "        do {\n"
            "            step(x);\n"
            "            if (cond(x)) break;\n"
            "        } while (retry(x));\n"
            "        out.println(x);\n",
        )
        assert cfg is not None
        from core.analysis.dominators import build_dom_tree
        dom = build_dom_tree(cfg)
        cond = next(n for n in cfg.nodes()
                    if n.label.startswith("do-while "))
        sink = next(n for n in cfg.nodes() if "println" in n.label)
        assert not dom.dominates(cond, sink), (
            "do-while condition must not dominate post-loop code: the "
            "break path never evaluates it"
        )
        brk = next(n for n in cfg.nodes() if n.label == "break;")
        assert cond not in cfg.successors(brk), (
            "break must not route through the loop condition"
        )
        # The exit path is still connected.
        reach = {cfg.entry_node}
        stack = [cfg.entry_node]
        while stack:
            for s2 in cfg.successors(stack.pop()):
                if s2 not in reach:
                    reach.add(s2)
                    stack.append(s2)
        assert sink in reach and cfg.exit_node in reach

    def test_do_while_without_break_condition_dominates_after(self):
        # Control (two directions): with no break, every exit from the
        # loop goes through the condition — dominance must survive the
        # break fix (real guards must not be lost).
        cfg, _ = _cfg(
            "        do {\n"
            "            step(x);\n"
            "        } while (retry(x));\n"
            "        out.println(x);\n",
        )
        assert cfg is not None
        from core.analysis.dominators import build_dom_tree
        dom = build_dom_tree(cfg)
        cond = next(n for n in cfg.nodes()
                    if n.label.startswith("do-while "))
        sink = next(n for n in cfg.nodes() if "println" in n.label)
        assert dom.dominates(cond, sink)

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


class TestEmbeddedStoreDefs:
    """Assignments embedded in conditions / for-updates / resource
    clauses must surface as ``defs`` — an invisible definer lets the
    value-bound gate's condition-3 exclusivity hold falsely on a live
    re-taint (``if (flag && (y = x) != null)`` then ``sink(y)``)."""

    def _node_with_def(self, cfg, name):
        return [n for n in cfg.nodes() if name in n.defs]

    def test_assignment_in_condition_defines(self):
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        if ((y = x) != null) { }\n"
            "        out.println(y);\n",
        )
        definers = self._node_with_def(cfg, "y")
        assert any(n.label.startswith("if") for n in definers), (
            f"condition write of y invisible: "
            f"{[(n.label, sorted(n.defs)) for n in cfg.nodes()]}"
        )

    def test_assignment_in_condition_earns_no_assigned_names(self):
        # Refusal direction: the embedded def must not grant
        # sanitizer-output identity via call-site assigned_names.
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        if ((y = Encode.forHtml(x)) != null) { }\n"
            "        out.println(y);\n",
        )
        cond = next(n for n in cfg.nodes() if n.label.startswith("if"))
        assert "y" in cond.defs
        assert all(not cs.assigned_names for cs in cond.call_sites)

    def test_while_assignment_condition_defines(self):
        cfg, _ = _cfg(
            "        String line = \"\";\n"
            "        while ((line = x) != null) { }\n"
            "        out.println(line);\n",
        )
        definers = self._node_with_def(cfg, "line")
        assert any(n.label.startswith("while") for n in definers)

    def test_for_update_expression_defines(self):
        cfg, _ = _cfg(
            "        for (int i = 0; i < 3; i++) { }\n"
            "        out.println(x);\n",
            params="String x, java.io.PrintWriter out",
        )
        assert any(
            "i" in n.defs and n.label.startswith("i++")
            for n in cfg.nodes()
        ), f"for-update def missing: " \
           f"{[(n.label, sorted(n.defs)) for n in cfg.nodes()]}"

    def test_condition_without_store_defines_nothing(self):
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        if (y != null) { }\n"
            "        out.println(y);\n",
        )
        cond = next(n for n in cfg.nodes() if n.label.startswith("if"))
        assert cond.defs == frozenset()


class TestEmbeddedStoreDefsExpressionContexts:
    """The condition fix's expression-context siblings: an embedded
    assignment writes its target in EVERY context — declaration
    initializers and assignment RHS included, not an enumerated
    subset (`String z = (y = x);` left y's rebind invisible)."""

    def test_decl_initializer_embedded_assignment_defines(self):
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        String z = (y = x);\n"
            "        out.println(y);\n",
        )
        decl = next(n for n in cfg.nodes() if "z" in n.defs)
        assert "y" in decl.defs

    def test_assignment_rhs_embedded_assignment_defines(self):
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        String z;\n"
            "        z = (y = x);\n"
            "        out.println(y);\n",
        )
        assign = next(
            n for n in cfg.nodes() if n.lineno == 6 and "z" in n.defs
        )
        assert "y" in assign.defs

    def test_embedded_store_earns_no_assigned_names_in_initializer(self):
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        String z = (y = Encode.forHtml(x));\n"
            "        out.println(y);\n",
        )
        decl = next(n for n in cfg.nodes() if "z" in n.defs)
        assert "y" in decl.defs
        # The call's return flows into the embedded target, but the
        # gate must not treat that as a clean rebinding of z OR y
        # through this statement's call site beyond the z slot it
        # already owns.
        for cs in decl.call_sites:
            assert "y" not in cs.assigned_names

    def test_enhanced_for_iterable_embedded_assignment_defines(self):
        cfg, _ = _cfg(
            "        String[] arr = new String[1];\n"
            "        String y = Encode.forHtml(x);\n"
            "        for (String s : (arr = new String[]{(y = x)})) { }\n"
            "        out.println(y);\n",
        )
        header = next(
            n for n in cfg.nodes() if n.label.startswith("for ")
        )
        assert "y" in header.defs and "arr" in header.defs


class TestSynchronizedLockExpression:
    """The lock expression evaluates before the body — dropping its
    subtree leaves embedded re-taint stores invisible to reaching-defs
    and lets refused constructs inside the lock build a wrong graph
    instead of refusing."""

    def test_lock_expression_store_is_visible_definer(self):
        cfg, _ = _cfg(
            "        String y = Encode.forHtml(x);\n"
            "        synchronized (y = x) {\n"
            "            out.println(y);\n"
            "        }\n",
        )
        assert cfg is not None
        lock = next(
            n for n in cfg.nodes() if n.label.startswith("synchronized")
        )
        assert "y" in lock.defs
        assert "x" in lock.uses
        from core.analysis.dataflow import reaching_defs
        rd = reaching_defs(cfg)
        sink = next(n for n in cfg.nodes() if "println" in n.label)
        assert lock in rd.at(sink, "y"), (
            "lock-expression re-taint does not reach the sink — the "
            "value gate's exclusivity proof would hold falsely"
        )
        # E2E: the gate must refuse to suppress over the live re-taint.
        from core.analysis.sanitizer_cut import (
            VERDICT_SUPPRESS,
            evaluate_finding,
        )
        result = evaluate_finding(
            cfg, [cfg.entry_node], sink, cwe="CWE-79", language="java",
            source_symbols=frozenset(cfg.params), sink_arg="y",
        )
        assert result.verdict != VERDICT_SUPPRESS

    def test_lock_expression_call_earns_no_assigned_names(self):
        # Refusal direction: a store embedded in the lock breaks
        # exclusivity but never grants sanitizer-output identity.
        cfg, _ = _cfg(
            "        String y = x;\n"
            "        synchronized (y = Encode.forHtml(x)) {\n"
            "            out.println(y);\n"
            "        }\n",
        )
        assert cfg is not None
        lock = next(
            n for n in cfg.nodes() if n.label.startswith("synchronized")
        )
        assert "y" in lock.defs
        assert "org.owasp.encoder.Encode.forHtml" in lock.calls
        assert all(not cs.assigned_names for cs in lock.call_sites)

    def test_lambda_in_lock_expression_refuses(self):
        cfg, _ = _cfg(
            "        synchronized (locks.computeIfAbsent(x, "
            "key -> new Object())) {\n"
            "            out.println(x);\n"
            "        }\n",
            params="String x, java.util.Map<String,Object> locks, "
                   "java.io.PrintWriter out",
        )
        assert cfg is None, (
            "lambda inside the lock expression must refuse the build "
            "(docstring refusal contract)"
        )

    def test_method_reference_in_lock_expression_refuses(self):
        cfg, _ = _cfg(
            "        synchronized (pick(String::length)) {\n"
            "            out.println(x);\n"
            "        }\n",
        )
        assert cfg is None

    def test_plain_lock_wires_body_through_lock_node(self):
        cfg, _ = _cfg(
            "        synchronized (this) {\n"
            "            out.println(x);\n"
            "        }\n",
        )
        assert cfg is not None
        lock = next(
            n for n in cfg.nodes() if n.label.startswith("synchronized")
        )
        succ = list(cfg.successors(lock))
        assert any("println" in s.label for s in succ), (
            "body must be wired through the lock node"
        )

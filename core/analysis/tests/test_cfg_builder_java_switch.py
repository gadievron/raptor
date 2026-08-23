"""Switch modelling in the Java CFG builder.

Soundness pins run in BOTH directions: shapes the constant refinement
must prune (proof-backed dead branches) and shapes where a missing
edge would be a false suppression (fall-through into a re-taint,
non-constant discriminants, tainted-branch selection).
"""
from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter_java")

from core.analysis.cfg_builder_java import build_java_intraproc_cfg  # noqa: E402
from core.analysis.dataflow import reaching_defs  # noqa: E402


def _cfg(body: str, *,
         imports: str = "import org.owasp.encoder.Encode;\n",
         params: str = "String x, int k, java.io.PrintWriter out",
         name: str = "handle"):
    src = (f"{imports}public class T {{\n"
           f"    public void {name}({params}) {{\n"
           f"{body}    }}\n}}\n")
    return build_java_intraproc_cfg(src, name), src


def _by_label(cfg, prefix: str):
    hits = [n for n in cfg.nodes() if n.label.startswith(prefix)]
    assert hits, f"no node labelled {prefix!r}"
    return hits[0]


def _succ_labels(cfg, node):
    return {s.label for s in cfg.successors(node)}


_CLASSIC = (
    "        String y;\n"
    "        switch (k) {\n"
    "          case 1:\n"
    "            y = Encode.forHtml(x);\n"
    "            break;\n"
    "          default:\n"
    "            y = x;\n"
    "            break;\n"
    "        }\n"
    "        out.println(y);\n"
)


class TestClassicSwitchShape:
    def test_all_branches_for_nonconstant_discriminant(self):
        cfg, _ = _cfg(_CLASSIC)
        assert cfg is not None
        assert "switch:all-branches" in cfg.build_notes
        cond = _by_label(cfg, "switch ")
        succ = _succ_labels(cfg, cond)
        assert any("case 1" in s for s in succ)
        assert any("default" in s for s in succ)

    def test_break_targets_join_not_loop(self):
        # break inside a switch inside a loop exits the SWITCH.
        cfg, _ = _cfg(
            "        for (int i = 0; i < k; i++) {\n"
            "          switch (i) {\n"
            "            default:\n"
            "              break;\n"
            "          }\n"
            "          out.println(i);\n"
            "        }\n"
        )
        assert cfg is not None
        brk = _by_label(cfg, "break;")
        assert _succ_labels(cfg, brk) == {"switch-end"}

    def test_missing_default_adds_cond_to_join_edge(self):
        cfg, _ = _cfg(
            "        switch (k) {\n"
            "          case 1:\n"
            "            out.println(x);\n"
            "            break;\n"
            "        }\n"
            "        out.println(k);\n"
        )
        cond = _by_label(cfg, "switch ")
        assert "switch-end" in _succ_labels(cfg, cond)

    def test_fallthrough_edge_exists(self):
        # Group without break flows into the next group's entry.
        cfg, _ = _cfg(
            "        String y;\n"
            "        switch (k) {\n"
            "          case 1:\n"
            "            y = Encode.forHtml(x);\n"
            "          default:\n"
            "            y = x;\n"
            "            break;\n"
            "        }\n"
            "        out.println(y);\n"
        )
        sanitize = _by_label(cfg, "y = Encode.forHtml(x);")
        assert any("default" in s for s in _succ_labels(cfg, sanitize))

    def test_arrow_rules_do_not_fall_through(self):
        cfg, _ = _cfg(
            "        String y;\n"
            "        switch (k) {\n"
            "          case 1 -> { y = Encode.forHtml(x); }\n"
            "          default -> { y = x; }\n"
            "        }\n"
            "        out.println(y);\n"
        )
        assert cfg is not None
        sanitize = _by_label(cfg, "y = Encode.forHtml(x);")
        assert _succ_labels(cfg, sanitize) == {"switch-end"}


class TestConstantRefinement:
    _CONST = _CLASSIC.replace("switch (k)", "switch (num)")

    def _const_cfg(self, num_line: str):
        return _cfg(f"        {num_line}\n" + self._CONST)

    def test_selected_branch_only(self):
        cfg, _ = self._const_cfg("int num = 1;")
        assert "switch:constant-resolved" in cfg.build_notes
        cond = _by_label(cfg, "switch ")
        succ = _succ_labels(cfg, cond)
        assert any("case 1" in s for s in succ)
        assert not any("default" in s for s in succ)

    def test_no_match_selects_default(self):
        cfg, _ = self._const_cfg("int num = 9;")
        assert "switch:constant-resolved" in cfg.build_notes
        cond = _by_label(cfg, "switch ")
        succ = _succ_labels(cfg, cond)
        assert any("default" in s for s in succ)
        assert not any("case 1" in s for s in succ)

    def test_no_match_no_default_keeps_join_only(self):
        cfg, _ = _cfg(
            "        int num = 9;\n"
            "        switch (num) {\n"
            "          case 1:\n"
            "            out.println(x);\n"
            "            break;\n"
            "        }\n"
            "        out.println(k);\n"
        )
        assert "switch:constant-resolved" in cfg.build_notes
        cond = _by_label(cfg, "switch ")
        assert _succ_labels(cfg, cond) == {"switch-end"}

    def test_pruned_branch_defs_do_not_reach(self):
        # The dead default's ``y = x`` must not appear among the
        # sink's reaching definers (reaching_defs is restricted to
        # entry-reachable nodes).
        cfg, _ = self._const_cfg("int num = 1;")
        rd = reaching_defs(cfg)
        sink = _by_label(cfg, "out.println(y);")
        definers = {d.label for d in rd.at(sink, "y")}
        assert definers == {"y = Encode.forHtml(x);"}

    def test_string_discriminant_resolves(self):
        cfg, _ = _cfg(
            '        String mode = "b";\n'
            "        String y;\n"
            "        switch (mode) {\n"
            '          case "a":\n'
            "            y = x;\n"
            "            break;\n"
            '          case "b":\n'
            "            y = Encode.forHtml(x);\n"
            "            break;\n"
            "        }\n"
            "        out.println(y);\n"
        )
        assert "switch:constant-resolved" in cfg.build_notes
        cond = _by_label(cfg, "switch ")
        succ = _succ_labels(cfg, cond)
        assert not any('case "a"' in s for s in succ)

    def test_identifier_label_keeps_all_branches(self):
        # Constant-variable labels are out of the literal-only label
        # fold's scope — every edge stays.
        cfg, _ = _cfg(
            "        final int ONE = 1;\n"
            "        int num = 1;\n"
            "        switch (num) {\n"
            "          case ONE:\n"
            "            out.println(x);\n"
            "            break;\n"
            "          default:\n"
            "            out.println(k);\n"
            "            break;\n"
            "        }\n"
        )
        assert "switch:all-branches" in cfg.build_notes

    def test_reassigned_discriminant_keeps_all_branches(self):
        # Disagreeing reaching defs of the discriminant refuse.
        cfg, _ = _cfg(
            "        int num = 1;\n"
            "        if (k > 2) { num = 2; }\n" + self._CONST,
        )
        assert "switch:all-branches" in cfg.build_notes


class TestSwitchRefusals:
    @pytest.mark.parametrize("body", [
        # value position
        '        String s = switch (k) { case 1 -> "a"; '
        'default -> "b"; };\n        out.println(s);\n',
        # pattern label
        "        Object o = x;\n"
        "        switch (o) { case Integer i when i > 2 -> "
        "out.println(i); default -> out.println(1); }\n",
        # yield
        "        int v = switch (k) { case 1: yield 2; "
        "default: yield 3; };\n",
    ])
    def test_refused_switch_shapes(self, body):
        cfg, _ = _cfg(body)
        assert cfg is None


class TestGateVerdictsThroughSwitch:
    """End-to-end evaluate_finding over switch shapes (tmp files)."""

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
        return result.verdict

    _SWITCH = [
        'String param = request.getParameter("q");',
        None,  # discriminant line placeholder
        'String bar;',
        'switch (num) {', '  case 106:', '    bar = "safe";',
        '    break;', '  default:', '    bar = param;',
        '    break;', '}',
        'out.println(bar);',
    ]

    def _body(self, num_line, drop_break=False):
        body = list(self._SWITCH)
        body[1] = num_line
        if drop_break:
            body.remove('    break;')
        return body

    def test_constant_selected_safe_branch_suppresses(self, tmp_path):
        assert self._verdict(
            tmp_path, self._body('int num = 106;'), 4, 15,
        ) == "suppress"

    def test_nonconstant_discriminant_does_not_suppress(self, tmp_path):
        assert self._verdict(
            tmp_path, self._body('int num = request.getIntHeader("n");'),
            4, 15,
        ) != "suppress"

    def test_constant_selecting_tainted_branch_does_not_suppress(
            self, tmp_path):
        assert self._verdict(
            tmp_path, self._body('int num = 105;'), 4, 15,
        ) != "suppress"

    def test_fallthrough_retaint_does_not_suppress(self, tmp_path):
        # Selected safe case falls through into ``bar = param``.
        assert self._verdict(
            tmp_path, self._body('int num = 106;', drop_break=True),
            4, 14,
        ) != "suppress"

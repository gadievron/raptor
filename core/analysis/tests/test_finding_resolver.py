"""Tests for ``core.analysis.finding_resolver`` — Phase 5 of the
value-binding arc.

Three input formats supported end-to-end (Python only); each gets a
happy-path test plus failure-mode coverage. The end-to-end test
feeds the resolved finding into Phase 4's ``evaluate_finding`` and
asserts the wrong-variable case lands at ``candidate_only`` — the
whole arc's correctness witness in one assertion.
"""
from __future__ import annotations

import dataclasses
from pathlib import Path

from core.analysis.cfg_builder import PyCFGNode
from core.analysis.finding_resolver import (
    ResolutionFailure,
    ResolvedFinding,
    _ParsedFinding,
    _read_finding_source,
    resolve_finding,
)
from core.analysis.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_SUPPRESS,
    evaluate_finding,
)
from core.testing.treesitter import requires_ts

# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


WRONG_VARIABLE_SRC = (
    "def handle(user, other):\n"
    "    safe_other = html.escape(other)\n"
    "    render(user.name)\n"
)

STRAIGHT_LINE_SAFE_SRC = (
    "def handle(x):\n"
    "    y = html.escape(x)\n"
    "    render(y)\n"
)


def _write(tmp_path: Path, name: str, src: str) -> Path:
    f = tmp_path / name
    f.write_text(src, encoding="utf-8")
    return f


def _sarif_result(file_path: str, source_line: int, sink_line: int):
    return {
        "ruleId": "py/xss",
        "message": {"text": "Cross-site scripting"},
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {"uri": file_path},
                "region": {"startLine": sink_line},
            },
        }],
        "codeFlows": [{
            "threadFlows": [{
                "locations": [
                    {"location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {"startLine": source_line},
                        },
                    }},
                    {"location": {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file_path},
                            "region": {"startLine": sink_line},
                        },
                    }},
                ],
            }],
        }],
        "properties": {
            "tags": [
                "security", "external/cwe/cwe-079", "external/cwe/cwe-116",
            ],
        },
    }


def _semgrep_finding(file_path: str, source_line: int, sink_line: int):
    return {
        "check_id": "python.flask.security.xss",
        "path": file_path,
        "start": {"line": source_line, "col": 1},
        "end": {"line": sink_line, "col": 30},
        "extra": {
            "message": "XSS",
            "metadata": {"cwe": ["CWE-79: Improper Neutralization of Input"]},
            "dataflow_trace": {
                "taint_source": [{
                    "location": {
                        "path": file_path,
                        "start": {"line": source_line, "col": 5},
                    },
                }],
                "taint_sink": {
                    "location": {
                        "path": file_path,
                        "start": {"line": sink_line, "col": 5},
                    },
                },
            },
        },
    }


def _raptor_native(file_path: str, source_line: int, sink_line: int, **extra):
    return {
        "cwe": "CWE-79",
        "file_path": file_path,
        "source_line": source_line,
        "sink_line": sink_line,
        "language": "python",
        **extra,
    }


# ---------------------------------------------------------------------------
# Happy path — three formats reach the same ResolvedFinding shape
# ---------------------------------------------------------------------------


class TestSARIFHappyPath:
    def test_sarif_wrong_variable_resolves_to_full_finding(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _sarif_result(str(src_file), source_line=1, sink_line=3)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.cwe == "CWE-79"
        assert result.language == "python"
        assert result.enclosing_function == "handle"
        # source_line == 1 (FunctionDef.lineno) → params source
        assert result.source_symbols == frozenset({"user", "other"})
        # sink_line == 3, call is render(user.name) → sink_arg = user
        assert result.sink_arg == "user"
        # CFG node refs hydrated
        assert isinstance(result.source_node, PyCFGNode)
        assert isinstance(result.sink_node, PyCFGNode)


class TestSemgrepHappyPath:
    def test_semgrep_wrong_variable_resolves(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _semgrep_finding(str(src_file), source_line=1, sink_line=3)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.cwe == "CWE-79"
        assert result.source_symbols == frozenset({"user", "other"})
        assert result.sink_arg == "user"


class TestRaptorNativeHappyPath:
    def test_raptor_native_wrong_variable_resolves(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=3)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.cwe == "CWE-79"
        assert result.source_symbols == frozenset({"user", "other"})
        assert result.sink_arg == "user"

    def test_raptor_native_with_sink_arg_hint(self, tmp_path):
        """When the upstream tool knows which arg is dangerous,
        it can pass a hint and the resolver uses that exact name."""
        src = (
            "def handle(safe, user):\n"
            "    render(user.name, safe=safe)\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(
            str(src_file), source_line=1, sink_line=2,
            sink_arg="user",
        )
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.sink_arg == "user"


# ---------------------------------------------------------------------------
# Source resolution — entry vs body
# ---------------------------------------------------------------------------


class TestSourceResolution:
    def test_function_entry_source_uses_params(self, tmp_path):
        """source_line == FunctionDef.lineno → cfg.entry as the
        source node and cfg.params as the source symbols."""
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=3)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.source_node is result.cfg.entry_node
        assert result.source_symbols == frozenset({"user", "other"})

    def test_body_assign_source_uses_defs(self, tmp_path):
        """source_line is a body assignment → source_symbols are the
        LHS names of that assignment."""
        src = (
            "def handle(request):\n"
            "    user_input = request.body\n"
            "    y = html.escape(user_input)\n"
            "    render(y)\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(str(src_file), source_line=2, sink_line=4)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.source_symbols == frozenset({"user_input"})

    def test_body_non_assign_source_falls_back_to_uses(self, tmp_path):
        """A non-Assign source statement (e.g. ``if check(x):``) has
        no defs; resolver falls back to uses for best-effort taint
        modelling."""
        src = (
            "def handle(x):\n"
            "    if check(x):\n"
            "        return 0\n"
            "    render(x)\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(str(src_file), source_line=2, sink_line=4)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        # If header has uses={x} (no defs), so source_symbols=={x}.
        assert "x" in result.source_symbols


# ---------------------------------------------------------------------------
# End-to-end — resolved finding feeds Phase 4
# ---------------------------------------------------------------------------


class TestEndToEnd:
    """The whole point of the arc: resolver + Phase 4 gate together
    refuse the wrong-variable false suppression and confirm the
    legitimate ones."""

    def test_wrong_variable_resolves_then_gate_emits_candidate_only(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=3)
        resolved = resolve_finding(finding)
        assert isinstance(resolved, ResolvedFinding)
        # The whole arc's payoff: feed the resolved finding straight
        # into evaluate_finding and confirm the false suppression
        # is refused.
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
        )
        assert result.verdict == VERDICT_CANDIDATE_ONLY

    def test_safe_straight_line_gate_emits_suppress(self, tmp_path):
        src_file = _write(tmp_path, "app.py", STRAIGHT_LINE_SAFE_SRC)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=3)
        resolved = resolve_finding(finding)
        assert isinstance(resolved, ResolvedFinding)
        result = evaluate_finding(
            resolved.cfg, [resolved.source_node], resolved.sink_node,
            cwe=resolved.cwe, language=resolved.language,
            source_symbols=resolved.source_symbols,
            sink_arg=resolved.sink_arg,
        )
        assert result.verdict == VERDICT_SUPPRESS


# ---------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------


class TestFailureModes:
    def test_unknown_format_returns_failure(self):
        result = resolve_finding({"random": "stuff"})
        assert isinstance(result, ResolutionFailure)
        assert "unknown" in result.reason.lower()

    def test_sarif_without_cwe_tag_fails(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _sarif_result(str(src_file), 1, 3)
        finding["properties"]["tags"] = ["security"]  # no cwe tag
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "CWE" in result.reason

    def test_semgrep_without_cwe_fails(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _semgrep_finding(str(src_file), 1, 3)
        finding["extra"]["metadata"]["cwe"] = []
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "CWE" in result.reason

    def test_missing_file_fails(self, tmp_path):
        finding = _raptor_native(
            str(tmp_path / "nonexistent.py"), source_line=1, sink_line=2,
        )
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "cannot read" in result.reason

    def test_syntax_error_fails(self, tmp_path):
        src_file = _write(
            tmp_path, "app.py", "def handle(x:\n    return x\n",
        )
        finding = _raptor_native(str(src_file), source_line=1, sink_line=2)
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "syntax error" in result.reason

    def test_source_outside_any_function_fails(self, tmp_path):
        src = "x = 1\n\ndef handle():\n    return x\n"
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=4)
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "enclosing function" in result.reason

    def test_sink_line_has_no_call_fails(self, tmp_path):
        src = (
            "def handle(x):\n"
            "    return x\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=2)
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "no sink call" in result.reason or "no bare-name" in result.reason

    def test_sink_call_with_no_bare_name_arg_fails(self, tmp_path):
        """``render("static")`` — sink call exists but no bare name
        arg. Resolver can't pick a sink_arg, returns failure."""
        src = (
            "def handle(x):\n"
            "    render(\"static\")\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        finding = _raptor_native(str(src_file), source_line=1, sink_line=2)
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "bare-name" in result.reason or "no sink call" in result.reason

    def test_unsupported_language_returns_failure(self, tmp_path):
        # Doesn't actually need to exist on disk for this check —
        # language detection happens before file read. Python, C/C++,
        # and Java all have resolver legs now; .ts is the
        # representative still-unsupported language.
        finding = {
            "cwe": "CWE-79",
            "file_path": str(tmp_path / "app.ts"),
            "source_line": 1,
            "sink_line": 5,
        }
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "not yet supported" in result.reason
        assert "typescript" in result.reason


# ---------------------------------------------------------------------------
# Path containment — engine-supplied file paths guarded before any read
# ---------------------------------------------------------------------------


class TestTraversalGuard:
    """Traversal via ``..`` segments is refused before any read."""

    def test_dotdot_segment_refused(self, tmp_path):
        _write(tmp_path, "secret.py", STRAIGHT_LINE_SAFE_SRC)
        finding = _raptor_native(f"{tmp_path}/sub/../secret.py", 1, 3)
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "'..'" in result.reason

    def test_relative_dotdot_refused(self):
        result = resolve_finding(_raptor_native("../../etc/target.py", 1, 3))
        assert isinstance(result, ResolutionFailure)
        assert "'..'" in result.reason
        # Refused by the guard, not by a failed read.
        assert "cannot read" not in result.reason

    def test_dotdot_refused_for_cpp_branch(self):
        finding = _raptor_native("../escape.c", 1, 3, language="c")
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "'..'" in result.reason

    def test_sarif_uri_with_dotdot_refused(self):
        result = resolve_finding(_sarif_result("../../x.py", 1, 3))
        assert isinstance(result, ResolutionFailure)
        assert "'..'" in result.reason

    def test_absolute_path_still_allowed(self, tmp_path):
        src = _write(tmp_path, "app.py", STRAIGHT_LINE_SAFE_SRC)
        result = resolve_finding(_raptor_native(str(src), 1, 3))
        assert isinstance(result, ResolvedFinding)
        assert result.enclosing_function == "handle"

    def test_null_byte_path_fails_closed(self):
        result = _read_finding_source("bad\x00path.py")
        assert isinstance(result, ResolutionFailure)

    def test_dotdot_filename_prefix_not_refused(self, tmp_path):
        # A file merely NAMED with a leading '..' prefix is not a
        # traversal segment.
        src = _write(tmp_path, "..hidden.py", STRAIGHT_LINE_SAFE_SRC)
        result = _read_finding_source(str(src))
        assert result == STRAIGHT_LINE_SAFE_SRC


# ---------------------------------------------------------------------------
# Nested-function resolution
# ---------------------------------------------------------------------------


class TestNestedFunctions:
    def test_innermost_enclosing_function_wins(self, tmp_path):
        """When both a nested helper and its enclosing function
        contain the source/sink lines, the resolver picks the
        innermost — that's where the value-binding logic should
        run."""
        src = (
            "def outer(req):\n"
            "    def inner(x):\n"
            "        y = html.escape(x)\n"
            "        render(y)\n"
            "    return inner(req)\n"
        )
        src_file = _write(tmp_path, "app.py", src)
        # Source line 3 and sink line 4 are inside `inner`. Outer
        # contains them too but is wider.
        finding = _raptor_native(str(src_file), source_line=3, sink_line=4)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)
        assert result.enclosing_function == "inner"


# ---------------------------------------------------------------------------
# Format-detection sanity
# ---------------------------------------------------------------------------


class TestFormatDetection:
    def test_sarif_shape_dispatched(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _sarif_result(str(src_file), 1, 3)
        # SARIF has ruleId + codeFlows — distinct from other shapes.
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)

    def test_semgrep_shape_dispatched(self, tmp_path):
        src_file = _write(tmp_path, "app.py", WRONG_VARIABLE_SRC)
        finding = _semgrep_finding(str(src_file), 1, 3)
        # Semgrep has check_id + extra.
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)


# ---------------------------------------------------------------------------
# Column plumbing removed — source_col / sink_col are not part of the model
# ---------------------------------------------------------------------------


class TestDeadColumnPlumbingRemoved:
    def test_parsed_finding_has_no_column_fields(self):
        names = {f.name for f in dataclasses.fields(_ParsedFinding)}
        assert "source_col" not in names
        assert "sink_col" not in names

    def test_native_finding_with_legacy_col_keys_still_resolves(self, tmp_path):
        src = _write(tmp_path, "app.py", STRAIGHT_LINE_SAFE_SRC)
        finding = _raptor_native(str(src), 1, 3, source_col=5, sink_col=11)
        result = resolve_finding(finding)
        assert isinstance(result, ResolvedFinding)


# ---------------------------------------------------------------------------
# Java sink forwarding (assignment-located findings) and receiver-hop
# (zero-argument receiver calls) — b33
# ---------------------------------------------------------------------------

_JAVA_PS_SAFE = """\
public class T {
    public void doPost(HttpServletRequest request) throws Exception {
        String param = request.getHeader("X");
        String bar = "safe!";
        java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();
        map.put("keyA", "a_Value");
        map.put("keyB", param);
        bar = (String) map.get("keyA");
        String sql = "SELECT * from USERS where USERNAME='" + bar + "'";
        java.sql.PreparedStatement statement = connection.prepareStatement(sql);
        statement.setString(1, "foo");
        statement.execute();
    }
}
"""


def _java_native(path, source_line, sink_line):
    return {"cwe": "CWE-89", "file_path": str(path),
            "source_line": source_line, "sink_line": sink_line,
            "language": "java", "rule_id": "test", "tool": "test"}


@requires_ts("java")
class TestJavaSinkForwardingAndReceiverHop:
    def test_assignment_sink_forwards_to_consuming_call(self, tmp_path):
        f = _write(tmp_path, "T.java", _JAVA_PS_SAFE)
        r = resolve_finding(_java_native(f, 3, 9))  # sink = concat line
        assert isinstance(r, ResolvedFinding)
        assert r.sink_arg == "sql"
        assert r.sink_node.lineno == 10  # forwarded to prepareStatement

    def test_zero_arg_receiver_call_hops_to_constructor(self, tmp_path):
        f = _write(tmp_path, "T.java", _JAVA_PS_SAFE)
        r = resolve_finding(_java_native(f, 3, 12))  # sink = execute()
        assert isinstance(r, ResolvedFinding)
        assert r.sink_arg == "sql"
        assert r.sink_node.lineno == 10

    def test_forwarding_refuses_on_intervening_reassignment(self, tmp_path):
        src = _JAVA_PS_SAFE.replace(
            "java.sql.PreparedStatement statement",
            "sql = sql + param;\n        java.sql.PreparedStatement statement")
        f = _write(tmp_path, "T.java", src)
        r = resolve_finding(_java_native(f, 3, 9))
        assert not isinstance(r, ResolvedFinding)

    def test_forwarding_refuses_when_never_consumed(self, tmp_path):
        src = _JAVA_PS_SAFE.replace("prepareStatement(sql)",
                                    "prepareStatement(other)")
        f = _write(tmp_path, "T.java", src)
        r = resolve_finding(_java_native(f, 3, 9))
        assert not isinstance(r, ResolvedFinding)

    def test_receiver_hop_full_reassignment_targets_latest(self, tmp_path):
        # A straight-line reassignment KILLS the earlier construction —
        # hopping to the latest one is the sound target.
        src = _JAVA_PS_SAFE.replace(
            "statement.setString(1, \"foo\");",
            "statement = connection.prepareStatement(other);")
        f = _write(tmp_path, "T.java", src)
        r = resolve_finding(_java_native(f, 3, 12))
        assert isinstance(r, ResolvedFinding)
        assert r.sink_arg == "other"

    def test_receiver_hop_refuses_branch_merged_definers(self, tmp_path):
        # Two constructions reach the execute on different paths — no
        # single value identity, the hop must refuse.
        src = _JAVA_PS_SAFE.replace(
            "statement.setString(1, \"foo\");",
            "if (param.length() > 3) { statement = connection.prepareStatement(other); }")
        f = _write(tmp_path, "T.java", src)
        r = resolve_finding(_java_native(f, 3, 12))
        assert not isinstance(r, ResolvedFinding)

    def test_receiver_hop_refuses_multi_arg_constructor(self, tmp_path):
        src = _JAVA_PS_SAFE.replace("prepareStatement(sql)",
                                    "prepareStatement(sql, mode)")
        f = _write(tmp_path, "T.java", src)
        r = resolve_finding(_java_native(f, 3, 12))
        assert not isinstance(r, ResolvedFinding)


_JAVA_B41 = (
    "import javax.servlet.http.HttpServletRequest;\n"           # 1
    "public class T {\n"                                        # 2
    "    public void handle(HttpServletRequest request,"
    " java.io.PrintWriter out) {\n"                             # 3
    "        String x = request.getParameter(\"q\");\n"         # 4
    "        String pre = \"Result: \";\n"                      # 5
    "        out.println(pre + x);\n"                           # 6
    "        out.format(java.util.Locale.US, \"%s\", x);\n"     # 7
    "        out.println(\n"                                    # 8
    "                x); // continuation\n"                     # 9
    "    }\n"                                                   # 10
    "}\n"                                                       # 11
)


@requires_ts("java")
class TestJavaB41SinkShapes:
    def test_deep_multi_name_concat_binds_value_name(self, tmp_path):
        # println(pre + x): no bare-name argument, two deep names —
        # the historical refusal; b41 binds one deterministically and
        # the gate's sibling guards adjudicate the other.
        f = _write(tmp_path, "T.java", _JAVA_B41)
        r = resolve_finding(_java_native(f, 4, 6))
        assert isinstance(r, ResolvedFinding)
        assert r.sink_arg in ("pre", "x")

    def test_package_chain_pick_prefers_value_carrying_name(self, tmp_path):
        # format(java.util.Locale.US, "%s", x): "java" rides the
        # argument surfaces as a package-root leftover; the pick must
        # land on the value-carrying name.
        f = _write(tmp_path, "T.java", _JAVA_B41)
        r = resolve_finding(_java_native(f, 4, 7))
        assert isinstance(r, ResolvedFinding)
        assert r.sink_arg == "x"

    def test_multiline_continuation_line_retargets_to_statement(
            self, tmp_path):
        # The finding flags the continuation line of a multi-line
        # statement; resolution retargets to the statement start,
        # whose node carries the call.
        f = _write(tmp_path, "T.java", _JAVA_B41)
        r = resolve_finding(_java_native(f, 4, 9))
        assert isinstance(r, ResolvedFinding)
        assert r.sink_node.lineno == 8
        assert r.sink_arg == "x"

    def test_statement_start_line_helper(self):
        from core.analysis.finding_resolver import (
            _java_statement_start_line,
        )
        assert _java_statement_start_line(_JAVA_B41, 9) == 8
        # A line that is its own statement start returns itself.
        assert _java_statement_start_line(_JAVA_B41, 6) == 6
        # A line outside any leaf statement returns None.
        assert _java_statement_start_line(_JAVA_B41, 2) is None

    def test_pick_value_name_prefers_defined_over_namespace(self):
        from core.analysis.finding_resolver import _pick_value_name

        class _N:
            def __init__(self, defs):
                self.defs = frozenset(defs)

        class _Cfg:
            params = ("request", "out")

            def nodes(self):
                return [_N({"x"}), _N({"pre"})]

        cfg = _Cfg()
        # "java" sorts first lexicographically but carries no value.
        assert _pick_value_name({"java", "x"}, cfg) == "x"
        # Within the carrying class, lexicographic keeps determinism.
        assert _pick_value_name({"x", "pre"}, cfg) == "pre"
        # All-namespace surfaces fall back to plain lexicographic.
        assert _pick_value_name({"java", "javax"}, cfg) == "java"

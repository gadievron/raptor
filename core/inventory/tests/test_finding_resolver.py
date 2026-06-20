"""Tests for ``core.inventory.finding_resolver`` — Phase 5 of the
value-binding arc.

Three input formats supported end-to-end (Python only); each gets a
happy-path test plus failure-mode coverage. The end-to-end test
feeds the resolved finding into Phase 4's ``evaluate_finding`` and
asserts the wrong-variable case lands at ``candidate_only`` — the
whole arc's correctness witness in one assertion.
"""
from __future__ import annotations

from pathlib import Path

from core.inventory.cfg_builder import PyCFGNode
from core.inventory.finding_resolver import (
    ResolutionFailure,
    ResolvedFinding,
    resolve_finding,
)
from core.inventory.sanitizer_cut import (
    VERDICT_CANDIDATE_ONLY,
    VERDICT_SUPPRESS,
    evaluate_finding,
)


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

    def test_non_python_language_returns_failure(self, tmp_path):
        # Doesn't actually need to exist on disk for this check —
        # language detection happens before file read.
        finding = {
            "cwe": "CWE-79",
            "file_path": str(tmp_path / "app.java"),
            "source_line": 1,
            "sink_line": 5,
        }
        result = resolve_finding(finding)
        assert isinstance(result, ResolutionFailure)
        assert "not yet supported" in result.reason
        assert "java" in result.reason


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

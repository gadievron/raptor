"""Tests for the tree-sitter structural dataflow validator."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from core.dataflow.structural_validator import (
    StructuralResult,
    _EXTRACTORS,
    _build_all_steps,
    _check_call_link,
    _extract_branch_guards_from_content,
    _extract_graph,
    _identify_sanitizer_calls,
    _resolve_file,
    validate_structurally,
)
from core.inventory.call_graph import (
    CallSite,
    FileCallGraph,
)

# ── helpers ──────────────────────────────────────────────────────


def _make_step(file: str, line: int, label: str = "") -> dict:
    return {"file": file, "line": line, "label": label, "snippet": ""}


def _make_path(source: dict, sink: dict, steps: list | None = None) -> dict:
    return {
        "source": source,
        "sink": sink,
        "steps": steps or [],
        "total_steps": 2 + len(steps or []),
    }


def _write_py(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ── _resolve_file (path traversal defense) ──────────────────────


class TestResolveFile:
    def test_relative_path_inside_repo(self, tmp_path):
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "app.py").write_text("x = 1\n")
        result = _resolve_file({"file": "src/app.py"}, tmp_path)
        assert result is not None
        assert result.name == "app.py"

    def test_traversal_rejected(self, tmp_path):
        result = _resolve_file({"file": "../../etc/passwd"}, tmp_path)
        assert result is None

    def test_dotdot_in_middle_rejected(self, tmp_path):
        (tmp_path / "src").mkdir()
        result = _resolve_file({"file": "src/../../../etc/shadow"}, tmp_path)
        assert result is None

    def test_absolute_outside_repo_rejected(self, tmp_path):
        result = _resolve_file({"file": "/etc/passwd"}, tmp_path)
        assert result is None

    def test_empty_file_returns_none(self, tmp_path):
        result = _resolve_file({"file": ""}, tmp_path)
        assert result is None


# ── StructuralResult ─────────────────────────────────────────────


class TestStructuralResult:
    def test_refuted_property(self):
        r = StructuralResult(verdict="refuted", reasoning="broken")
        assert r.refuted is True

    def test_confirmed_not_refuted(self):
        r = StructuralResult(verdict="confirmed", reasoning="ok")
        assert r.refuted is False

    def test_iterations_always_one(self):
        r = StructuralResult(verdict="inconclusive", reasoning="x")
        assert r.iterations == 1

    def test_to_dict(self):
        r = StructuralResult(
            verdict="confirmed",
            reasoning="ok",
            confidence="high",
            sanitizers=["escape_html"],
            path_conditions=[{"text": "x > 0", "step_index": 1, "negated": False}],
        )
        d = r.to_dict()
        assert d["verdict"] == "confirmed"
        assert d["method"] == "structural-treesitter"
        assert d["sanitizers"] == ["escape_html"]
        assert len(d["path_conditions"]) == 1


# ── _build_all_steps ─────────────────────────────────────────────


class TestBuildAllSteps:
    def test_source_and_sink_only(self):
        p = _make_path(
            _make_step("a.py", 1),
            _make_step("a.py", 10),
        )
        steps = _build_all_steps(p)
        assert len(steps) == 2

    def test_with_intermediate(self):
        p = _make_path(
            _make_step("a.py", 1),
            _make_step("a.py", 20),
            steps=[_make_step("a.py", 10)],
        )
        steps = _build_all_steps(p)
        assert len(steps) == 3

    def test_missing_source(self):
        p = {"source": None, "sink": _make_step("a.py", 1), "steps": []}
        steps = _build_all_steps(p)
        assert len(steps) == 1


# ── _check_call_link ────────────────────────────────────────────


class TestCheckCallLink:
    def test_direct_call_found(self):
        graph = FileCallGraph(
            calls=[CallSite(line=5, chain=["process"], caller="handle")],
        )
        found, indirect = _check_call_link("handle", "process", graph)
        assert found is True
        assert indirect is False

    def test_no_call_found(self):
        graph = FileCallGraph(
            calls=[CallSite(line=5, chain=["other"], caller="handle")],
        )
        found, indirect = _check_call_link("handle", "process", graph)
        assert found is False
        assert indirect is False

    def test_indirection_yields_inconclusive(self):
        graph = FileCallGraph(
            calls=[CallSite(line=5, chain=["other"], caller="handle")],
            indirection={"getattr"},
        )
        found, indirect = _check_call_link("handle", "process", graph)
        assert found is None
        assert indirect is True

    def test_method_call_chain(self):
        graph = FileCallGraph(
            calls=[CallSite(line=5, chain=["self", "validate"], caller="handle")],
        )
        found, _ = _check_call_link("handle", "validate", graph)
        assert found is True

    def test_cross_file_import(self):
        graph = FileCallGraph(
            imports={"helper": "utils.helper"},
            calls=[],
        )
        found, _ = _check_call_link("main", "helper", graph, cross_file=True)
        assert found is True

    def test_cross_file_import_beats_indirection(self):
        graph = FileCallGraph(
            imports={"helper": "utils.helper"},
            calls=[],
            indirection={"getattr"},
        )
        found, indirect = _check_call_link("main", "helper", graph, cross_file=True)
        assert found is True
        assert indirect is False

    def test_none_target(self):
        graph = FileCallGraph()
        found, _ = _check_call_link("main", None, graph)
        assert found is None


# ── _identify_sanitizer_calls ───────────────────────────────────


class TestIdentifySanitizers:
    def test_sanitize_keyword(self):
        calls = [CallSite(line=1, chain=["html", "escape"], caller="render")]
        found = _identify_sanitizer_calls(calls, "")
        assert any("escape" in s for s in found)

    def test_label_match(self):
        found = _identify_sanitizer_calls([], "validator applied here")
        assert any("label:" in s for s in found)

    def test_no_match(self):
        calls = [CallSite(line=1, chain=["print"], caller="main")]
        found = _identify_sanitizer_calls(calls, "just a log")
        assert found == []


# ── _extract_branch_guards_from_content ─────────────────────────


class TestBranchGuards:
    def test_simple_if(self):
        content = textwrap.dedent("""\
            def f():
                if x > 0:
                    do_something()
        """)
        guards = _extract_branch_guards_from_content(content, 3, "python")
        assert any("x > 0" in g for g in guards)

    def test_no_guard(self):
        content = "do_something()\n"
        guards = _extract_branch_guards_from_content(content, 1, "python")
        assert guards == []

    def test_nested_if(self):
        content = textwrap.dedent("""\
            def f():
                if user:
                    if user.is_admin:
                        grant()
        """)
        guards = _extract_branch_guards_from_content(content, 4, "python")
        assert len(guards) >= 1

    def test_line_out_of_range(self):
        guards = _extract_branch_guards_from_content("x = 1\n", 99, "python")
        assert guards == []

    def test_exact_guard_text_extracted(self):
        content = (
            "def f(x):\n"
            "    if x > 0:\n"
            "        sink(x)\n"
        )
        guards = _extract_branch_guards_from_content(content, 3, "python")
        assert guards == ["x > 0"]

    def test_out_of_range_line_returns_empty(self):
        content = "a = 1\nb = 2\n"
        assert _extract_branch_guards_from_content(content, 3, "python") == []
        assert _extract_branch_guards_from_content(content, 0, "python") == []

    def test_line_one_no_negative_scan(self):
        assert _extract_branch_guards_from_content("x = 1\n", 1, "python") == []


# ── _extract_graph grammar selection ─────────────────────────────


TS_CONTENT = """\
interface Req { body: string }

function helper(x: string): string {
    return x.trim();
}

export function main(req: Req): void {
    helper(req.body);
}
"""


class TestTypescriptGrammar:
    def test_extractor_table_binds_ts_grammars(self):
        assert _EXTRACTORS["typescript"].keywords["language"] == "typescript"
        assert _EXTRACTORS["tsx"].keywords["language"] == "tsx"

    def test_typed_ts_produces_call_edges(self):
        pytest.importorskip("tree_sitter_typescript")
        graph = _extract_graph(TS_CONTENT, "typescript")
        assert graph is not None
        edges = [(c.caller, tuple(c.chain)) for c in graph.calls]
        assert ("main", ("helper",)) in edges

    def test_tsx_grammar_parses_jsx(self):
        pytest.importorskip("tree_sitter_typescript")
        tsx = (
            "function App(): JSX.Element {\n"
            "    const v = render();\n"
            "    return <div>{v}</div>;\n"
            "}\n"
        )
        graph = _extract_graph(tsx, "tsx")
        assert graph is not None
        assert any(tuple(c.chain) == ("render",) for c in graph.calls)


class TestGrammarMissingIsNoEvidence:
    def test_extract_graph_returns_none_without_grammar(self, monkeypatch):
        import core.inventory.extractors as ex
        monkeypatch.setattr(ex, "_ts_language", lambda lang: None)
        assert _extract_graph("int main(void) { return 0; }\n", "c") is None

    def test_extract_graph_returns_none_without_tree_sitter(self, monkeypatch):
        import core.inventory.extractors as ex
        monkeypatch.setattr(ex, "_TS_AVAILABLE", False)
        assert _extract_graph("function f() {}\n", "javascript") is None

    def test_python_unaffected_by_missing_grammars(self, monkeypatch):
        import core.inventory.extractors as ex
        monkeypatch.setattr(ex, "_TS_AVAILABLE", False)
        graph = _extract_graph("def f():\n    g()\n", "python")
        assert graph is not None
        assert any(tuple(c.chain) == ("g",) for c in graph.calls)

    def test_no_high_confidence_refutation_without_grammar(
        self, monkeypatch, tmp_path,
    ):
        """An environment gap (grammar not installed) must not become a
        high-confidence refutation that suppresses a finding."""
        import core.inventory.extractors as ex
        monkeypatch.setattr(ex, "_ts_language", lambda lang: None)
        src = tmp_path / "vuln.c"
        src.write_text(
            "void sink(char *s) { system(s); }\n"
            "void source(char *s) { sink(s); }\n"
        )
        path = {
            "source": {"file": "vuln.c", "line": 2, "label": "source"},
            "sink": {"file": "vuln.c", "line": 1, "label": "sink"},
        }
        result = validate_structurally(path, tmp_path)
        assert result.verdict != "refuted"


# ── validate_structurally (integration) ─────────────────────────


class TestValidateStructurally:
    def test_too_few_steps(self):
        result = validate_structurally(
            {"source": _make_step("a.py", 1), "sink": None, "steps": []},
            Path("/nonexistent"),
        )
        assert result.verdict == "inconclusive"

    def test_missing_files_inconclusive(self, tmp_path):
        path = _make_path(
            _make_step("missing_a.py", 1),
            _make_step("missing_b.py", 10),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "inconclusive"
        assert "not found" in result.reasoning

    def test_confirmed_direct_call(self, tmp_path):
        _write_py(tmp_path, "app.py", """\
            def source():
                return input()

            def sink(data):
                eval(data)

            def main():
                data = source()
                sink(data)
        """)
        # Dataflow: main() calls source() then calls sink()
        # Step order follows the flow: main→source, main→sink
        path = _make_path(
            _make_step("app.py", 9),   # main() calls source()
            _make_step("app.py", 10),  # main() calls sink()
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict in ("confirmed", "inconclusive")
        assert result.method == "structural-treesitter"

    def test_refuted_no_call_link(self, tmp_path):
        _write_py(tmp_path, "a.py", """\
            def handler():
                x = 1
                return x

            def unrelated():
                pass
        """)
        path = _make_path(
            _make_step("a.py", 2),
            _make_step("a.py", 6),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict in ("refuted", "inconclusive")

    def test_sanitizer_detected(self, tmp_path):
        _write_py(tmp_path, "web.py", """\
            def handle(request):
                data = request.get("input")
                clean = sanitize_input(data)
                render(clean)
        """)
        path = _make_path(
            _make_step("web.py", 2),
            _make_step("web.py", 4),
            steps=[_make_step("web.py", 3, label="sanitize_input")],
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert len(result.sanitizers) > 0

    def test_branch_guards_extracted(self, tmp_path):
        _write_py(tmp_path, "check.py", """\
            def process(user_input):
                if len(user_input) < 100:
                    execute(user_input)
        """)
        path = _make_path(
            _make_step("check.py", 1),
            _make_step("check.py", 3),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert len(result.path_conditions) > 0

    def test_line_beyond_file(self, tmp_path):
        _write_py(tmp_path, "tiny.py", "x = 1\n")
        path = _make_path(
            _make_step("tiny.py", 1),
            _make_step("tiny.py", 999),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert any(
            not v["exists"] for v in result.evidence
        )

    def test_cross_file_path(self, tmp_path):
        _write_py(tmp_path, "source.py", """\
            def get_input():
                return input()
        """)
        _write_py(tmp_path, "sink.py", """\
            from source import get_input

            def execute():
                data = get_input()
                eval(data)
        """)
        # Dataflow: source.get_input() → sink.execute() calls get_input()
        path = _make_path(
            _make_step("source.py", 2),  # source: get_input returns input()
            _make_step("sink.py", 4),    # sink: execute() calls get_input()
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict in ("confirmed", "inconclusive")

    def test_evidence_has_expected_keys(self, tmp_path):
        _write_py(tmp_path, "e.py", """\
            def f():
                g()
            def g():
                pass
        """)
        path = _make_path(
            _make_step("e.py", 2),
            _make_step("e.py", 4),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert len(result.evidence) == 2
        for ev in result.evidence:
            assert "step_index" in ev
            assert "file" in ev
            assert "exists" in ev


# ── line-count convention: N trailing-newline lines means N lines ──


class TestLineCountConvention:
    def test_phantom_trailing_line_rejected(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("x = a()\ny = b(x)\n")   # 2 real lines
        path = {
            "source": {"file": "f.py", "line": 1, "label": "source"},
            "sink": {"file": "f.py", "line": 3, "label": "sink"},
        }
        result = validate_structurally(path, tmp_path)
        sink_ev = result.evidence[1]
        assert sink_ev["exists"] is False
        assert "exceeds file length 2" in sink_ev["detail"]

    def test_last_real_line_accepted(self, tmp_path):
        src = tmp_path / "f.py"
        src.write_text("x = a()\ny = b(x)\n")
        path = {
            "source": {"file": "f.py", "line": 1, "label": "source"},
            "sink": {"file": "f.py", "line": 2, "label": "sink"},
        }
        result = validate_structurally(path, tmp_path)
        assert all(ev["exists"] for ev in result.evidence)


# ── Same-function consecutive steps (verdict soundness) ─────────


class TestSameFunctionSteps:
    """Consecutive steps inside one function are linked by straight-
    line control flow, not by a self-call edge.  The old code demanded
    a call edge between them and 'refuted' every intra-procedural
    taint path with high confidence."""

    def test_intraprocedural_path_not_refuted(self, tmp_path):
        _write_py(tmp_path, "app.py", """\
            import subprocess

            def handler(req):
                cmd = req.args.get("cmd")
                full = "prefix " + cmd
                subprocess.call(full, shell=True)
        """)
        path = _make_path(
            _make_step("app.py", 4, label="req.args.get"),
            _make_step("app.py", 6, label="subprocess.call"),
            steps=[_make_step("app.py", 5, label="concat")],
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict != "refuted"

    def test_same_name_across_files_not_shortcircuited(self, tmp_path):
        # Same function NAME in two files is not the same function —
        # the cross-file leg must not take the same-function shortcut.
        _write_py(tmp_path, "a.py", """\
            def handler(req):
                data = req.args.get("x")
                return data
        """)
        _write_py(tmp_path, "b.py", """\
            def handler(data):
                eval(data)
        """)
        path = _make_path(
            _make_step("a.py", 2),
            _make_step("b.py", 2),
        )
        result = validate_structurally(path, tmp_path, language="python")
        # No call edge, no import link: anything but a confident
        # same-function confirmation.
        assert result.verdict != "confirmed" or result.confidence != "high"


class TestReturnFlowLink:
    """Return-flow hops: source inside a callee, next step in the
    caller — the data comes BACK over the call's return value. The
    reverse edge (caller → callee) is in the graph and must rescue
    the link instead of refuting the path with high confidence."""

    def test_reverse_edge_rescues_return_hop(self):
        graph = FileCallGraph(
            calls=[CallSite(line=6, chain=["get_input"], caller="handler")],
        )
        found, indirect = _check_call_link("get_input", "handler", graph)
        assert found is True
        assert indirect is False

    def test_reverse_edge_not_used_cross_file(self):
        # Cross-file stays inconclusive (never a confirm from a
        # same-name edge in another file's graph).
        graph = FileCallGraph(
            calls=[CallSite(line=6, chain=["get_input"], caller="handler")],
        )
        found, _ = _check_call_link(
            "get_input", "handler", graph, cross_file=True,
        )
        assert found is None

    def test_no_edge_either_direction_still_refutes(self):
        graph = FileCallGraph(
            calls=[CallSite(line=5, chain=["other"], caller="handler")],
        )
        found, indirect = _check_call_link("get_input", "handler", graph)
        assert found is False
        assert indirect is False

    def test_same_file_return_flow_not_refuted(self, tmp_path):
        pytest.importorskip("tree_sitter")
        pytest.importorskip("tree_sitter_python")
        _write_py(tmp_path, "flow.py", """\
            def get_input():
                x = input()
                return x


            def handler():
                x = get_input()
                eval(x)
        """)
        path = _make_path(
            _make_step("flow.py", 2),
            _make_step("flow.py", 8),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "confirmed"

    def test_forward_hop_control_still_confirms(self, tmp_path):
        pytest.importorskip("tree_sitter")
        pytest.importorskip("tree_sitter_python")
        _write_py(tmp_path, "fwd.py", """\
            def handler():
                x = input()
                process(x)


            def process(x):
                eval(x)
        """)
        path = _make_path(
            _make_step("fwd.py", 2),
            _make_step("fwd.py", 7),
        )
        result = validate_structurally(path, tmp_path, language="python")
        assert result.verdict == "confirmed"


# ── attribution divergence must abstain, never refute ───────────


class TestAttributionDivergence:
    """The span extractor and the call-graph extractor are two
    attribution sources; when they diverge (JS arrow functions: span
    says ``run``, the graph tags the calls ``caller=None``) the link
    check filters on a name the graph never uses and finds vacuous
    emptiness. That must land as inconclusive — a high-confidence
    refutation feeds recommends_downgrade on an exploitable finding."""

    HELPER_TAIL = "function helper(y) {\n  sink(y);\n}\n"

    # Every fixture genuinely calls helper → sink, so "refuted" is
    # always wrong; well-attributed shapes should stay confirmed.
    LINKED_SHAPES = {
        "arrow.js": (
            "const run = (x) => {\n  helper(x);\n};\n", 2, 5),
        "asyncarrow.js": (
            "const run = async (x) => {\n  await helper(x);\n};\n", 2, 5),
        "classmethod.js": (
            "class App {\n  run(x) {\n    helper(x);\n  }\n}\n", 3, 7),
        "iife.js": (
            "const api = (function () {\n  function run(x) {\n"
            "    helper(x);\n  }\n  return { run };\n})();\n", 3, 8),
        "generator.js": (
            "function* run(x) {\n  helper(x);\n  yield x;\n}\n", 2, 6),
        "objmethod.js": (
            "const app = {\n  run(x) {\n    helper(x);\n  },\n};\n", 3, 7),
    }

    @pytest.fixture(autouse=True)
    def _need_js_grammar(self):
        pytest.importorskip("tree_sitter")
        pytest.importorskip("tree_sitter_javascript")

    @pytest.mark.parametrize("name", sorted(LINKED_SHAPES))
    def test_linked_js_shapes_are_never_refuted(self, tmp_path, name):
        head, call_line, sink_line = self.LINKED_SHAPES[name]
        (tmp_path / name).write_text(head + self.HELPER_TAIL)
        path = _make_path(
            _make_step(name, call_line), _make_step(name, sink_line),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict != "refuted", result.reasoning

    def test_plain_function_control_still_confirms_high(self, tmp_path):
        (tmp_path / "plain.js").write_text(
            "function run(x) {\n  helper(x);\n}\n" + self.HELPER_TAIL,
        )
        path = _make_path(_make_step("plain.js", 2), _make_step("plain.js", 5))
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "confirmed"
        assert result.confidence == "high"

    def test_truly_absent_edge_still_refutes(self, tmp_path):
        """Two-direction: with clean attribution and a genuinely
        missing edge, the refutation lane stays live."""
        (tmp_path / "broken.js").write_text(
            "function run(x) {\n  other(x);\n}\n" + self.HELPER_TAIL,
        )
        path = _make_path(
            _make_step("broken.js", 2), _make_step("broken.js", 5),
        )
        result = validate_structurally(path, tmp_path)
        assert result.verdict == "refuted"

    def test_unresolved_attribution_downgrades_refutation_unit(self):
        graph = FileCallGraph(
            calls=[CallSite(chain=("helper",), line=2, caller=None)],
            imports={}, indirection=False,
        )
        assert _check_call_link(
            "run", "helper", graph, attribution_resolved=True,
        ) == (False, False)
        assert _check_call_link(
            "run", "helper", graph, attribution_resolved=False,
        ) == (None, False)

    def test_extraction_failure_reads_as_unresolved(self, monkeypatch):
        """from_func=None from a FAILED span extraction must not be
        conflated with genuine module level."""
        from core.dataflow.structural_validator import (
            _enclosing_function_state,
        )
        import core.inventory.extractors as ex

        def boom(*a, **k):
            raise RuntimeError("grammar exploded")

        monkeypatch.setattr(ex, "extract_functions", boom)
        graph = FileCallGraph(calls=[], imports={}, indirection=False)
        name, resolved = _enclosing_function_state(
            1, graph, "function f() {}\n", "javascript",
        )
        assert name is None
        assert resolved is False

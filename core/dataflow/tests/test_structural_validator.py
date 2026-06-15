"""Tests for the tree-sitter structural dataflow validator."""

from __future__ import annotations

import textwrap
from pathlib import Path

from core.dataflow.structural_validator import (
    StructuralResult,
    _build_all_steps,
    _check_call_link,
    _extract_branch_guards_from_content,
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

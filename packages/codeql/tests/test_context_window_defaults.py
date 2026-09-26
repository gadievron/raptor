"""/codeql classifier context windows: defaults wired, boundaries
exact, output byte-identical to the pre-extraction literals.

Same contract as the llm_analysis sibling
(``packages/llm_analysis/tests/test_context_window_defaults.py``):
the ±50 finding window, the ±10 dataflow-validation window, and the
±5 path-condition step window used to be bare literals; they now come
from ``core.llm.context_window``. The vendored differentials below
keep the OLD literals hardcoded on purpose — a changed default goes
red here and becomes a reviewed behaviour change.
"""

from __future__ import annotations

import inspect
import logging
from pathlib import Path

from core.llm.context_window import (
    DATAFLOW_STEP_CONTEXT_LINES,
    DATAFLOW_VALIDATION_CONTEXT_LINES,
    FINDING_CONTEXT_LINES,
)
from core.source import split_lines
from packages.codeql.autonomous_analyzer import (
    AutonomousCodeQLAnalyzer,
    CodeQLFinding,
)
from packages.codeql.dataflow_validator import (
    DataflowPath,
    DataflowStep,
    DataflowValidator,
)

_N_LINES = 200
_SRC = "".join(f"marker-{i:04d}\n" for i in range(1, _N_LINES + 1))


def _repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir(exist_ok=True)
    (repo / "a.c").write_bytes(_SRC.encode())
    return repo


def _analyzer() -> AutonomousCodeQLAnalyzer:
    a = AutonomousCodeQLAnalyzer.__new__(AutonomousCodeQLAnalyzer)
    a.logger = logging.getLogger("test-context-window")
    return a


def _validator() -> DataflowValidator:
    v = DataflowValidator.__new__(DataflowValidator)
    v.logger = logging.getLogger("test-context-window")
    return v


def _finding(line: int, end_line: int | None = None) -> CodeQLFinding:
    return CodeQLFinding(
        rule_id="cpp/test-rule", rule_name="t", message="m",
        level="warning", file_path="a.c", start_line=line,
        end_line=end_line or line, snippet="SNIPPET-FALLBACK",
    )


class TestFindingWindow:
    def test_default_is_the_shared_constant(self):
        sig = inspect.signature(AutonomousCodeQLAnalyzer.read_vulnerable_code)
        assert sig.parameters["context_lines"].default == FINDING_CONTEXT_LINES

    def test_both_edges(self, tmp_path: Path):
        repo = _repo(tmp_path)
        s = FINDING_CONTEXT_LINES + 60  # line 110: window floor is 60
        out = _analyzer().read_vulnerable_code(_finding(s), repo)
        floor = s - FINDING_CONTEXT_LINES
        ceil = s + FINDING_CONTEXT_LINES
        assert f"marker-{floor:04d}" in out
        assert f"marker-{floor - 1:04d}" not in out
        assert f"marker-{ceil:04d}" in out
        assert f"marker-{ceil + 1:04d}" not in out


class TestDataflowValidationWindow:
    def test_default_is_the_shared_constant(self):
        sig = inspect.signature(DataflowValidator.read_source_context)
        assert (sig.parameters["context_lines"].default
                == DATAFLOW_VALIDATION_CONTEXT_LINES)

    def test_both_edges(self, tmp_path: Path):
        repo = _repo(tmp_path)
        line = 100
        out = _validator().read_source_context(
            str(repo / "a.c"), line, repo_root=repo,
        )
        w = DATAFLOW_VALIDATION_CONTEXT_LINES
        assert f"marker-{line - w:04d}" in out
        assert f"marker-{line - w - 1:04d}" not in out
        assert f"marker-{line + w:04d}" in out
        assert f"marker-{line + w + 1:04d}" not in out


class TestPathConditionStepWindow:
    def test_extract_path_conditions_uses_step_window(self, tmp_path: Path):
        """The SMT path-condition pass reads each step with the shared
        ±DATAFLOW_STEP_CONTEXT_LINES window (it passed a literal 5
        before). Captured via a recording read_source_context; the LLM
        call then fails (no client on the bare instance) and the
        method degrades to ([], {}) by contract."""
        repo = _repo(tmp_path)
        v = _validator()
        seen: list[int | None] = []
        real = v.read_source_context

        def recording(file_path, line, context_lines=None, repo_root=None):
            seen.append(context_lines)
            return real(file_path, line,
                        context_lines=context_lines
                        or DATAFLOW_VALIDATION_CONTEXT_LINES,
                        repo_root=repo_root)

        v.read_source_context = recording  # type: ignore[method-assign]
        step = DataflowStep(
            file_path="a.c", line=100, column=1, snippet="s", label="step",
        )
        path = DataflowPath(
            source=DataflowStep(
                file_path="a.c", line=10, column=1, snippet="s",
                label="source",
            ),
            sink=DataflowStep(
                file_path="a.c", line=150, column=1, snippet="s",
                label="sink",
            ),
            intermediate_steps=[step],
            sanitizers=[], rule_id="cpp/test-rule", message="m",
        )
        conditions, hint = v._extract_path_conditions(path, repo)
        assert conditions == [] and hint == {}
        assert seen  # every step read was captured
        assert all(c == DATAFLOW_STEP_CONTEXT_LINES for c in seen)


# ── Equivalence differentials (old literals on purpose) ─────────────


def _old_read_vulnerable_code(
    content: str, start_line: int, end_line: int,
) -> str:
    lines = content.splitlines(keepends=True)
    start = max(0, start_line - 50 - 1)
    end = min(len(lines), end_line + 50)
    out = []
    for i in range(start, end):
        marker = ">>> " if start_line - 1 <= i < end_line else "    "
        out.append(f"{marker}{i + 1:4d}: {lines[i].rstrip()}")
    return "\n".join(out)


def _old_read_source_context(content: str, line: int) -> str:
    lines = split_lines(content)
    start = max(0, line - 10 - 1)
    end = min(len(lines), line + 10)
    out = []
    for i in range(start, end):
        marker = ">>> " if i == line - 1 else "    "
        out.append(f"{marker}{i + 1:4d}: {lines[i].rstrip()}")
    return "\n".join(out)


class TestEquivalenceDifferential:
    def test_read_vulnerable_code_byte_identical(self, tmp_path: Path):
        repo = _repo(tmp_path)
        a = _analyzer()
        for s, e in ((100, 100), (3, 3), (198, 198), (80, 95)):
            assert (a.read_vulnerable_code(_finding(s, e), repo)
                    == _old_read_vulnerable_code(_SRC, s, e)), (s, e)

    def test_read_source_context_byte_identical(self, tmp_path: Path):
        repo = _repo(tmp_path)
        v = _validator()
        for line in (1, 5, 100, 195, 200):
            assert (v.read_source_context(
                        str(repo / "a.c"), line, repo_root=repo)
                    == _old_read_source_context(_SRC, line)), line

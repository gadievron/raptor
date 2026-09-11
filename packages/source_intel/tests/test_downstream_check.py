"""Tests for the axis-8 validation-after-overflow suppressor.

The suppressor is verdict-active (it drives NOT_EXPLOITABLE), so the
scope discipline of its early-exit scan is two-directional:

  * a guard that does NOT exit must never suppress — in particular a
    braceless ``if`` whose single controlled statement is a warning,
    followed by the function's ordinary final ``return``, is NOT an
    early-exit guard;
  * a guard that genuinely exits (braced block with a ``return``,
    braceless ``return`` statement, single-line form, ``else`` arm
    exit) must keep suppressing.
"""

from __future__ import annotations

from pathlib import Path

from core.dataflow.finding import Finding, Step
from packages.source_intel.adapter import (
    _downstream_check_suppresses_finding,
    _if_scope_has_early_exit,
)


def _finding_at(path: str, line: int,
                snippet: str = "int size = nex * 8;") -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id="cpp/uncontrolled-allocation-size",
        message="m",
        source=Step(file_path=path, line=line, column=1,
                    snippet=snippet, label="source"),
        sink=Step(file_path=path, line=line, column=1,
                  snippet=snippet, label="sink"),
        intermediate_steps=(),
        raw={},
    )


def _write(tmp_path: Path, code: str) -> str:
    f = tmp_path / "t.c"
    f.write_text(code)
    return str(f)


class TestBracelessIfScope:
    def test_non_exiting_braceless_body_with_final_return_not_suppressed(
        self, tmp_path,
    ):
        """The braceless if controls exactly ONE statement; the
        function's final `return 0;` after it must not count as an
        early-exit guard."""
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size > 100)\n"
            '        pr_warn("big");\n'
            "    do_alloc(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is False

    def test_braceless_if_whose_statement_is_return_suppresses(
        self, tmp_path,
    ):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size > 100)\n"
            "        return -1;\n"
            "    use(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is True

    def test_single_line_if_return_suppresses(self, tmp_path):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size > 100) return -1;\n"
            "    use(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is True

    def test_exit_in_else_arm_suppresses(self, tmp_path):
        """An exit on the else arm guards the fall-through path
        equally — the value never reaches the consumer unchecked."""
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size <= 100)\n"
            "        ok(size);\n"
            "    else\n"
            "        return -22;\n"
            "    use(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is True

    def test_non_exiting_both_arms_with_final_return_not_suppressed(
        self, tmp_path,
    ):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size > 100)\n"
            '        pr_warn("big");\n'
            "    else\n"
            '        pr_info("ok");\n'
            "    use(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is False


class TestBracedIfScope:
    def test_braced_early_return_still_suppresses(self, tmp_path):
        """The legitimately-guarded case keeps flipping: braced guard
        with warnings before the exit (the canonical
        validate-then-use shape)."""
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (unlikely(size < 0 || size > 100)) {\n"
            '        xfs_warn(mp, "corrupt");\n'
            '        xfs_warn(mp, "more context");\n'
            "        return -1;\n"
            "    }\n"
            "    memcpy(buf, src, size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is True

    def test_braced_non_exiting_body_with_final_return_not_suppressed(
        self, tmp_path,
    ):
        path = _write(tmp_path, (
            "int f(int nex) {\n"
            "    int size = nex * 8;\n"
            "    if (size > 100) {\n"
            '        pr_warn("big");\n'
            "    }\n"
            "    use(size);\n"
            "    return 0;\n"
            "}\n"
        ))
        assert _downstream_check_suppresses_finding(
            _finding_at(path, 2),
        ) is False


class TestIfScopeScanner:
    """Unit tests for the scope scanner itself."""

    def test_multi_line_condition_then_braceless_return(self):
        lines = [
            "if (size < 0 ||\n",
            "    size > limit)\n",
            "        return -1;\n",
        ]
        assert _if_scope_has_early_exit(lines, 0) is True

    def test_return_in_comment_does_not_count(self):
        lines = [
            "if (size > 100)\n",
            "    log(); /* no return here */\n",
            "return 0;\n",
        ]
        assert _if_scope_has_early_exit(lines, 0) is False

    def test_out_of_scope_text_on_close_line_does_not_count(self):
        lines = [
            "if (size > 100) { log(); } return 0;\n",
        ]
        assert _if_scope_has_early_exit(lines, 0) is False

    def test_else_if_chain_exit_counts(self):
        lines = [
            "if (size > 100)\n",
            "    log();\n",
            "else if (size < 0)\n",
            "    return -1;\n",
        ]
        assert _if_scope_has_early_exit(lines, 0) is True

    def test_identifier_starting_with_else_ends_scope(self):
        lines = [
            "if (size > 100)\n",
            "    log();\n",
            "elsewhere();\n",
            "return 0;\n",
        ]
        assert _if_scope_has_early_exit(lines, 0) is False

"""Relative finding paths must resolve against the validator's
configured repo_root, not this module's own checkout.

The constructor stores ``repo_root`` precisely so operators can point
the validator at an arbitrary target tree; if a verdict helper falls
back to the module-level default for relative sink paths, the paths
either don't exist (the axis silently no-ops and the verdict degrades)
or — worse — collide with unrelated files in this repository.
"""

from __future__ import annotations

from pathlib import Path

from core.dataflow.finding import Finding, Step
from packages.source_intel.analyze import (
    GRADE_SAME_FUNCTION,
    AbortEvidence,
    SourceIntelResult,
)
from packages.source_intel.adapter import (
    _abort_dominates_finding,
    _downstream_check_suppresses_finding,
)


def _finding(rel_path: str, line: int, rule_id: str,
             snippet: str = "x") -> Finding:
    return Finding(
        finding_id="t",
        producer="codeql",
        rule_id=rule_id,
        message="m",
        source=Step(file_path=rel_path, line=line, column=1,
                    snippet=snippet, label="source"),
        sink=Step(file_path=rel_path, line=line, column=1,
                  snippet=snippet, label="sink"),
        intermediate_steps=(),
        raw={},
    )


def test_abort_dominance_resolves_relative_sink_against_repo_root(
    tmp_path: Path,
):
    (tmp_path / "a.c").write_text(
        "int f(int a)\n"
        "{\n"
        "    BUG_ON(a < 0);\n"
        "    memcpy(dst, src, a);\n"
        "    return 0;\n"
        "}\n"
    )
    abort_abs = str((tmp_path / "a.c").resolve())
    result = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(abort_abs, 3),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function=None,
    ),))
    finding = _finding("a.c", 4, "cpp/unbounded-write")

    # With the operator's repo_root the relative sink resolves onto
    # the abort's file and the axis fires.
    assert _abort_dominates_finding(
        finding, result, repo_root=tmp_path,
    ) is True

    # Resolved against the wrong root the paths can't match — the
    # axis silently no-ops.
    assert _abort_dominates_finding(
        finding, result, repo_root=tmp_path / "elsewhere",
    ) is False


def test_downstream_check_resolves_relative_sink_against_repo_root(
    tmp_path: Path,
):
    (tmp_path / "g.c").write_text(
        "int f(int nex) {\n"
        "    int size = nex * 8;\n"
        "    if (size > 100)\n"
        "        return -1;\n"
        "    use(size);\n"
        "    return 0;\n"
        "}\n"
    )
    finding = _finding(
        "g.c", 2, "cpp/uncontrolled-allocation-size",
        snippet="int size = nex * 8;",
    )
    assert _downstream_check_suppresses_finding(
        finding, repo_root=tmp_path,
    ) is True
    assert _downstream_check_suppresses_finding(
        finding, repo_root=tmp_path / "elsewhere",
    ) is False

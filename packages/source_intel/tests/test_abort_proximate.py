"""Tests for axis-2 abort-proximate evidence.

Covers:
  * Real-spatch E2E that the shipped abort_proximate.cocci fires.
  * Python-side enclosing-function lookup for grading.
  * Adapter verdict: abort-dominance → NOT_EXPLOITABLE for
    memory-corruption findings; non-memory findings unaffected.
  * Render: abort-evidence line shape + grade caveat.
"""

from __future__ import annotations

import shutil
from unittest.mock import patch

import pytest

from core.dataflow.finding import Finding, Step
from core.dataflow.validator import ValidatorVerdict
from packages.source_intel.adapter import (
    SourceIntelValidator,
    _abort_dominates_finding,
)
from packages.source_intel.analyze import (
    GRADE_SAME_FUNCTION,
    AbortEvidence,
    SourceIntelResult,
    _enclosing_function,
    analyze,
)
from packages.source_intel.render import derive_evidence_strings


# =====================================================================
# Enclosing-function lookup
# =====================================================================


def test_enclosing_function_finds_simple_def(tmp_path):
    f = tmp_path / "x.c"
    f.write_text(
        "int outside(int a)\n"     # 1
        "{\n"                      # 2
        "    return a + 1;\n"      # 3
        "}\n"                      # 4
        "\n"                       # 5
        "void example(int x)\n"    # 6
        "{\n"                      # 7
        "    int y = x;\n"         # 8
        "    return;\n"            # 9
        "}\n"                      # 10
    )
    assert _enclosing_function(str(f), 8) == "example"
    assert _enclosing_function(str(f), 3) == "outside"


def test_enclosing_function_returns_none_on_missing_file():
    assert _enclosing_function("/no/such/file.c", 5) is None


def test_enclosing_function_handles_out_of_range(tmp_path):
    f = tmp_path / "x.c"
    f.write_text("int main(void) { return 0; }\n")
    assert _enclosing_function(str(f), 100) is None
    assert _enclosing_function(str(f), 0) is None


# =====================================================================
# Real-spatch E2E
# =====================================================================


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_abort_proximate_fires_on_bug_on(tmp_path):
    """Real spatch runs the shipped abort_proximate rule against a
    fixture containing BUG_ON / panic / abort calls. Result must
    carry AbortEvidence records."""
    src = tmp_path / "abort_fixture.c"
    src.write_text(
        "void BUG_ON(int c);\n"
        "void panic(const char *m);\n"
        "void abort(void);\n"
        "\n"
        "void with_bug_on(int *p) {\n"
        "    BUG_ON(!p);\n"
        "    *p = 1;\n"
        "}\n"
        "\n"
        "void with_panic(int *p) {\n"
        "    if (!p) panic(\"oom\");\n"
        "    *p = 1;\n"
        "}\n"
        "\n"
        "void no_abort(int *p) {\n"
        "    *p = 1;\n"
        "}\n"
    )

    r = analyze(tmp_path)
    macros = {ab.macro for ab in r.aborts}
    assert "BUG_ON" in macros
    assert "panic" in macros


@pytest.mark.skipif(
    not shutil.which("spatch"),
    reason="spatch not installed — skip real-spatch E2E",
)
def test_e2e_abort_captures_enclosing_function(tmp_path):
    """The Python-side function-bounds lookup must correctly attribute
    each abort call to its enclosing function."""
    src = tmp_path / "abort_fns.c"
    src.write_text(
        "void BUG_ON(int c);\n"
        "\n"
        "void func_a(int *p) {\n"
        "    BUG_ON(!p);\n"
        "    *p = 1;\n"
        "}\n"
        "\n"
        "void func_b(int *p) {\n"
        "    *p = 1;\n"
        "}\n"
    )

    r = analyze(tmp_path)
    abort_in_a = [ab for ab in r.aborts if ab.enclosing_function == "func_a"]
    assert abort_in_a, (
        f"expected BUG_ON attributed to func_a; got "
        f"{[(ab.macro, ab.enclosing_function) for ab in r.aborts]!r}"
    )


# =====================================================================
# Verdict policy — abort_dominates → NOT_EXPLOITABLE
# =====================================================================


def _finding(file_path: str, rule_id: str,
             sink_line: int = 5) -> Finding:
    return Finding(
        finding_id="test",
        producer="codeql",
        rule_id=rule_id,
        message="test",
        source=Step(file_path=file_path, line=1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=file_path, line=sink_line, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )


def test_abort_dominates_emits_not_exploitable(tmp_path):
    """Memory-corruption finding + abort in same function →
    NOT_EXPLOITABLE."""
    src = tmp_path / "test.c"
    src.write_text("void f(int *p){BUG_ON(!p);*p=1;}\n")

    finding = _finding(str(src), "cpp/null-dereference",
                       sink_line=1)
    result = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(str(src), 1),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="f",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.NOT_EXPLOITABLE


def test_abort_in_different_function_does_not_dominate(tmp_path):
    """Same-file abort but in a DIFFERENT function — must NOT
    trigger NOT_EXPLOITABLE.

    Note: the fixture includes a caller of `f` so the dead-code
    verdict pass doesn't fire — we're isolating the abort-dominance
    behaviour."""
    src = tmp_path / "test.c"
    src.write_text(
        "void other(int *q){BUG_ON(!q);}\n"
        "void f(int *p){*p=1;}\n"
        "int main(void){int x; f(&x); return 0;}\n"
    )

    finding = _finding(str(src), "cpp/null-dereference",
                       sink_line=2)
    result = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(str(src), 1),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="other",  # different function from f
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        # Should fall through to UNCERTAIN (no attribute evidence either).
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_abort_dominance_skipped_for_injection_cwe(tmp_path):
    """Injection-class findings (CWE-78, CWE-89) don't benefit from
    abort-class signal — exploitation primitive doesn't depend on
    process continuation. NOT_EXPLOITABLE must NOT fire."""
    src = tmp_path / "test.c"
    src.write_text(
        "void f(int *p){BUG_ON(!p);*p=1;}\n"
        "int main(void){int x; f(&x); return 0;}\n"
    )

    finding = _finding(str(src), "cpp/command-line-injection",
                       sink_line=1)
    result = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(str(src), 1),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="f",
    ),))
    with patch(
        "packages.source_intel.adapter.analyze",
        return_value=result,
    ):
        v = SourceIntelValidator(repo_root=tmp_path)
        assert v.validate(finding) == ValidatorVerdict.UNCERTAIN


def test_abort_dominance_pure_helper():
    """Direct test of `_abort_dominates_finding` — same-function
    match wins; cross-function does not."""
    # Build a real file so _enclosing_function can derive the finding's
    # function name (Finding has no `function` field — derived from
    # sink (file, line) via the same heuristic both sides use).
    import tempfile
    import os
    src_dir = tempfile.mkdtemp()
    src_file = os.path.join(src_dir, "x.c")
    with open(src_file, "w") as fh:
        fh.write("void f(int *p)\n{\n    BUG_ON(!p);\n    *p = 1;\n    return;\n}\n")
    finding = Finding(
        finding_id="t",
        producer="codeql",
        rule_id="cpp/null-dereference",
        message="t",
        source=Step(file_path=src_file, line=1, column=1,
                    snippet="x", label="source"),
        sink=Step(file_path=src_file, line=4, column=1,
                  snippet="x", label="sink"),
        intermediate_steps=(),
        raw={},
    )
    matching = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(src_file, 3),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="f",
    ),))
    assert _abort_dominates_finding(finding, matching) is True

    crossing = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=(src_file, 3),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="other",
    ),))
    assert _abort_dominates_finding(finding, crossing) is False


# =====================================================================
# Render
# =====================================================================


def test_abort_evidence_renders_with_grade_caveat():
    """Same_function grade is weak — renderer must say so explicitly
    so Stage D doesn't over-weight."""
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="BUG_ON",
        location=("test.c", 10),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="example",
    ),))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "BUG_ON" in text
    assert "example" in text
    assert "same_function" in text.lower() or "shares the function" in text.lower()
    assert "weak" in text.lower() or "unrelated path" in text.lower()


def test_abort_evidence_with_conditional_caveat():
    """Abort under #ifdef adds the conditional caveat — matching
    attribute-evidence's behaviour."""
    r = SourceIntelResult(aborts=(AbortEvidence(
        macro="panic",
        location=("test.c", 5),
        grade=GRADE_SAME_FUNCTION,
        enclosing_function="f",
        conditional_on="CONFIG_PARANOID",
    ),))
    lines = derive_evidence_strings(r)
    text = "\n".join(lines)
    assert "CONDITIONAL" in text
    assert "CONFIG_PARANOID" in text

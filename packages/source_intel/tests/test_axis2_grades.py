"""Tests for axis-2 grade classifier (same_function / same_path / dominates).

The classifier reads source structure (brace depth + preceding
return/goto) to upgrade abort grade from the default same_function
to same_path or dominates when warranted. Drives verdict policy's
per-grade proximity gate.
"""

from __future__ import annotations



from packages.source_intel.analyze import (
    GRADE_DOMINATES,
    GRADE_SAME_FUNCTION,
    GRADE_SAME_PATH,
    _classify_abort_grade,
)


def test_classifier_handles_missing_file():
    assert _classify_abort_grade("/no/such/file.c", 5) == GRADE_SAME_FUNCTION


def test_classifier_handles_out_of_range(tmp_path):
    f = tmp_path / "x.c"
    f.write_text("int main(void) { return 0; }\n")
    assert _classify_abort_grade(str(f), 100) == GRADE_SAME_FUNCTION


def test_classifier_dominates_unconditional_at_function_start(tmp_path):
    """Unconditional abort at depth 1 (function body) with no
    preceding return/goto → DOMINATES."""
    f = tmp_path / "dom.c"
    f.write_text(
        "void op(void)\n"        # line 1
        "{\n"                    # line 2
        "    BUG();\n"           # line 3 — depth 1, no prior return
        "    return;\n"          # line 4
        "}\n"                    # line 5
    )
    assert _classify_abort_grade(str(f), 3) == GRADE_DOMINATES


def test_classifier_same_path_inside_if_body(tmp_path):
    """Abort inside an if-body (depth 2) → SAME_PATH."""
    f = tmp_path / "sp.c"
    f.write_text(
        "void op(int *p)\n"      # 1
        "{\n"                    # 2
        "    if (!p) {\n"        # 3
        "        BUG();\n"       # 4 — depth 2
        "    }\n"                # 5
        "    *p = 1;\n"          # 6
        "}\n"                    # 7
    )
    assert _classify_abort_grade(str(f), 4) == GRADE_SAME_PATH


def test_classifier_downgrades_when_brace_less_if_return(tmp_path):
    """Conservative behavior on brace-less `if (cond) return;`:
    the `return -1;` sits at depth 1 in the brace tracker (no
    `{...}` around it), so the classifier sees an early-return
    preceding the abort at depth 1 and downgrades to
    SAME_FUNCTION. Documents the conservative-classifier limit —
    pure structural; doesn't reason about conditional exits."""
    f = tmp_path / "early.c"
    f.write_text(
        "int op(int x)\n"        # 1
        "{\n"                    # 2
        "    if (x < 0)\n"       # 3
        "        return -1;\n"   # 4 — at depth 1 in brace tracker
        "    BUG();\n"           # 5 — depth 1
        "    return 0;\n"        # 6
        "}\n"                    # 7
    )
    grade = _classify_abort_grade(str(f), 5)
    assert grade == GRADE_SAME_FUNCTION


def test_classifier_dominates_after_unconditional_return(tmp_path):
    """An unconditional `return` at depth 1 BEFORE the abort means
    abort is unreachable (or at least no longer dominates from
    function entry). Conservative classifier downgrades to
    SAME_FUNCTION."""
    f = tmp_path / "un.c"
    f.write_text(
        "int op(void)\n"         # 1
        "{\n"                    # 2
        "    int x = 0;\n"       # 3
        "    return x;\n"        # 4 — depth 1 unconditional return
        "    BUG();\n"           # 5 — unreachable
        "}\n"                    # 6
    )
    grade = _classify_abort_grade(str(f), 5)
    assert grade == GRADE_SAME_FUNCTION


def test_classifier_dominates_nested_braces(tmp_path):
    """Compound statement around abort — depth 1 if no `if`.

    `{ ... }` block at depth 1 is unusual but valid; abort inside
    counts as depth 2."""
    f = tmp_path / "nested.c"
    f.write_text(
        "void op(void)\n"        # 1
        "{\n"                    # 2
        "    {\n"                # 3 — bare block, depth 2
        "        BUG();\n"       # 4 — depth 3
        "    }\n"                # 5
        "}\n"                    # 6
    )
    grade = _classify_abort_grade(str(f), 4)
    assert grade == GRADE_SAME_PATH

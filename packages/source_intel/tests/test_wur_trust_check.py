"""Tests for axis-1 WUR adversarial-tolerance trust check.

The check refuses to emit EXPLOITABLE on WUR alone when the
annotated function's body is structurally suspect — either
trivially small or returns the same literal on every path.

Documented residual gap: functions returning varying-but-
meaningless values aren't detectable structurally.
"""

from __future__ import annotations


from packages.source_intel.adapter import (
    _is_literal_const,
    _wur_annotation_trustworthy,
)


def test_is_literal_const_recognizes_basics():
    assert _is_literal_const("0")
    assert _is_literal_const("-1")
    assert _is_literal_const("NULL")
    assert _is_literal_const("nullptr")
    assert _is_literal_const("0xdead")
    assert _is_literal_const("(void *)0")


def test_is_literal_const_rejects_variables_and_expressions():
    assert not _is_literal_const("r")
    assert not _is_literal_const("err")
    assert not _is_literal_const("a + b")
    assert not _is_literal_const("compute()")


def test_trust_check_returns_true_on_missing_file():
    """Conservative: file unreadable → trust the annotation."""
    assert _wur_annotation_trustworthy("/no/such.c", "f") is True


def test_trust_check_returns_true_on_empty_inputs():
    assert _wur_annotation_trustworthy("", "f") is True
    assert _wur_annotation_trustworthy("/x.c", "") is True


def test_trust_check_rejects_trivial_body(tmp_path):
    """1-statement body (return literal) → untrustworthy."""
    f = tmp_path / "trivial.c"
    f.write_text(
        "int trivial(void)\n"
        "{\n"
        "    return 0;\n"
        "}\n"
    )
    assert _wur_annotation_trustworthy(str(f), "trivial") is False


def test_trust_check_rejects_long_constant_returns(tmp_path):
    """Long body, all returns are same literal → untrustworthy."""
    f = tmp_path / "constret.c"
    f.write_text(
        "extern int log_thing(const char *);\n"
        "int constret(int x)\n"
        "{\n"
        "    int y = x + 1;\n"
        "    log_thing(\"a\");\n"
        "    log_thing(\"b\");\n"
        "    if (y > 100) {\n"
        "        log_thing(\"big\");\n"
        "        return 0;\n"
        "    }\n"
        "    if (y < 0) {\n"
        "        log_thing(\"neg\");\n"
        "        return 0;\n"
        "    }\n"
        "    return 0;\n"
        "}\n"
    )
    assert _wur_annotation_trustworthy(str(f), "constret") is False


def test_trust_check_accepts_varying_return(tmp_path):
    """Varying return value (variable, not literal) → trustworthy
    by structural check. Documented residual gap: structural
    analysis can't tell if the return value is semantically
    meaningful."""
    f = tmp_path / "vary.c"
    f.write_text(
        "extern int compute(int);\n"
        "int vary(int x)\n"
        "{\n"
        "    int r = compute(x);\n"
        "    if (r < 0) r = -1;\n"
        "    return r;\n"
        "}\n"
    )
    assert _wur_annotation_trustworthy(str(f), "vary") is True


def test_trust_check_accepts_mixed_literal_returns(tmp_path):
    """Returns are literals but DIFFERENT (0 / -1 → error code
    semantics) → trustworthy."""
    f = tmp_path / "mixed.c"
    f.write_text(
        "int mixed(int x)\n"
        "{\n"
        "    if (x < 0)\n"
        "        return -1;\n"
        "    if (x > 100)\n"
        "        return -2;\n"
        "    return 0;\n"
        "}\n"
    )
    assert _wur_annotation_trustworthy(str(f), "mixed") is True


def test_trust_check_handles_declaration_only(tmp_path):
    """Only forward declaration in file (no definition body to
    inspect) → conservative: trust the annotation."""
    f = tmp_path / "decl.c"
    f.write_text(
        "extern int external_fn(int);\n"
    )
    assert _wur_annotation_trustworthy(str(f), "external_fn") is True

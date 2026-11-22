"""Format-argument arity counting — unit and sweep-boundary tests.

The counter may only CONFIRM a deficit it has counted exactly: every
directive, escape and literal form outside the closed grammar declines
the whole call, because an over-count would manufacture a false
positive on a call the compiler accepts as correctly supplied. The
red-team cases here are the decline shapes — each must refuse to
count rather than guess.
"""

from __future__ import annotations

import pytest

pytest.importorskip("tree_sitter")
pytest.importorskip("tree_sitter_c")

from core.audit.format_args import (
    _count_required,
    _unescape,
    check_format_args,
)


def _wrap(body: str) -> str:
    return "#include <stdio.h>\nvoid f(const char *name, int n)\n{\n" + body + "\n}\n"


# ---------------------------------------------------------------------------
# Deficits the counter must confirm
# ---------------------------------------------------------------------------


def test_simple_deficit_is_confirmed():
    r = check_format_args(_wrap('\tprintf("%s %d\\n", name);'))
    assert r.deficit_found is True
    assert r.applicable is True
    assert r.call_name == "printf"
    assert r.required == 2
    assert r.supplied == 1
    assert "undefined behaviour" in r.reasoning


def test_zero_supplied_deficit():
    r = check_format_args(_wrap('\tprintf("%d\\n");'))
    assert r.deficit_found is True
    assert r.required == 1
    assert r.supplied == 0


def test_star_width_consumes_an_argument():
    # %*d needs width + value = 2; only one supplied.
    r = check_format_args(_wrap('\tprintf("%*d\\n", n);'))
    assert r.deficit_found is True
    assert r.required == 2
    assert r.supplied == 1


def test_star_precision_consumes_an_argument():
    r = check_format_args(_wrap('\tprintf("%.*f\\n", n);'))
    assert r.deficit_found is True
    assert r.required == 2


def test_hex_escape_x25_is_a_percent_sign():
    # \x25 unescapes to '%' ('s' is not a hex digit, so the escape
    # stops there), making the format require one argument.
    r = check_format_args(_wrap('\tprintf("\\x25s\\n");'))
    assert r.deficit_found is True
    assert r.required == 1


def test_octal_escape_045_is_a_percent_sign():
    r = check_format_args(_wrap('\tprintf("\\045d\\n");'))
    assert r.deficit_found is True
    assert r.required == 1


def test_snprintf_format_position_two():
    src = _wrap('\tchar b[8];\n\tsnprintf(b, sizeof(b), "%s=%d", name);')
    r = check_format_args(src)
    assert r.deficit_found is True
    assert r.call_name == "snprintf"
    assert r.required == 2
    assert r.supplied == 1


def test_fprintf_format_position_one():
    r = check_format_args(_wrap('\tfprintf(stderr, "%s: %s\\n", name);'))
    assert r.deficit_found is True
    assert r.call_name == "fprintf"


def test_length_modifiers_count_one_argument_each():
    r = check_format_args(_wrap('\tprintf("%hhd %lld %zu %ld\\n", n, n, n);'))
    assert r.deficit_found is True
    assert r.required == 4
    assert r.supplied == 3


def test_multiple_deficits_sorted_and_first_reported():
    src = _wrap('\tprintf("%d %d", n);\n\tprintf("%s");')
    r = check_format_args(src)
    assert r.deficit_found is True
    assert len(r.deficits) == 2
    assert r.deficits[0]["line"] < r.deficits[1]["line"]
    assert r.line == r.deficits[0]["line"]


def test_to_dict_carries_deficit_fields():
    d = check_format_args(_wrap('\tprintf("%d");')).to_dict()
    assert d["deficit_found"] is True
    assert d["required"] == 1
    assert d["supplied"] == 0
    assert d["deficits"]


# ---------------------------------------------------------------------------
# Negatives that are NOT defects
# ---------------------------------------------------------------------------


def test_exact_supply_is_no_deficit():
    r = check_format_args(_wrap('\tprintf("%s %d\\n", name, n);'))
    assert r.deficit_found is False
    assert r.applicable is True
    assert r.analysed_calls == 1


def test_surplus_arguments_are_not_a_defect():
    r = check_format_args(_wrap('\tprintf("%d\\n", n, n, n);'))
    assert r.deficit_found is False
    assert r.applicable is True
    assert "not a defect" in r.reasoning


def test_double_percent_consumes_nothing():
    r = check_format_args(_wrap('\tprintf("100%%\\n");'))
    assert r.deficit_found is False
    assert r.analysed_calls == 1


def test_no_directives_no_deficit():
    r = check_format_args(_wrap('\tprintf("hello\\n");'))
    assert r.deficit_found is False
    assert r.applicable is True


# ---------------------------------------------------------------------------
# Red team: every unmodeled shape declines — a count here could be wrong
# ---------------------------------------------------------------------------


def _declines(body: str) -> None:
    r = check_format_args(_wrap(body))
    assert r.deficit_found is False
    assert r.applicable is False
    assert r.analysed_calls == 0
    assert r.declined_calls >= 1


def test_positional_directive_declines():
    # POSIX %1$d counting is non-local; a deficit guess could be wrong.
    _declines('\tprintf("%1$d %1$d\\n");')


def test_positional_width_declines():
    _declines('\tprintf("%*1$d\\n", n);')


def test_percent_m_declines():
    # glibc %m consumes no argument — outside the portable grammar.
    _declines('\tprintf("%m\\n");')


def test_wide_conversions_decline():
    _declines('\tprintf("%S\\n");')
    _declines('\tprintf("%C\\n");')


def test_flagged_double_percent_declines():
    # "%-%" is not a %% pair; glibc tolerates it, the grammar does not.
    _declines('\tprintf("%-%\\n");')


def test_trailing_lone_percent_declines():
    _declines('\tprintf("abc%");')


def test_unknown_conversion_declines():
    _declines('\tprintf("%y\\n");')


def test_universal_escape_declines():
    _declines('\tprintf("\\u0025d\\n");')


def test_gnu_e_escape_declines():
    _declines('\tprintf("\\e[0m%d\\n");')


def test_out_of_range_hex_escape_declines():
    _declines('\tprintf("\\x100%d\\n", n);')


def test_prefixed_literal_declines():
    _declines('\tprintf(u8"%d\\n");')


def test_non_literal_format_declines():
    _declines("\tprintf(name);")


def test_concatenated_literal_declines():
    # tree-sitter yields concatenated_string, not string_literal.
    _declines('\tprintf("%d" "%d\\n", n);')


def test_preprocessor_inside_call_declines():
    # Conditional compilation inside an argument list trips the parse
    # gate (has_error) today; the in-subtree preproc check behind it is
    # defence in depth. Either way nothing may be counted.
    r = check_format_args(
        _wrap('\tprintf("%d\\n"\n#ifdef X\n\t, n\n#endif\n\t);'),
    )
    assert r.deficit_found is False
    assert r.applicable is False
    assert r.analysed_calls == 0


def test_missing_format_argument_declines():
    _declines("\tsnprintf(name, 4);")


def test_va_list_variants_are_not_seeded():
    src = (
        "#include <stdarg.h>\n"
        "void g(const char *fmt, va_list ap)\n{\n"
        '\tvprintf("%d %d", ap);\n'
        "}\n"
    )
    r = check_format_args(src)
    assert r.deficit_found is False
    assert r.applicable is False
    assert r.declined_calls == 0  # never considered at all


def test_call_through_pointer_is_not_counted():
    r = check_format_args(_wrap('\t(*fn)("%d %d", n);'))
    assert r.deficit_found is False
    assert r.analysed_calls == 0


def test_unparseable_source_declines():
    r = check_format_args('void f( {{{ printf("%d"); }')
    assert r.deficit_found is False
    assert r.applicable is False


def test_empty_source_declines():
    r = check_format_args("")
    assert r.deficit_found is False
    assert r.applicable is False


def test_oversized_source_declines():
    r = check_format_args("x" * ((1 << 20) + 1))
    assert r.deficit_found is False
    assert r.applicable is False


def test_decline_does_not_poison_other_calls():
    # One declined call in the file must not block counting the rest.
    src = _wrap('\tprintf("%1$d");\n\tprintf("%d %d", n);')
    r = check_format_args(src)
    assert r.deficit_found is True
    assert r.declined_calls == 1
    assert r.analysed_calls == 1


# ---------------------------------------------------------------------------
# Counter internals: the closed grammar is exactly as documented
# ---------------------------------------------------------------------------


def test_count_required_grammar():
    assert _count_required("") == 0
    assert _count_required("%d") == 1
    assert _count_required("%%") == 0
    assert _count_required("%-08.3f") == 1
    assert _count_required("%*.*s") == 3
    assert _count_required("%lld %zu") == 2
    assert _count_required("%") is None
    assert _count_required("%1$d") is None
    assert _count_required("%.2$d") is None
    assert _count_required("%m") is None
    assert _count_required("%-%") is None
    assert _count_required("%qd") == 1  # BSD %qd: q modifier, d converts
    assert _count_required("%q") is None  # modifier running off the end
    assert _count_required("%k") is None


def test_unescape_grammar():
    assert _unescape("a\\nb") == "a\nb"
    assert _unescape("\\x25") == "%"
    assert _unescape("\\045") == "%"
    assert _unescape("\\0") == "\0"
    assert _unescape('\\"\\\\') == '"\\'
    assert _unescape("\\u0025") is None
    assert _unescape("\\e") is None
    assert _unescape("\\x") is None
    assert _unescape("\\x1ff") is None
    assert _unescape("tail\\") is None


# ---------------------------------------------------------------------------
# Sweep boundary: confirmed survives, negatives capped at inconclusive
# ---------------------------------------------------------------------------


def _sweep(source: str):
    from core.audit.sweep import _run_smt_verb_inner
    return _run_smt_verb_inner(
        file_path="unit.c",
        function_name="f",
        verb="check-format-args",
        source=source,
        hypothesis="printf called with too few arguments",
    )


def test_sweep_deficit_is_confirmed_with_scope():
    result = _sweep(_wrap('\tprintf("%s %d\\n", name);'))
    assert result.outcome == "confirmed"
    assert result.details["required"] == 2
    assert result.details["supplied"] == 1
    assert result.details["oracle_scope"] == "source-pattern"


def test_sweep_clean_negative_is_capped_at_inconclusive():
    # applicable=True would be "refuted", but the diagnostic scope caps
    # every non-confirmed outcome at inconclusive.
    result = _sweep(_wrap('\tprintf("%d\\n", n);'))
    assert result.outcome == "inconclusive"
    assert result.details["applicable"] is True


def test_sweep_declined_source_is_inconclusive():
    result = _sweep(_wrap('\tprintf("%1$d");'))
    assert result.outcome == "inconclusive"
    assert result.details["applicable"] is False

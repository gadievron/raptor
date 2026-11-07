"""Tests for header_functions — function definition index from C/C++ headers."""

import pytest

from core.inventory.header_functions import (
    build_header_function_index,
    lookup_header_function,
    _extract_function_body,
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Build header indexes in a private ordered cache under its lock."""
    from collections import OrderedDict
    from importlib import import_module

    from core.testing.module_state import isolated_module_state

    header_mod = import_module("core.inventory.header_functions")
    with isolated_module_state(
        header_mod, {"_cache": OrderedDict()}, lock=header_mod._cache_lock,
    ):
        yield


class TestBuildIndex:
    def test_static_inline(self, tmp_path):
        (tmp_path / "util.h").write_text(
            "static inline int max(int a, int b) {\n"
            "    return a > b ? a : b;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "max" in idx
        assert idx["max"][0] == "util.h"
        assert "return a > b" in idx["max"][1]

    def test_skips_declarations(self, tmp_path):
        (tmp_path / "api.h").write_text(
            "int compute(int x);\n"
            "void process(const char *data);\n"
        )
        idx = build_header_function_index(tmp_path)
        assert len(idx) == 0

    def test_skips_c_files(self, tmp_path):
        (tmp_path / "impl.c").write_text(
            "int foo(void) {\n"
            "    return 42;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert len(idx) == 0

    def test_multiple_functions(self, tmp_path):
        (tmp_path / "helpers.h").write_text(
            "static inline int min(int a, int b) {\n"
            "    return a < b ? a : b;\n"
            "}\n"
            "\n"
            "static inline int clamp(int v, int lo, int hi) {\n"
            "    if (v < lo) return lo;\n"
            "    if (v > hi) return hi;\n"
            "    return v;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "min" in idx
        assert "clamp" in idx

    def test_skips_long_functions(self, tmp_path):
        body_lines = "\n".join(f"    line{i}();" for i in range(35))
        (tmp_path / "big.h").write_text(
            f"static void big(void) {{\n{body_lines}\n}}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "big" not in idx

    def test_cached(self, tmp_path):
        (tmp_path / "a.h").write_text(
            "static inline void noop(void) {}\n"
        )
        i1 = build_header_function_index(tmp_path)
        i2 = build_header_function_index(tmp_path)
        assert i1 is i2

    def test_attribute_always_inline(self, tmp_path):
        (tmp_path / "fast.h").write_text(
            "__attribute__((always_inline)) static inline int sq(int x) {\n"
            "    return x * x;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "sq" in idx

    def test_nested_braces(self, tmp_path):
        (tmp_path / "ctrl.h").write_text(
            "static inline int abs_val(int x) {\n"
            "    if (x < 0) {\n"
            "        return -x;\n"
            "    }\n"
            "    return x;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "abs_val" in idx
        assert "return -x" in idx["abs_val"][1]

    def test_function_pointer_parameter(self, tmp_path):
        """A fn-pointer parameter nests parentheses inside the list;
        the flat [^)]* param pattern never reached the brace."""
        (tmp_path / "cb.h").write_text(
            "static inline void each(int n, void (*cb)(int)) {\n"
            "    for (int i = 0; i < n; i++) cb(i);\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "each" in idx
        assert "cb(i)" in idx["each"][1]

    def test_subdirectory_headers(self, tmp_path):
        sub = tmp_path / "include" / "mylib"
        sub.mkdir(parents=True)
        (sub / "math.h").write_text(
            "static inline int double_it(int x) { return x * 2; }\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "double_it" in idx
        assert "include/mylib/math.h" in idx["double_it"][0]

    def test_skips_keywords(self, tmp_path):
        (tmp_path / "bad.h").write_text(
            "if (x) {\n    foo();\n}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "if" not in idx

    def test_skips_reserved_words_but_keeps_prefix_names(self, tmp_path):
        # _SKIP_NAMES shares the extractor's reserved-word blocklist:
        # a captured name that is a C/C++ reserved word (`class` is a
        # legal C identifier but reserved in C++) is refused, while
        # identifiers that merely prefix a reserved word must index.
        (tmp_path / "mix.h").write_text(
            "static int class(int x) {\n"
            "    return x;\n"
            "}\n"
            "static int classify(int x) {\n"
            "    return x + 1;\n"
            "}\n"
            "static int interior(void) {\n"
            "    return 2;\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "class" not in idx
        assert "classify" in idx
        assert "interior" in idx

    def test_braces_inside_string_literal(self, tmp_path):
        (tmp_path / "fmt.h").write_text(
            'static inline void fmt(int x) {\n'
            '    printf("value={%d}", x);\n'
            '}\n'
        )
        idx = build_header_function_index(tmp_path)
        assert "fmt" in idx
        assert "printf" in idx["fmt"][1]

    def test_braces_inside_char_literal(self, tmp_path):
        (tmp_path / "tok.h").write_text(
            "static inline int is_open(char c) {\n"
            "    return c == '{';\n"
            "}\n"
        )
        idx = build_header_function_index(tmp_path)
        assert "is_open" in idx


class TestLookup:
    def test_found(self, tmp_path):
        (tmp_path / "u.h").write_text(
            "static inline void noop(void) {}\n"
        )
        result = lookup_header_function(tmp_path, "noop")
        assert result is not None
        assert result[0] == "u.h"

    def test_not_found(self, tmp_path):
        (tmp_path / "u.h").write_text(
            "static inline void noop(void) {}\n"
        )
        assert lookup_header_function(tmp_path, "missing") is None


class TestExtractFunctionBody:
    def test_single_line(self):
        lines = ["int f(void) { return 1; }"]
        result = _extract_function_body(lines, 0)
        assert result is not None
        assert "return 1" in result

    def test_multi_line(self):
        lines = [
            "int f(void) {",
            "    return 1;",
            "}",
        ]
        result = _extract_function_body(lines, 0)
        assert result is not None
        assert "return 1" in result

    def test_unclosed(self):
        lines = ["int f(void) {", "    x++;"]
        assert _extract_function_body(lines, 0) is None


class TestMultiLineSignature:
    def test_two_line_signature_gets_full_body(self, tmp_path):
        # The depth<=0 exit fired after the FIRST line even when that
        # line carried no brace — a multi-line signature returned a
        # one-line "body" (degraded callee-enrichment hints).
        (tmp_path / "multi.h").write_text(
            "static inline int add_pair(int a,\n"
            "                           int b) {\n"
            "    return a + b;\n"
            "}\n"
        )
        result = lookup_header_function(tmp_path, "add_pair")
        assert result is not None
        _, body = result
        assert "return a + b;" in body
        assert body.count("\n") >= 2

    def test_single_line_body_still_extracted(self, tmp_path):
        (tmp_path / "one.h").write_text(
            "static inline int one(void) { return 1; }\n"
        )
        result = lookup_header_function(tmp_path, "one")
        assert result is not None
        assert "return 1;" in result[1]


@pytest.mark.parametrize('separator', ['\v', '\f', '\x1c', '\x1d', '\x1e', '\x85', '\u2028', '\u2029'],
                         ids=['vt', 'ff', 'fs', 'gs', 'rs', 'nel', 'ls', 'ps'])
def test_display_separators_do_not_shift_header_bodies(tmp_path, separator):
    first = 'static int first(void) {\n    return 1;\n}'
    second = 'static int second(void) {\n    return 2;\n}'
    (tmp_path / 'rows.h').write_text(
        f'/* comment{separator}still on the same source row */\n'
        f'{first}\n/* middle{separator}comment */\n{second}\n',
        encoding='utf-8',
    )
    assert build_header_function_index(tmp_path) == {
        'first': ('rows.h', first), 'second': ('rows.h', second),
    }


def test_display_separator_does_not_consume_body_line_budget(tmp_path):
    body = 'static int thirty(void) {\n' + '    /* a\fb */\n' * 28 + '}'
    (tmp_path / 'budget.h').write_text(body + '\n', encoding='utf-8')
    assert build_header_function_index(tmp_path) == {'thirty': ('budget.h', body)}


def test_declarations_and_reserved_names_need_no_line_list(tmp_path, monkeypatch):
    from core.inventory import header_functions as mod

    (tmp_path / 'decls.h').write_text('int declared(void);\nif (x) {\n}\n', encoding='utf-8')

    def unexpected(*args):
        raise AssertionError('header without eligible definitions was split')

    monkeypatch.setattr(mod, 'split_lines', unexpected)
    assert build_header_function_index(tmp_path) == {}


def test_duplicate_only_header_needs_no_line_list(tmp_path, monkeypatch):
    from core.inventory import header_functions as mod

    first = tmp_path / 'first.h'
    second = tmp_path / 'second.h'
    first.write_text('static int same(void) { return 1; }\n', encoding='utf-8')
    second.write_text('static int same(void) { return 2; }\n', encoding='utf-8')
    monkeypatch.setattr(mod, 'iter_regular_files', lambda *args: iter([first, second]))
    split = mod.split_lines
    seen = []

    def observed(text):
        seen.append(text)
        return split(text)

    monkeypatch.setattr(mod, 'split_lines', observed)
    assert build_header_function_index(tmp_path) == {
        'same': ('first.h', 'static int same(void) { return 1; }'),
    }
    assert seen == [first.read_text()]


def test_line_progress_survives_skips_failed_bodies_and_file_reset(tmp_path, monkeypatch):
    from core.inventory import header_functions as mod

    first = tmp_path / 'first.h'
    second = tmp_path / 'second.h'
    accepted = 'static int recover(void) { return 3; }'
    last = 'static int last(void) { return 4; }'
    first.write_text(
        '/* preamble */\nif (x) {}\nstatic int same(void) { return 1; }\n'
        'static int same(void) { return 2; }\nstatic int recover(void) {\n'
        + '    statement();\n' * 36 + '}\n' + accepted + '\n', encoding='utf-8',
    )
    second.write_text(last + '\n', encoding='utf-8')
    monkeypatch.setattr(mod, 'iter_regular_files', lambda *args: iter([first, second]))
    assert build_header_function_index(tmp_path) == {
        'same': ('first.h', 'static int same(void) { return 1; }'),
        'recover': ('first.h', accepted), 'last': ('second.h', last),
    }


def test_text_adapter_keeps_full_prefix_count_operations(tmp_path, monkeypatch):
    from pathlib import Path
    from core.inventory import header_functions as mod

    calls = []

    class Text(str):
        def count(self, separator, start=0, end=None):
            calls.append((separator, start, end))
            return super().count(separator, start, end)

    class Header(type(Path())):
        def read_text(self, **kwargs):
            return Text(super().read_text(**kwargs))

    path = tmp_path / 'adapter.h'
    source = '/* preface */\nstatic int one(void) {}\nstatic int two(void) {}\n'
    path.write_text(source, encoding='utf-8')
    monkeypatch.setattr(mod, 'iter_regular_files', lambda *args: iter([Header(path)]))
    assert list(build_header_function_index(tmp_path)) == ['one', 'two']
    assert calls == [('\n', 0, source.index('static int one')),
                     ('\n', 0, source.index('static int two'))]

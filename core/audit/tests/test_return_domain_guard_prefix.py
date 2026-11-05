"""Guard prefilter is only a necessary-condition optimization."""

import tracemalloc

import pytest

from core.audit import return_domain as rd


@pytest.mark.parametrize('separator', ['\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x85', '\u2028', '\u2029'])
def test_guard_keeps_existing_splitlines_model(separator):
    source = separator.join(['#\tifndef GUARD', '#define GUARD', 'int live;', '#endif', ''])
    assert rd._strip_include_guard(source) == '\n\nint live;\n'


@pytest.mark.parametrize('whitespace', ['', ' ', '\t', '\u2003'])
def test_prefix_accepts_original_whitespace(whitespace):
    source = f'#{whitespace}ifndef GUARD\n#define GUARD\nint live;\n#endif\n'
    assert rd._strip_include_guard(source) == '\n\nint live;\n'


@pytest.mark.parametrize('source', [
    '#ifdef OTHER\n#endif\n#ifndef GUARD\n#define GUARD\n#endif\n',
    '#ifndef GUARD\n#define GUARD 1\n#endif\n',
    '#ifndef GUARD\n#define GUARD\n#endif\nint live;\n',
    '#ifndefGUARD\n#define GUARD\n#endif\n',
])
def test_possible_prefix_does_not_bypass_guard_validation(source):
    assert rd._strip_include_guard(source) == source


def test_string_subclass_retains_splitlines_override():
    class Source(str):
        def splitlines(self):
            return ['#ifndef GUARD', '#define GUARD', 'int live;', '#endif']

    assert rd._strip_include_guard(Source('no guard prefix')) == '\n\nint live;\n'


def test_unguarded_file_does_not_allocate_a_line_list():
    if tracemalloc.is_tracing():
        pytest.skip('requires isolated allocation tracing')
    source = 'int ordinary;\n' * 100000
    tracemalloc.start()
    try:
        result = rd._strip_include_guard(source)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert result == source
    assert peak < 64 * 1024

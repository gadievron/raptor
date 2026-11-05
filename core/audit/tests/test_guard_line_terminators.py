"""Guard alignment keeps offsets when views blank line terminators."""

import pytest

from core.audit.prefilter import _guard_view_lines


@pytest.mark.parametrize('terminator', [
    '\n', '\r', '\r\n', '\v', '\f', '\x1c', '\x1d', '\x1e',
    '\x85', '\u2028', '\u2029',
])
def test_alignment_uses_original_terminator_width(terminator):
    first = '  alpha'
    second = '\tbeta '
    source = first + terminator + second + terminator + 'gamma'
    # A view may blank terminators; alignment must follow the source.
    view = ''.join(chr(65 + i % 26) for i in range(len(source)))
    second_start = len(first) + len(terminator)
    third_start = second_start + len(second) + len(terminator)
    assert _guard_view_lines(source, view) == [
        view[2:7], view[second_start + 1:second_start + 5], view[third_start:],
    ]
    assert _guard_view_lines(terminator * 2, ' ' * (len(terminator) * 2)) == ['', '']


def test_custom_splitlines_keeps_original_segment_handling():
    class Source(str):
        def splitlines(self, keepends=False):
            assert keepends is True
            return [' alpha\n beta\n']

    assert _guard_view_lines(Source('unused'), '0123456789abcdef') == ['12345']

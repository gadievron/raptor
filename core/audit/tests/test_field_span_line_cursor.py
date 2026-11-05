"""Regex spans retain independent end coordinates for overlapping heads."""

from core.audit.field_census import function_spans_regex


def test_nested_heads_keep_independent_end_lines():
    source = 'int outer(void) {\nint inner(void) {\n}\n}\n'
    spans = function_spans_regex(source)
    assert [(s.name, s.start, s.end) for s in spans] == [
        ('outer', 1, 4), ('inner', 2, 3),
    ]


def test_unclosed_heads_keep_final_lf_line():
    source = '// heading\x85still one LF line\nint outer(void) {\nint inner(void) {\n'
    spans = function_spans_regex(source)
    assert [(s.name, s.start, s.end) for s in spans] == [
        ('outer', 2, 4), ('inner', 3, 4),
    ]


def test_string_subclass_keeps_prefix_counting():
    calls = []

    class Source(str):
        def count(self, sub, start=0, end=None):
            calls.append((sub, start, end))
            return super().count(sub, start, end)

    source = Source('int first(void) {\n}\nint second(void) {\n}\n')
    spans = function_spans_regex(source)
    assert [(s.name, s.start, s.end) for s in spans] == [
        ('first', 1, 2), ('second', 3, 4),
    ]
    assert len(calls) == 4
    assert all(sub == '\n' and start == 0 for sub, start, _ in calls)

"""Function extraction retains LF coordinates and subclass behavior."""

from core.audit._util import extract_functions_from_source


def test_coordinates_follow_lf_not_unicode_line_separators():
    source = '# heading\x85still one line\n\ndef first():\n    pass\n\nasync def second():\n    pass'
    assert extract_functions_from_source(source) == [
        ('first', 3, 'def first():\n    pass\n'),
        ('second', 6, 'async def second():\n    pass'),
    ]


def test_string_subclass_keeps_prefix_count_calls():
    calls = []

    class Source(str):
        def count(self, sub, start=0, end=None):
            calls.append((sub, start, end))
            return super().count(sub, start, end)

    source = Source('def first():\n    pass\n\ndef second():\n    pass')
    records = extract_functions_from_source(source)
    assert [(name, line) for name, line, _ in records] == [('first', 1), ('second', 4)]
    assert calls == [('\n', 0, 0), ('\n', 0, source.index('def second'))]

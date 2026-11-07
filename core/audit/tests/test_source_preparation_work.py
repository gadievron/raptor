"""Native source preparation avoids unused copies and repeated head work."""

import pytest

from core.audit import _util
from core.audit import dispatch_completeness as dispatch


def test_function_extraction_handles_data_only_and_lf_coordinates():
    assert _util.extract_functions_from_source('value = 1\n' * 10000) == []
    assert _util.extract_functions_from_source('# definition data only\n' * 10000) == []
    source = '# a\fb\u2028c\nasync def one():\n    return 1\n\ndef two():\n    return 2\n'
    assert _util.extract_functions_from_source(source) == [
        ('one', 2, 'async def one():\n    return 1\n'),
        ('two', 5, 'def two():\n    return 2\n'),
    ]


def test_function_source_adapter_keeps_eager_splitting():
    calls = []

    class Source(str):
        def split(self, *args):
            calls.append(args)
            return super().split(*args)

    assert _util.extract_functions_from_source(Source('not a function\n')) == []
    assert calls == [('\n',)]


def test_dispatch_absent_literal_needs_no_native_lines(monkeypatch):
    def unexpected(*args):
        raise AssertionError('native stream without if was split')

    # Instrument the trusted provider identity at the local seam. Adapter
    # replacement without this trusted marker is covered separately below.
    monkeypatch.setattr(dispatch, 'split_lines', unexpected)
    monkeypatch.setattr(dispatch, '_DISPATCH_LINES_IMPL', unexpected)
    assert dispatch._extract_if_elif_tables_from_source('value = 1\n' * 10000, 'a.py') == []


def test_dispatch_replaced_line_provider_retains_its_results(monkeypatch):
    lines = ['if kind == "one":', '    pass', 'elif kind == "two":', '    pass']
    monkeypatch.setattr(dispatch, 'split_lines', lambda source: lines)
    tables = dispatch._extract_if_elif_tables_from_source('payload', 'a.py')
    assert [table.to_dict() for table in tables] == [{
        'file': 'a.py', 'function': '<module>', 'line': 1,
        'keys': ['one', 'two'], 'table_type': 'if_elif',
    }]


def test_dispatch_source_adapter_retains_line_split_even_without_literal():
    calls = []

    class Source(str):
        def split(self, *args):
            calls.append(args)
            return super().split(*args)

    assert dispatch._extract_if_elif_tables_from_source(Source('payload'), 'a.py') == []
    assert calls == [('\n',)]


@pytest.mark.parametrize('indent', ['', '  ', '\t', '\f'], ids=['none', 'spaces', 'tab', 'form-feed'])
def test_dispatch_long_body_keeps_table_metadata(indent):
    source = ('def run():\n' + indent + 'if kind == "one":\n'
              + indent + '    pass\n' * 200
              + indent + 'elif kind == "two":\n' + indent + '    pass\n')
    tables = dispatch._extract_if_elif_tables_from_source(source, 'a.py')
    assert len(tables) == 1
    assert tables[0].keys == {'one', 'two'} and tables[0].line == 2
    assert tables[0].function == 'run'


def test_function_source_adapter_invalid_split_keeps_original_error():
    calls = []

    class Source(str):
        def split(self, *args):
            calls.append(args)
            return None

    with pytest.raises(TypeError):
        _util.extract_functions_from_source(Source('def one():\n    return 1\n'))
    assert calls == [('\n',)]


def test_replaced_function_pattern_keeps_its_match_language(monkeypatch):
    import re

    pattern = re.compile(r'^(?P<indent>[ \t]*)fn (?P<name>\w+)\(', re.MULTILINE)
    monkeypatch.setattr(_util, '_FUNC_DEF_RE', pattern)
    assert _util.extract_functions_from_source('fn one():\n    return 1\n') == [
        ('one', 1, 'fn one():\n    return 1\n'),
    ]


def test_dispatch_foreign_lines_retain_strip_operations(monkeypatch):
    counts = [0, 0, 0, 0]

    class Line(str):
        def lstrip(self, *args):
            counts[self.index] += 1
            return super().lstrip(*args)

    lines = []
    for i, text in enumerate(['if mode == "one":', '    pass', 'elif mode == "two":', '    pass']):
        line = Line(text)
        line.index = i
        lines.append(line)
    monkeypatch.setattr(dispatch, 'split_lines', lambda source: lines)
    tables = dispatch._extract_if_elif_tables_from_source('payload', 'a.py')
    assert len(tables) == 1 and tables[0].keys == {'one', 'two'}
    assert counts == [3, 2, 1, 2]

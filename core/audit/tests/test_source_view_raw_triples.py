"""Raw triple-quote boundaries and EOF diagnostics remain stable."""

import pytest

from core.audit.source_view import _java_text_block_end, sanitized_view_with_status


@pytest.mark.parametrize(('body', 'closed'), [
    ('', True),
    ('ordinary text', True),
    ('a\nb\r\né🙂', True),
    ('ends with backslash\\', True),
    ('"one" and ""two', True),
    ('', False),
    ('unterminated\n', False),
    ('two quotes ""', False),
])
def test_raw_triple_close_and_eof(body, closed):
    text = 'prefix """' + body + ('""" tail' if closed else '')
    calls = []
    end = _java_text_block_end(text, 7, escapes=False,
                              on_eof=lambda: calls.append('eof'))
    assert end == (10 + len(body) + 3 if closed else len(text))
    assert calls == ([] if closed else ['eof'])


def test_escaped_java_close_keeps_scanning():
    text = '"""body\\"""still data""" tail'
    assert _java_text_block_end(text, 0, escapes=True) == text.index(' tail')


def test_string_subclass_retains_original_access():
    class Source(str):
        def find(self, *args):
            raise AssertionError('subclasses retain character scanning')

    assert _java_text_block_end(Source('"""body""" tail'), 0,
                                escapes=False) == 10


@pytest.mark.parametrize('extension', ['kt', 'cs'])
def test_raw_triples_preserve_following_code(extension):
    text = 'var s = """data\nwith trailing slash\\""";\nlive();\n'
    result = sanitized_view_with_status(text, 'a.' + extension)
    assert 'live();' in result.text
    assert 'data' not in result.text
    assert len(result.text) == len(text)
    assert result.text.count('\n') == text.count('\n')
    assert not result.reasons

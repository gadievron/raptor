"""Sink argument extraction retains its raw LF five-line window."""

from core.audit.condition_binding import extract_sink_arg_identifiers


def test_large_source_keeps_five_line_limit():
    source = ('header' * 3000 + '\n'
              'sink(\nalpha,\nobj.field,\nbeta,\ngamma,\noutside);\n')
    identifiers = extract_sink_arg_identifiers(source, 2, 'sink')
    assert {'alpha', 'obj.field', 'beta', 'gamma'} <= identifiers
    assert 'outside' not in identifiers


def test_large_source_empty_window_stays_empty():
    source = 'header' * 3000 + '\n\n'
    assert extract_sink_arg_identifiers(source, 2, '') == frozenset()
    assert extract_sink_arg_identifiers(source, 999, 'sink') == frozenset()

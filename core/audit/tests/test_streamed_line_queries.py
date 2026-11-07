"""Audit line scans retain coordinates, caps and overridden providers."""
import pytest

from core.audit import constant_resolution as constants
from core.audit import fail_open_detector as fail
from core.audit import fail_open_lang as lang
from core.audit import return_domain as domain


@pytest.mark.parametrize('kind', ['ignored', 'tristate'])
def test_native_span_stops_before_unused_source_tail(monkeypatch, kind):
    seen = []

    def observed(source):
        for text in ['header', 'f();' if kind == 'ignored' else 'if (f()) {', 'outside']:
            seen.append(text)
            yield text
        raise AssertionError('query consumed past the native span')

    monkeypatch.setattr(lang, 'iter_source_lines', observed)
    fn = lang._ignored_return_regex if kind == 'ignored' else lang._tristate_regex
    rows = fn('native source', 'f', (2, 2))
    assert len(rows) == 1 and rows[0].line == 2
    assert seen == ['header', 'f();' if kind == 'ignored' else 'if (f()) {', 'outside']


def test_first_definition_does_not_consume_unused_tail(monkeypatch):
    def observed(source):
        yield 'def consume():'
        raise AssertionError('start-line lookup consumed the tail')

    monkeypatch.setattr(fail, 'iter_source_lines', observed)
    assert fail._function_start_line('native source', 'consume') == 1


def test_peer_cap_and_exclusion_keep_source_order_and_coordinates(monkeypatch):
    seen = []

    def observed(source):
        for i in range(1, 8):
            seen.append((source, i))
            yield 'f() < 0'
        raise AssertionError('peer lookup consumed beyond its five-result cap')

    monkeypatch.setattr(domain, 'iter_source_lines', observed)
    rows = domain._peer_checks({'a.c': 'first', 'b.c': 'second'}, 'f', ('a.c', 2))
    assert rows == [f'a.c:{i} tests `< 0`' for i in [1, 3, 4, 5, 6]]
    assert seen == [('first', i) for i in range(1, 7)]


@pytest.mark.parametrize('consumer', ['start', 'peers', 'depth', 'ignored', 'tristate'])
def test_replaced_split_provider_retains_direct_operation(monkeypatch, consumer):
    seen = []
    modules = {'start': fail, 'peers': domain, 'depth': constants, 'ignored': lang, 'tristate': lang}
    module = modules[consumer]

    def provided(source):
        seen.append(source)
        return ['f();', 'if (f()) {', '#if F', '#endif']

    def forbidden(source):
        raise AssertionError('replaced provider bypassed')

    monkeypatch.setattr(module, 'split_lines', provided)
    monkeypatch.setattr(module, 'iter_source_lines', forbidden)
    if consumer == 'start':
        assert fail._function_start_line('source', 'f') == 1
    elif consumer == 'peers':
        assert domain._peer_checks({'a.c': 'source'}, 'f', ('a.c', 100)) == []
    elif consumer == 'depth':
        assert constants._compute_conditional_depths('source') == {1: 0, 2: 0, 3: 1, 4: 0}
    else:
        fn = lang._ignored_return_regex if consumer == 'ignored' else lang._tristate_regex
        fn('source', 'f', (1, 2))
    assert seen == ['source']


def test_foreign_span_keeps_per_line_access_operations():
    seen = []

    class Span(tuple):
        def __getitem__(self, index):
            seen.append(index)
            return super().__getitem__(index)

    source = 'f();\nblank\nblank\n'
    rows = lang._ignored_return_regex(source, 'f', Span((1, 1)))
    assert len(rows) == 1
    assert seen == [0, 1] * 3


def test_exotic_separators_do_not_shift_native_line_numbers():
    source = 'prefix\v\f\x85\u2028\rtext\r\nf();\r\nif (f()) {\n\r'
    ignored = lang._ignored_return_regex(source, 'f', None)
    tristate = lang._tristate_regex(source, 'f', None)
    assert ignored[0].line == 2 and tristate[0].line == 3


def test_foreign_source_keeps_split_calls_and_results(monkeypatch):
    events = []

    class Source(str):
        def split(self, separator):
            events.append(separator)
            return super().split(separator)

    def forbidden(source):
        raise AssertionError('foreign source streamed')

    monkeypatch.setattr(lang, 'iter_source_lines', forbidden)
    source = Source('f();\r\nif (f()) {\n')
    rows = lang._ignored_return_regex(source, 'f', None)
    assert rows and rows[0].line == 1 and events == ['\n']


def test_start_line_regex_override_keeps_each_original_search(monkeypatch):
    from core.testing.module_bindings import patch_module_attribute

    calls = []
    actual = fail.re.search

    def observed(pattern, text):
        calls.append(text)
        return actual(pattern, text)

    patch_module_attribute(monkeypatch, fail, 're', 'search', observed)
    assert fail._function_start_line('header\npadding\ndef consume():\n', 'consume') == 3
    assert calls == ['header', 'padding', 'def consume():']


def test_native_start_line_prepares_the_pattern_once(monkeypatch):
    from core.testing.module_bindings import patch_module_attribute

    calls = []
    actual_compile, actual_escape = fail.re.compile, fail.re.escape

    def compile_pattern(pattern):
        calls.append('compile')
        return actual_compile(pattern)

    def escape_name(name):
        calls.append('escape')
        return actual_escape(name)

    patch_module_attribute(monkeypatch, fail, 're', 'compile', compile_pattern)
    patch_module_attribute(monkeypatch, fail, 're', 'escape', escape_name)
    # Observe trusted providers at the consumer seam; ordinary replacements
    # without these markers retain the direct operations tested above.
    monkeypatch.setattr(fail, '_START_RE_MODULE', fail.re)
    monkeypatch.setattr(fail, '_START_COMPILE_IMPL', compile_pattern)
    monkeypatch.setattr(fail, '_START_ESCAPE_IMPL', escape_name)
    assert fail._function_start_line('padding\n' * 100 + 'def consume():', 'consume') == 101
    assert calls == ['escape', 'compile']

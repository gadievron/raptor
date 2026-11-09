"""Cleanup scan admission preserves findings and adapted matcher behaviour."""
import re

import pytest

from core.audit import intra_function as original
from core.testing.module_views import module_function_view


@pytest.fixture
def view():
    return module_function_view(original)


def _source(body):
    return 'int f(void) {\n' + '    use(buf);\n' * 40 + body + '\n}\n'


def test_native_impossible_scan_reaches_admission(view):
    calls = []
    native = view._cleanup_scan_definitely_empty

    def observe(*args):
        result = native(*args)
        calls.append(result)
        return result

    view._cleanup_scan_definitely_empty = observe
    assert view.check_cleanup_consistency(_source('free(buf);')) == []
    assert calls == [True]


def test_short_function_does_not_enter_admission(view):
    def unexpected(*args):
        raise AssertionError('short function entered admission')

    view._cleanup_scan_definitely_empty = unexpected
    assert view.check_cleanup_consistency('int f(){\nuse(buf);\nfree(buf);\n}\n') == []


def test_recompiled_seed_pattern_still_admits(view):
    # Own both stdlib cache bindings; do not purge another consumer's cache.
    private_re = module_function_view(re, bindings={'_cache': {}, '_cache2': {}})
    seed = view._NATIVE_CLEANUP_PATTERN
    pattern = private_re.compile(seed.pattern, seed.flags)
    assert pattern is not seed
    assert view._cleanup_scan_definitely_empty(['use(buf);'] * 40, 2, pattern)


@pytest.mark.parametrize('padding', ['', '    use(buf);\n' * 40])
def test_actual_missing_cleanup_still_reported(view, padding):
    source = ('int f(){\n' + padding + 'free(buf); return -1;\n'
              'free(buf); return -2;\nreturn 0;\n}\n')
    findings = view.check_cleanup_consistency(source)
    assert len(findings) == 1
    assert findings[0].kind == 'cleanup'
    assert findings[0].line == 4 + padding.count('\n')
    assert '2/3 return paths' in findings[0].description


@pytest.mark.parametrize('body', [
    'returning = 1;\nreturn_count++;',
    'return 1; return 2;',
    '// return in comment\nfree(buf); return 0;',
    'free(buf); return -1;\nfree(buf); return -2;\nreturn 0;',
])
def test_substring_upper_bound_is_conservative(view, body):
    source = _source(body)
    lines = view.split_lines(source)
    assert not view._cleanup_scan_definitely_empty(lines, 2, view._CLEANUP_CALLS)
    # The complete original loop remains available as the comparison path.
    legacy = module_function_view(original, bindings={
        '_cleanup_scan_definitely_empty': lambda *args: False,
    })
    assert view.check_cleanup_consistency(source) == legacy.check_cleanup_consistency(source)


def test_foreign_cleanup_matcher_keeps_every_line_callback(view):
    calls = []

    class Matcher:
        def finditer(self, line):
            calls.append(line)
            return iter(())

    source = _source('done();')
    view._CLEANUP_CALLS = Matcher()
    assert view.check_cleanup_consistency(source) == []
    assert calls == view.split_lines(source)


def test_replaced_return_pattern_keeps_every_search(view):
    calls = []

    class Returns:
        def search(self, line):
            calls.append(line)
            return None

    source = _source('done();')
    view._RETURN_RE = Returns()
    assert view.check_cleanup_consistency(source) == []
    assert calls == view.split_lines(source)


@pytest.mark.parametrize('pattern,error', [(r'free', IndexError), (r'(missing)?free', AttributeError)])
def test_replaced_native_cleanup_pattern_keeps_group_errors(view, pattern, error):
    view._CLEANUP_CALLS = re.compile(pattern)
    with pytest.raises(error):
        view.check_cleanup_consistency(_source('free(buf);'))


@pytest.mark.parametrize('pattern,error', [(r'free', IndexError), (r'(missing)?free', AttributeError)])
def test_import_captured_cleanup_pattern_keeps_group_errors(view, pattern, error):
    # Model a compiler adapter installed before the module captured its seed.
    # Being the original captured object does not establish native semantics.
    view._CLEANUP_CALLS = view._NATIVE_CLEANUP_PATTERN = re.compile(pattern)
    with pytest.raises(error):
        view.check_cleanup_consistency(_source('free(buf);'))


def test_import_captured_return_pattern_keeps_its_language(view):
    view._RETURN_RE = view._NATIVE_RETURN_PATTERN = re.compile(r'RETURN')
    source = _source('free(buf); RETURN -1;\nfree(buf); RETURN -2;\nRETURN 0;')
    findings = view.check_cleanup_consistency(source)
    assert len(findings) == 1
    assert findings[0].kind == 'cleanup'


def test_vocabulary_construction_error_is_not_suppressed(view):
    def broken(*args):
        raise ValueError('owned vocabulary failure')

    view._cleanup_call_re = broken
    with pytest.raises(ValueError, match='owned vocabulary failure'):
        view.check_cleanup_consistency(_source('done();'), domain_model={'owned': True})


def test_foreign_lines_do_not_gain_count_callbacks(view):
    class Line(str):
        def count(self, *args):
            raise AssertionError('new count callback on foreign line')

    view.split_lines = lambda source: [Line('first')] * 40
    assert view.check_cleanup_consistency('owned') == []


@pytest.mark.parametrize('minimum', [0, -1, True, 1.5])
def test_adapted_or_nonpositive_minimum_keeps_legacy_scan(view, minimum):
    assert not view._cleanup_scan_definitely_empty(['done();'] * 40, minimum, view._CLEANUP_CALLS)


def test_malformed_domain_model_keeps_legacy_error(view):
    with pytest.raises(TypeError):
        view.check_cleanup_consistency(_source('done();'), domain_model={'paired_operations': 1})


@pytest.mark.parametrize("binding", ["set", "frozenset", "enumerate"])
def test_replaced_loop_builtin_keeps_legacy_calls(view, binding):
    calls = []
    native = getattr(__import__("builtins"), binding)

    def observe(*args, **kwargs):
        calls.append(args)
        return native(*args, **kwargs)

    setattr(view, binding, observe)
    source = _source("return 0;")
    assert view.check_cleanup_consistency(source) == []
    assert calls


def test_replaced_length_keeps_only_original_calls(view):
    calls = []

    def observe(value):
        calls.append(value)
        return len(value)

    view.len = observe
    assert view.check_cleanup_consistency(_source("done();")) == []
    # The existing minimum-row check and final segment-count check.
    assert len(calls) == 2


def test_line_container_adapter_does_not_gain_length_calls(view):
    calls = []

    class Lines(list):
        def __len__(self):
            calls.append("len")
            return super().__len__()

    view.split_lines = lambda source: Lines(["done();"] * 40)
    assert view.check_cleanup_consistency("owned") == []
    assert calls == ["len"]


def test_native_source_reaches_bound_without_line_counts(view):
    calls = []
    native = view._cleanup_scan_definitely_empty

    def observe(lines, minimum, pattern, source=None):
        calls.append(source)
        return native(lines, minimum, pattern, source)

    view._cleanup_scan_definitely_empty = observe
    source = _source('done();')
    assert view.check_cleanup_consistency(source) == []
    assert calls == [source]


def test_splitter_restoring_native_binding_keeps_returning_rows(view):
    source = _source('done();')
    rows = view.split_lines(_source('free(buf); return -1;\nfree(buf); return -2;\nreturn 0;'))
    native = view.split_lines

    def adapted(text):
        assert text is source
        view.split_lines = native
        return rows

    view.split_lines = adapted
    assert len(view.check_cleanup_consistency(source)) == 1


def test_length_restoring_native_binding_keeps_mutated_rows(view):
    source = _source('done();')
    seen = []

    def adapted(rows):
        seen.append(rows)
        rows.extend(['free(buf); return -1;', 'free(buf); return -2;', 'return 0;'])
        view.len = len
        return len(rows)

    view.len = adapted
    assert len(view.check_cleanup_consistency(source)) == 1
    assert len(seen) == 1


def test_source_adapter_does_not_gain_count_calls(view):
    class Source(str):
        def count(self, *args):
            raise AssertionError('source adapter gained count callback')

    assert view.check_cleanup_consistency(Source(_source('done();'))) == []


@pytest.mark.parametrize('ending', ['\n', '\r\n', '\r', '\u2028'])
@pytest.mark.parametrize('word', ['use(buf);', 'return 0;', 'ret\rurn', '😀return😀'])
def test_source_bound_keeps_line_model_conservative(view, ending, word):
    source = ending.join([word] * 40)
    rows = view.split_lines(source)
    assert source.count('return') >= sum(row.count('return') for row in rows)
    for minimum in (1, 2, 41):
        assert view._cleanup_scan_definitely_empty(rows, minimum, view._CLEANUP_CALLS, source) == (
            view._cleanup_scan_definitely_empty(rows, minimum, view._CLEANUP_CALLS))

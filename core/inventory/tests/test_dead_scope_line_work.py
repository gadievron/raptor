"""Line-coordinate work on accepted lexical views preserves dead ranges.

The lexical helper is held at its consumer seam to test coordinate work;
real grammar admission and conservative refusals live in test_dead_scope.
"""

import pytest

from core.inventory import dead_scope as mod
from core.inventory import lexical_view


def run_view(monkeypatch, language, view):
    monkeypatch.setattr(lexical_view, 'blank_noncode', lambda *args: view)
    if language == 'rust':
        return mod._detect_rust(view)
    if language == 'php':
        return mod._detect_php(view)
    return mod._detect_javascript(language, view)


@pytest.mark.parametrize(('language', 'view'), [
    ('javascript', 'const live = 1;\n' * 3000),
    ('typescript', 'if (false) {\n'),
    ('rust', 'fn live() {}\n' * 3000),
    ('rust', 'if false {\n'),
    ('rust', '#[cfg(any())] struct NotAFunction {}\n'),
    ('rust', '#[cfg(any())] mod bodyless;\nfn live() {}\n'),
], ids=['js-no-guard', 'ts-unclosed', 'rust-no-guard', 'rust-unclosed', 'cfg-struct', 'cfg-bodyless'])
def test_unreported_native_ranges_need_no_line_index(monkeypatch, language, view):
    def unexpected(*args):
        raise AssertionError('no complete range needs coordinates')

    monkeypatch.setattr(mod, '_newline_offsets', unexpected)
    assert run_view(monkeypatch, language, view) == []


@pytest.mark.parametrize(('language', 'view', 'expected'), [
    ('javascript', 'if (false) { if (0) {} }', [(1, 1), (1, 1)]),
    ('rust', 'if false {\nif false {}\n}\n#[cfg(any())]\nfn gated() {}\n', [(1, 3), (2, 2), (4, 5)]),
], ids=['empty-lf-index', 'rust-shared-across-passes'])
def test_admitted_ranges_build_exactly_one_shared_index(monkeypatch, language, view, expected):
    actual = mod._newline_offsets
    seen = []

    def observed(source):
        seen.append(source)
        return actual(source)

    monkeypatch.setattr(mod, '_newline_offsets', observed)
    assert run_view(monkeypatch, language, view) == expected
    assert len(seen) == 1 and seen[0] is view


@pytest.mark.parametrize(('padding', 'count'), [(9000, 32), (9000, 33), (0, 40)],
                         ids=['large-prefix', 'large-prefix-more-ranges', 'small-view'])
def test_php_ranges_need_no_newline_table(monkeypatch, padding, count):
    view = ' \n' * padding + 'if (false) {\n    work();\n}\n' * count

    def unexpected(*args):
        raise AssertionError('PHP line coordinates should not need a newline table')

    monkeypatch.setattr(mod, '_newline_offsets', unexpected)
    expected = [(padding + 3 * i + 1, padding + 3 * i + 3) for i in range(count)]
    assert run_view(monkeypatch, 'php', view) == expected


def test_php_nested_closings_keep_lf_coordinates(monkeypatch):
    prefix = ' \n' * 9000 + 'if (0) {}\n' * 32
    view = prefix + 'if (false) {\n if (null) {\n  /* a\fb\u2028c */\n }\n}\n'
    expected = [(9001 + i, 9001 + i) for i in range(32)] + [(9033, 9037), (9034, 9036)]
    assert run_view(monkeypatch, 'php', view) == expected


def test_php_adapter_retains_full_prefix_count_operations(monkeypatch):
    calls = []

    class View(str):
        def count(self, separator, start=0, end=None):
            calls.append((separator, start, end))
            return super().count(separator, start, end)

    view = View(' \n' * 9000 + 'if (0) {}\n' * 40)

    def unexpected(*args):
        raise AssertionError('adapter should retain its count operations')

    monkeypatch.setattr(mod, '_newline_offsets', unexpected)
    assert run_view(monkeypatch, 'php', view) == [(9001 + i, 9001 + i) for i in range(40)]
    assert len(calls) == 80 and all(separator == '\n' and start == 0 for separator, start, _ in calls)


@pytest.mark.parametrize('language', ['javascript', 'rust'])
def test_adapter_keeps_eager_index_preparation(monkeypatch, language):
    class View(str):
        pass

    view = View('no candidates\n')
    actual = mod._newline_offsets
    seen = []

    def observed(source):
        seen.append(source)
        return actual(source)

    monkeypatch.setattr(mod, '_newline_offsets', observed)
    assert run_view(monkeypatch, language, view) == []
    assert len(seen) == 1 and seen[0] is view


@pytest.mark.parametrize('adapter', [False, True], ids=['native-offset-match', 'adapter-suffix-match'])
def test_rust_cfg_matching_avoids_native_suffix_copies(monkeypatch, adapter):
    class View(str):
        pass

    view = '\n#[cfg(any())]\nfn first() {}\n#[cfg(any())]\nmod bodyless;\nfn live() {}\n'
    if adapter:
        view = View(view)
    actual = mod._RUST_ITEM_AFTER_CFG
    calls = []

    class Pattern:
        def match(self, *args):
            calls.append(args)
            return actual.match(*args)

    monkeypatch.setattr(mod, '_RUST_ITEM_AFTER_CFG', Pattern())
    assert run_view(monkeypatch, 'rust', view) == [(2, 3)]
    starts = [match.end() for match in mod._RUST_DEAD_CFG.finditer(view)]
    if adapter:
        assert calls == [(view[start:],) for start in starts]
    else:
        assert all(args[0] is view for args in calls)
        assert [args[1] for args in calls] == starts


@pytest.mark.parametrize(('tail', 'expected'), [
    ('fn first() { work(); }\nfn next() {}', [(1, 2)]),
    ('mod missing;\nfn live() {}', []),
    ('struct Data {}\nfn live() {}', []),
    ('fn no_body()', []),
    ('pub(crate) async unsafe fn gated() {}', [(1, 2)]),
], ids=['semicolon-in-body', 'bodyless-module', 'non-function', 'no-brace', 'qualified-function'])
def test_rust_cfg_native_offset_search_keeps_item_gates(monkeypatch, tail, expected):
    assert run_view(monkeypatch, 'rust', '#[cfg(any())]\n' + tail) == expected

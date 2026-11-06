"""Scope-name collection shares parsing without weakening claim selection."""

import pytest

from core.audit import defassign, lifetime_witness, refutation


@pytest.fixture
def parser():
    value = defassign._c_parser()
    if value is None:
        pytest.skip('requires tree-sitter C grammar')
    return value


@pytest.mark.parametrize('source,locals_,parameters', [
    pytest.param('int f(int a, char *b){int v; unsigned w=1; return v;}',
                 {'a', 'b', 'v', 'w'}, {'a', 'b'}, id='ordinary'),
    pytest.param('int f(void){return 0;}', set(), set(), id='void'),
    pytest.param('int f(int a){int a; {int b;} return a;}',
                 {'a', 'b'}, {'a'}, id='shadowing'),
    pytest.param('int f(int a){int x, *y, z[3]; return a;}',
                 {'a', 'x', 'y', 'z'}, {'a'}, id='multiple-declarators'),
    pytest.param('int f(int (*cb)(int arg)){int (*local)(int inner); return 0;}',
                 {'cb', 'arg', 'local', 'inner'}, {'cb', 'arg', 'inner'}, id='nested-parameters'),
    pytest.param('int f(int a){int local; return', {'a', 'local'}, {'a'}, id='recovery'),
])
def test_exact_sets(parser, source, locals_, parameters):
    expected = frozenset(locals_), frozenset(parameters)
    assert defassign.function_scope_names(source) == expected
    assert defassign.function_local_names(source) == expected[0]
    assert defassign.function_parameter_names(source) == expected[1]


def test_combined_collection_parses_and_walks_once(monkeypatch, parser):
    parses = []
    walks = []
    original_walk = defassign._walk_nodes

    class CountingParser:
        def parse(self, raw):
            parses.append(raw)
            return parser.parse(raw)

    def walk(root):
        walks.append(root)
        yield from original_walk(root)

    monkeypatch.setattr(defassign, '_c_parser', lambda: CountingParser())
    monkeypatch.setattr(defassign, '_walk_nodes', walk)
    assert defassign.function_scope_names('int f(int p){int x;}') == (
        frozenset({'p', 'x'}), frozenset({'p'}),
    )
    assert len(parses) == len(walks) == 1


@pytest.mark.parametrize('mode', ['unavailable', 'parse-failure', 'encoding-failure'])
def test_failures_keep_empty_sets(monkeypatch, mode):
    class Parser:
        def parse(self, raw):
            raise ValueError('controlled parse failure')
    monkeypatch.setattr(defassign, '_c_parser', lambda: None if mode == 'unavailable' else Parser())
    source = '\ud800' if mode == 'encoding-failure' else 'int f(int p);'
    assert defassign.function_scope_names(source) == (frozenset(), frozenset())
    assert defassign.function_local_names(source) == frozenset()
    assert defassign.function_parameter_names(source) == frozenset()


@pytest.mark.parametrize('mechanism,receipt,expected', [
    pytest.param('x uninitialised', {'description': "Variable 'x'"}, {'x'}, id='local'),
    pytest.param('p uninitialised', {'description': "Variable 'p'"}, set(), id='parameter-only'),
    pytest.param('x uninitialised', {'description': "Variable 'missing'"}, set(), id='unknown-receipt'),
    pytest.param('x uninitialised', None, {'x'}, id='prose-only'),
])
def test_claim_selection_uses_one_combined_collection(monkeypatch, parser, mechanism, receipt, expected):
    sources = []
    original = defassign.function_scope_names

    def collect(source):
        sources.append(source)
        return original(source)

    monkeypatch.setattr(defassign, 'function_scope_names', collect)
    source = 'int f(int p){int x; return x;}'
    assert refutation._uninit_claim_variables(mechanism, receipt, source) == expected
    assert sources == [source]


def test_lifetime_analysis_collects_both_sets_once(monkeypatch, parser, tmp_path):
    source = 'void f(void *p){void *q = p; consume(q);}'
    (tmp_path / 'm.c').write_text(source)
    # Replace caches, preserving inherited objects and contents.
    monkeypatch.setattr(defassign, '_TABLE_CACHE', {})
    monkeypatch.setattr(lifetime_witness, '_LT_TABLE_CACHE', {})
    calls = []
    original = lifetime_witness.function_scope_names

    def collect(text):
        calls.append(text)
        return original(text)

    monkeypatch.setattr(lifetime_witness, 'function_scope_names', collect)
    analysis = lifetime_witness._Analysis(
        source, frozenset({'p'}), target_path=tmp_path, rel_file='m.c',
    )
    assert analysis.locals == frozenset({'p', 'q'})
    assert analysis.params == frozenset({'p'})
    assert calls == [source]

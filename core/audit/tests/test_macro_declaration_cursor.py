"""Declaration collection keeps membership while reusing its destination set."""

from types import SimpleNamespace

import pytest

from core.audit import defassign


@pytest.fixture
def parser():
    value = defassign._c_parser()
    if value is None:
        pytest.skip('requires tree-sitter C grammar')
    return value


def padded(text):
    return '/* padding */\n' * 400 + text


@pytest.mark.parametrize('large', [False, True], ids=['small', 'cursor'])
def test_prototypes_and_definitions_keep_exact_names(parser, large):
    text = 'int declared(int); static int defined(int x) { return x; }'
    if large:
        text = padded(text)
    assert defassign._declared_function_names(text, parser) == {'declared', 'defined'}


@pytest.mark.parametrize('initial', [(), ('keep',)], ids=['empty-destination', 'existing-destination'])
def test_collection_fills_and_returns_owned_destination(parser, initial):
    target = set(initial)
    result = defassign._declared_function_names(padded('int declared(int);'), parser, into=target)
    assert result is target
    assert target == set(initial) | {'declared'}


def test_function_pointer_filtering_is_unchanged(parser):
    text = padded('typedef int (*callback)(int); int (*factory(void))(int);')
    assert defassign._declared_function_names(text, parser) == {'factory'}


def test_recovery_keeps_valid_declarations(parser):
    text = padded('int first(int); int later(int); int bad(')
    assert {'first', 'later'} <= defassign._declared_function_names(text, parser)


def test_cursor_path_does_not_request_root_children(parser):
    class Tree:
        def __init__(self, native):
            self.native = native
        def walk(self):
            return self.native.walk()
        @property
        def root_node(self):
            pytest.fail('cursor collection requested a root-node list traversal')
    class Parser:
        def parse(self, raw):
            return Tree(parser.parse(raw))
    assert defassign._declared_function_names(padded('int declared(int);'), Parser()) == {'declared'}


def test_tree_adapter_without_cursor_keeps_legacy_traversal(parser):
    class Parser:
        def parse(self, raw):
            return SimpleNamespace(root_node=parser.parse(raw).root_node)
    assert defassign._declared_function_names(padded('int declared(int);'), Parser()) == {'declared'}


def test_custom_text_does_not_probe_its_length(parser):
    class Source(str):
        def __len__(self):
            pytest.fail('custom text entered native cursor eligibility checks')
    assert defassign._declared_function_names(Source('int declared(int);'), parser) == {'declared'}


def test_parser_failure_preserves_destination():
    class Parser:
        def parse(self, raw):
            raise ValueError('controlled parse refusal')
    target = {'keep'}
    assert defassign._declared_function_names('int unknown(int);', Parser(), into=target) is target
    assert target == {'keep'}
    assert defassign._declared_function_names('int unknown(int);', Parser()) == set()

"""Bounded argument summaries retain Unicode prefixes and provider seams."""

from types import SimpleNamespace

import pytest

from core.audit import ts_extract as extract
from core.testing.module_views import module_function_view
from core.testing.treesitter import requires_ts


def native_call(argument):
    source = 'function f() { consume(' + argument + '); }'
    tree, lang, src = extract._parse_file('argument.js', source)
    node = next(n for n in extract._walk_descendants(tree.root_node)
                if n.type in extract._CALL_TYPES[lang])
    return node, lang, src


@requires_ts('javascript')
@pytest.mark.parametrize('unit', ['a', 'é', '☃', '😀'])
@pytest.mark.parametrize('size', [0, 1, 58, 59, 60, 61, 239, 240, 241, 1000])
def test_unicode_prefix_matches_existing_character_cap(unit, size):
    argument = '"' + unit * size + '"'
    node, lang, src = native_call(argument)
    assert extract._extract_first_arg(node, lang, src, extract._CALL_TYPES[lang]) == argument[:60]


@requires_ts('javascript')
@pytest.mark.parametrize('pattern', [b'\xff', b'\xf0\x9f\x98\x80', b'\xe2\x82', b'\xed\xa0\x80'])
def test_replacement_decoding_matches_full_slice(pattern):
    node, lang, original = native_call('"' + 'a' * 1000 + '"')
    src = pattern * (len(original) // len(pattern) + 1)
    arg = node.child_by_field_name('arguments').named_children[0]
    expected = src[arg.start_byte:arg.end_byte].decode('utf-8', errors='replace')[:60]
    assert extract._extract_first_arg(node, lang, src, extract._CALL_TYPES[lang]) == expected


@requires_ts('javascript')
def test_replaced_text_helper_remains_authoritative():
    node, lang, src = native_call('"' + 'a' * 1000 + '"')
    calls = []

    def provider(child, data):
        calls.append((child.type, data))
        return 'provider text ' * 20

    view = module_function_view(extract, bindings={'_node_text': provider})
    assert view._extract_first_arg(node, lang, src, extract._CALL_TYPES[lang]) == ('provider text ' * 20)[:60]
    assert calls == [('string', src)]


@requires_ts('javascript')
def test_bytes_subclass_receives_original_full_slice():
    node, lang, original = native_call('"' + 'a' * 1000 + '"')
    slices = []

    class Source(bytes):
        def __getitem__(self, key):
            slices.append(key)
            return super().__getitem__(key)

    src = Source(original)
    arg = node.child_by_field_name('arguments').named_children[0]
    assert extract._extract_first_arg(node, lang, src, extract._CALL_TYPES[lang]) == ('"' + 'a' * 59)
    assert slices == [slice(arg.start_byte, arg.end_byte)]


@requires_ts('javascript')
def test_replaced_length_helper_receives_full_text():
    node, lang, src = native_call('"' + 'a' * 1000 + '"')
    lengths = []

    def length(value):
        lengths.append(len(value))
        return len(value)

    view = module_function_view(extract, bindings={'len': length})
    # The copied text function has the same code and private globals; align
    # only its identity sentinel so this pin exercises the length guard.
    view._FIRST_ARG_NODE_TEXT = view._node_text
    assert view._extract_first_arg(node, lang, src, extract._CALL_TYPES[lang]) == ('"' + 'a' * 59)
    assert lengths == [1002]


def test_foreign_node_keeps_original_span_property_reads():
    reads = []

    class Child:
        type = 'identifier'

        @property
        def start_byte(self):
            reads.append('start')
            return 0

        @property
        def end_byte(self):
            reads.append('end')
            return 1000

    class Call:
        def child_by_field_name(self, name):
            assert name == 'arguments'
            return SimpleNamespace(children=[Child()])

    assert extract._extract_first_arg(Call(), 'c', b'x' * 1000, ()) == 'x' * 60
    assert reads == ['start', 'end']

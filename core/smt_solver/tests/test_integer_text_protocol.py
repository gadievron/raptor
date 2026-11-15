"""Integer model selection uses stored text rather than string protocols."""
import pytest

from core.smt_solver.integer_abi import (
    INTEGER_ABIS, IntegerABI, integer_abi_key, resolve_integer_abi,
)
from core.smt_solver.integer_types import integer_type


def forbidden(*args, **kwargs):
    raise AssertionError('string protocol must not select an integer model')


class Text(str):
    __eq__ = forbidden
    __ne__ = forbidden
    __hash__ = forbidden
    __str__ = forbidden
    __deepcopy__ = forbidden
    split = forbidden


@pytest.mark.parametrize('name', sorted(INTEGER_ABIS))
def test_named_layout_uses_stored_alias(name):
    expected = INTEGER_ABIS[name]
    selected = resolve_integer_abi(Text(name))
    assert selected is expected
    assert integer_type('long', Text(name)).width == expected.long_bits
    assert integer_abi_key(Text(name)) == integer_abi_key(name)


def test_unknown_layout_does_not_dispatch_lookup_protocols():
    assert resolve_integer_abi(Text('unknown')) is None
    assert integer_type('long', Text('unknown')) is None
    assert integer_abi_key(Text('unknown')) == 'unknown'


def test_metadata_records_snapshot_plain_text():
    fields = INTEGER_ABIS['lp64'].record()
    for field in ('name', 'representation', 'source'):
        fields[field] = Text(fields[field])
    selected = resolve_integer_abi(fields)
    assert selected == INTEGER_ABIS['lp64']
    assert all(type(selected.record()[field]) is str
               for field in ('name', 'representation', 'source'))
    assert integer_abi_key(selected) == integer_abi_key('lp64')


@pytest.mark.parametrize('field,value', [
    ('representation', Text('ones-complement')),
    ('source', Text('unsupported')),
    ('name', Text('bad\nname')),
    ('representation', None), ('source', None), ('name', None),
])
def test_invalid_metadata_refuses_without_comparison_protocols(field, value):
    fields = INTEGER_ABIS['lp64'].record()
    fields[field] = value
    with pytest.raises(ValueError):
        IntegerABI(**fields)
    assert resolve_integer_abi(fields) is None
    assert integer_type('long', fields) is None
    assert integer_abi_key(fields) == 'unknown'


@pytest.mark.parametrize('spelling,width,signed', [
    ('long', 64, True), ('unsigned long', 64, False),
    ('short', 16, True), ('unsigned char', 8, False),
])
def test_type_spelling_uses_stored_characters(spelling, width, signed):
    selected = integer_type(Text(spelling), 'lp64')
    assert selected.width == width
    assert selected.signed is signed


@pytest.mark.parametrize('spelling', ['Widget', 'LONG', 'unsigned signed int'])
def test_type_protocol_cannot_supply_builtin_tokens(spelling):
    assert integer_type(Text(spelling), 'lp64') is None

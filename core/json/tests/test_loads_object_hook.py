"""In-memory validation hooks retain size, BOM and default-decoder contracts."""
import math

import pytest

from core.json import utils


@pytest.mark.parametrize('kind', [str, bytes, bytearray], ids=['text', 'bytes', 'bytearray'])
@pytest.mark.parametrize('bom', [False, True], ids=['plain', 'bom'])
def test_object_hook_receives_all_members_after_bom_handling(kind, bom):
    text = ('\ufeff' if bom else '') + '{"a":1,"a":2}'
    data = text if kind is str else kind(text.encode())
    assert utils.loads(data, object_pairs_hook=tuple) == (('a', 1), ('a', 2))


def test_hook_uses_stdlib_instead_of_backend_dispatch(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail('validation hook reached backend dispatch')
    monkeypatch.setattr(utils, '_loads', forbidden)
    assert utils.loads('{"value":1208925819614629174706176}', object_pairs_hook=tuple) == (
        ('value', 2 ** 80),)


@pytest.mark.parametrize('explicit_none', [False, True], ids=['default', 'none'])
def test_default_calls_keep_existing_dispatch(monkeypatch, explicit_none):
    original = utils._loads
    calls = []

    def dispatch(*args, **kwargs):
        calls.append((args, kwargs))
        return original(*args, **kwargs)
    monkeypatch.setattr(utils, '_loads', dispatch)
    options = {'object_pairs_hook': None} if explicit_none else {}
    assert utils.loads('{"value":1}', **options) == {'value': 1}
    assert len(calls) == 1


@pytest.mark.parametrize('kind', [str, bytes, bytearray], ids=['text', 'bytes', 'bytearray'])
def test_size_gate_precedes_hook_and_exact_limit_remains_supported(kind):
    text = '{"value":1}'
    data = text if kind is str else kind(text.encode())

    def forbidden(_pairs):
        pytest.fail('over-budget input reached object hook')
    with pytest.raises(utils.JsonBudgetExceededError):
        utils.loads(data, max_bytes=len(data) - 1, object_pairs_hook=forbidden)
    assert utils.loads(data, max_bytes=len(data), object_pairs_hook=tuple) == (('value', 1),)


@pytest.mark.parametrize('value', ['NaN', 'Infinity', '-Infinity'])
def test_nonfinite_constant_policy_is_preserved_with_hook(value):
    text = '{"value":' + value + '}'
    with pytest.raises(ValueError):
        utils.loads(text, object_pairs_hook=tuple)
    result = utils.loads(text, allow_non_finite=True, object_pairs_hook=tuple)
    assert result[0][0] == 'value'
    assert not math.isfinite(result[0][1])


def test_callback_failure_is_not_hidden():
    error = ValueError('owned validation failure')

    def refuse(_pairs):
        raise error
    with pytest.raises(ValueError) as caught:
        utils.loads('{"value":1}', object_pairs_hook=refuse)
    assert caught.value is error


def test_nested_objects_each_receive_the_hook():
    value = utils.loads('{"first":{"value":1},"second":{"value":2}}', object_pairs_hook=tuple)
    assert value == (('first', (('value', 1),)), ('second', (('value', 2),)))

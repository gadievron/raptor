"""Witness objectives come from stored input, not subclass protocols."""
import pytest

from core.smt_solver.witness_preferences import parse_witness_preference as parse
from packages.exploit_feasibility import smt_path as path


def forbidden(*args, **kwargs):
    raise AssertionError('protocol must not replace a witness objective')


class Text(str):
    __eq__ = forbidden
    __contains__ = forbidden
    __str__ = forbidden
    __repr__ = forbidden
    partition = forbidden
    strip = forbidden
    lower = forbidden


class Pair(tuple):
    __len__ = forbidden
    __iter__ = forbidden
    __getitem__ = forbidden
    __repr__ = forbidden


class Stopped(Exception):
    pass


@pytest.mark.parametrize('spec', [
    Text('max:Count'), Pair(('Count', 'max')),
    Pair((Text(' Count '), Text(' MAX '))),
], ids=['string', 'tuple', 'tuple-fields'])
def test_public_objective_preserves_stored_name_and_direction(monkeypatch, spec):
    objectives = []

    def check(*args, **kwargs):
        objectives.append(kwargs['prefer_witness'])
        raise Stopped()

    monkeypatch.setattr(path, 'check_path_feasibility', check)
    with pytest.raises(Stopped):
        path.validate_path(['Count <= 255'], profile='uint8', prefer_witness=spec)
    assert objectives == [('Count', 'max')]
    assert all(type(field) is str for field in objectives[0])


@pytest.mark.parametrize('spec', [Pair(()), Pair(('Count',)), Pair(('Count', 'max', 'extra'))],
                         ids=['empty', 'one', 'three'])
def test_tuple_shape_refuses_without_length_iteration_or_repr(spec):
    with pytest.raises(ValueError, match='tuple must be'):
        parse(spec)


@pytest.mark.parametrize('spec', [Text(''), None], ids=['empty', 'none'])
def test_empty_preference_retains_no_objective(spec):
    assert parse(spec) is None


@pytest.mark.parametrize('spec', [
    Text('sideways:Count'), Text('max:'), Pair((Text('Count'), Text('sideways'))),
], ids=['direction-string', 'empty-name', 'direction-tuple'])
def test_invalid_stored_fields_cannot_supply_a_valid_objective(spec):
    with pytest.raises(ValueError):
        parse(spec)


def test_normalization_keeps_case_sensitive_variable_identity():
    assert parse(Text(' MIN : Count ')) == ('Count', 'min')
    assert parse(Pair((Text(' count '), Text(' MAX ')))) == ('count', 'max')

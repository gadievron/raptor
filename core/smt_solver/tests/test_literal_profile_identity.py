"""Literal range checking and construction require one immutable profile."""
from types import SimpleNamespace

import pytest

from core.smt_solver import path_feasibility as pf
from core.smt_solver.config import BVProfile
from core.smt_solver.rejection import Rejection, parse_literal_value


class Derived(BVProfile):
    pass


class Changing(BVProfile):
    def __post_init__(self):
        object.__setattr__(self, '_reads', 0)

    def __getattribute__(self, name):
        if name == 'width':
            reads = object.__getattribute__(self, '_reads')
            object.__setattr__(self, '_reads', reads + 1)
            return 9 if reads == 0 else 8
        return object.__getattribute__(self, name)


@pytest.mark.parametrize('profile', [
    Derived(8, False), Changing(8, False),
    SimpleNamespace(width=8, signed=False), None,
])
def test_literal_profile_refuses_before_protocol_or_construction(monkeypatch, profile):
    emitted = []
    monkeypatch.setattr(pf, '_mk_val', lambda value, width: emitted.append((value, width)))
    with pytest.raises(ValueError, match='profile'):
        parse_literal_value('256', profile)
    with pytest.raises(ValueError, match='profile'):
        pf.make_val('256', profile=profile)
    assert emitted == []
    if type(profile) is Changing:
        assert object.__getattribute__(profile, '_reads') == 0


@pytest.mark.parametrize('literal,signed,expected', [
    ('255', False, 255), ('127', True, 127), ('-128', True, -128),
    ('0xff', False, 255), ('0xff', True, 255),
])
def test_base_profile_literal_pattern_and_width_are_preserved(monkeypatch, literal, signed, expected):
    profile = BVProfile(8, signed)
    emitted = []
    monkeypatch.setattr(pf, '_mk_val', lambda value, width: emitted.append((value, width)))
    assert parse_literal_value(literal, profile) == expected
    pf.make_val(literal, profile=profile)
    assert emitted == [(expected, 8)]


@pytest.mark.parametrize('literal,signed', [('256', False), ('128', True), ('-129', True)])
def test_base_profile_out_of_range_still_refuses(monkeypatch, literal, signed):
    emitted = []
    monkeypatch.setattr(pf, '_mk_val', lambda value, width: emitted.append((value, width)))
    profile = BVProfile(8, signed)
    assert isinstance(parse_literal_value(literal, profile), Rejection)
    with pytest.raises(ValueError, match='rejected'):
        pf.make_val(literal, profile=profile)
    assert emitted == []

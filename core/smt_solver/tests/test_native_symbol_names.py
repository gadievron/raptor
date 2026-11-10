"""Native string termination must not merge distinct accepted symbols."""

import pytest

z3 = pytest.importorskip('z3')

from core.smt_solver import BVProfile, mk_var  # noqa: E402
from core.smt_solver import path_feasibility as paths  # noqa: E402


@pytest.mark.parametrize('name', ['Value\x00Other', '\x00Value', 'Value\x00'], ids=['middle', 'leading', 'trailing'])
def test_embedded_nul_is_rejected_before_native_symbol_creation(name):
    with pytest.raises(ValueError, match='NUL'):
        mk_var(name, 8)


@pytest.mark.parametrize('binding', [None, z3.BitVec('Existing', 8)])
def test_invalid_registry_name_declines_before_query_or_mutation(monkeypatch, binding):
    name = 'Value\x00Other'
    registry = {name: binding}
    monkeypatch.setattr(paths, '_new_solver', lambda *a, **kw: pytest.fail('invalid name reached query'))
    with pytest.raises(ValueError, match='NUL'):
        paths.check_verb_feasibility([], [], registry, profile=BVProfile(8))
    assert list(registry) == [name] and registry[name] is binding
    with pytest.raises(ValueError, match='NUL'):
        paths.make_var(name, registry, profile=BVProfile(8))
    assert registry[name] is binding


def test_valid_non_identifier_names_keep_distinct_native_identity():
    names = ['Value', 'value', 'Value.Other', 'Value Other', 'Value\u03a9']
    variables = [mk_var(name, 8) for name in names]
    assert [str(value.decl().name()) for value in variables] == names
    assert all(not z3.eq(a, b) for i, a in enumerate(variables) for b in variables[i + 1:])
    registry = {}
    value = paths.make_var('Value.Other', registry, profile=BVProfile(8))
    assert paths.make_var('Value.Other', registry, profile=BVProfile(8)) is value

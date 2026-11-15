"""Registry validation traverses stored bindings, not virtual item views."""
from types import SimpleNamespace

import pytest

from core.smt_solver.config import BVProfile
from core.smt_solver import path_feasibility as pf


class Hidden(dict):
    def items(self):
        return []


class Trap(dict):
    def __bool__(self):
        return False

    def __len__(self):
        return 0

    def items(self):
        raise AssertionError('virtual items must not replace stored bindings')


@pytest.mark.parametrize('cls', [Hidden, Trap])
@pytest.mark.parametrize('name,error', [('NULL', 'NULL'), ('Value\x00Other', 'NUL')])
def test_invalid_stored_binding_cannot_hide_in_an_item_view(cls, name, error):
    registry = cls({'Count': None, name: None})
    with pytest.raises(ValueError, match=error):
        pf._validate_var_registry(registry, BVProfile(8), context=object())
    assert dict.copy(registry) == {'Count': None, name: None}


def test_virtual_invalid_binding_does_not_replace_a_valid_store():
    class Injected(dict):
        def items(self):
            return [('NULL', None)]

    registry = Injected({'Count': None})
    assert pf._validate_var_registry(registry, BVProfile(8), context=object()) is None
    assert dict.copy(registry) == {'Count': None}


def test_nonempty_lazy_subclass_keeps_default_context_acquisition(monkeypatch):
    seen, context = [], object()

    def current():
        seen.append(context)
        return context

    monkeypatch.setattr(pf, 'z3', SimpleNamespace(main_ctx=current))
    registry = Trap({'Count': None})
    assert pf._validate_var_registry(registry, BVProfile(8)) is None
    assert seen == [context]
    assert dict.copy(registry) == {'Count': None}


def test_empty_stored_registry_still_needs_no_backend(monkeypatch):
    monkeypatch.setattr(pf, 'z3', None)
    assert pf._validate_var_registry(Trap(), BVProfile(8)) is None

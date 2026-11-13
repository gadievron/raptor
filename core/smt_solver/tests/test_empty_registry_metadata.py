"""An empty binding registry needs no native default context."""

from types import SimpleNamespace

import pytest

from core.smt_solver import BVProfile
from core.smt_solver import path_feasibility as paths


@pytest.fixture
def forbid_default_context(monkeypatch):
    def forbidden():
        raise AssertionError("metadata-only validation requested a native context")
    monkeypatch.setattr(paths, "z3", SimpleNamespace(main_ctx=forbidden))


def test_empty_registry_is_a_noop_before_default_context(forbid_default_context):
    registry = {}
    assert paths._validate_var_registry(registry, BVProfile(8)) is None
    assert registry == {}


def test_empty_registry_is_a_noop_without_backend(monkeypatch):
    monkeypatch.setattr(paths, "z3", None)
    assert paths._validate_var_registry({}, BVProfile(8)) is None


@pytest.mark.parametrize("registry", [None, [], ()])
def test_invalid_container_still_refuses_before_context(registry, forbid_default_context):
    with pytest.raises(ValueError, match="mutable dictionary"):
        paths._validate_var_registry(registry, BVProfile(8))


def test_nonempty_lazy_registry_keeps_existing_context_acquisition(monkeypatch):
    seen, context = [], object()
    def current():
        seen.append(context)
        return context
    monkeypatch.setattr(paths, "z3", SimpleNamespace(main_ctx=current))
    registry = {"Value": None}
    assert paths._validate_var_registry(registry, BVProfile(8)) is None
    assert seen == [context]
    assert registry == {"Value": None}


@pytest.mark.parametrize("name", ["NULL", "Value\x00Other"])
def test_false_looking_nonempty_dictionary_cannot_hide_invalid_bindings(name, forbid_default_context):
    class FalseLookingRegistry(dict):
        def __bool__(self):
            return False
    registry = FalseLookingRegistry({name: None})
    with pytest.raises(ValueError, match="NULL|NUL"):
        paths._validate_var_registry(registry, BVProfile(8), context=object())
    assert list(registry) == [name] and registry[name] is None

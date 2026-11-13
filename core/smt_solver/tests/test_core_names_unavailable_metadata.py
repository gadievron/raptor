"""Core-name diagnostics fail closed without requiring native proof state."""

from types import SimpleNamespace

import pytest

from core.smt_solver import explain


@pytest.fixture
def missing_backend(monkeypatch):
    monkeypatch.setattr(explain, "z3", None)
    monkeypatch.setattr(explain, "Z3_ERRORS", ())


def test_absent_solver_has_no_nameable_core_when_backend_is_missing(missing_backend):
    assert explain.core_names(None, {"marker": "condition"}) == []


def test_wrong_solver_shape_keeps_existing_attribute_error_fallback(missing_backend):
    assert explain.core_names(object(), {}) == []


def test_existing_python_label_projection_is_independent_of_backend(missing_backend):
    # Supplied labels exercise projection only, not a solver verdict/core proof.
    labels = ["first", "foreign", "last"]
    supplied = SimpleNamespace(unsat_core=lambda: labels)
    reverse = {"first": "same display", "last": "same display"}
    assert explain.core_names(supplied, reverse) == ["same display", "same display"]
    assert labels == ["first", "foreign", "last"]
    assert reverse == {"first": "same display", "last": "same display"}


def test_non_core_programming_error_is_not_silenced(missing_backend):
    def broken():
        raise TypeError("bad caller contract")
    with pytest.raises(TypeError, match="bad caller contract"):
        explain.core_names(SimpleNamespace(unsat_core=broken), {})


def test_shared_binding_exception_classes_keep_the_existing_fallback(monkeypatch):
    class BindingError(Exception):
        pass

    def unavailable():
        raise BindingError("core unavailable")

    monkeypatch.setattr(explain, "Z3_ERRORS", (BindingError,))
    assert explain.core_names(SimpleNamespace(unsat_core=unavailable), {}) == []

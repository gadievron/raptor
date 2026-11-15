"""Witness names resolve signedness by stored text, without key protocols."""
import json
from types import MappingProxyType, SimpleNamespace

import pytest

from core.smt_solver import witness as w


class Name(str):
    def __hash__(self):
        return hash('Value')

    def __eq__(self, other):
        return other == 'Value'


class Separate(str):
    def __hash__(self):
        return hash('Other')

    def __eq__(self, other):
        return False


@pytest.fixture
def model_seam(monkeypatch):
    context = object()
    events = []
    expression = SimpleNamespace(ctx=context)

    class Value:
        def as_long(self):
            return 255

        def size(self):
            return 8

    class Model:
        ctx = context

        def translate(self, target):
            events.append('completion')
            assert target is context
            return self

        def eval(self, term, model_completion):
            events.append('evaluation')
            assert term is expression
            assert term.ctx is context
            return Value()

    monkeypatch.setattr(w, 'z3', SimpleNamespace(ModelRef=Model, is_bv_value=lambda value: True))
    monkeypatch.setattr(w, 'require_bv', lambda *args, **kwargs: None)
    return Model(), expression, events


def test_signedness_map_uses_stored_key():
    context = w._signedness_context({Name('Other'): True})
    assert all(type(name) is str for name in context)
    assert w.bv_to_int(255, 8, w._resolve_signedness('Value', context)) == 255
    assert w.bv_to_int(255, 8, w._resolve_signedness('Other', context)) == -1


def test_registry_name_keeps_output_and_signedness_identity(model_seam):
    model, expression, events = model_seam
    result = w.format_vars(model, {Name('Other'): expression}, {'Value': True})
    assert json.loads(json.dumps(result)) == {'Other': 255}
    assert all(type(name) is str for name in result)
    assert events == ['evaluation']


def test_duplicate_signedness_names_refuse():
    flags = {'Value': False, Separate('Value'): True}
    with pytest.raises(ValueError, match='duplicate signedness'):
        w._signedness_context(flags)


def test_duplicate_registry_names_refuse_before_completion(model_seam):
    model, expression, events = model_seam
    registry = {'Value': expression, Separate('Value'): expression}
    with pytest.raises(ValueError, match='duplicate variable registry'):
        w.format_vars(model, registry, False, completion=True)
    assert events == []


def test_name_case_and_completion_behavior_remain_distinct(model_seam):
    model, expression, events = model_seam
    result = w.format_vars(model, {'Value': expression, 'value': expression},
                           {'Value': True}, completion=True)
    assert result == {'Value': -1, 'value': 255}
    assert events == ['completion', 'evaluation', 'evaluation']


def test_mapping_views_keep_expression_identity_and_signedness(model_seam):
    model, expression, events = model_seam
    registry = MappingProxyType({'Value': expression})
    flags = MappingProxyType({'Value': True})
    assert w.format_vars(model, registry, flags) == {'Value': -1}
    assert events == ['evaluation']

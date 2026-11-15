"""ABI model values cannot override their arithmetic or proof identity."""
import pytest

from core.smt_solver.integer_abi import (
    INTEGER_ABIS, IntegerABI, integer_abi_key, integer_abi_record, resolve_integer_abi,
)
from core.smt_solver.integer_types import integer_type


def forbidden(*args, **kwargs):
    raise AssertionError('unsupported ABI instance must not dispatch')


class Derived(IntegerABI):
    pass


class ClaimedRecord(IntegerABI):
    record = forbidden


class Unvalidated(IntegerABI):
    def __post_init__(self):
        pass


class DynamicFields(Unvalidated):
    def __getattribute__(self, name):
        if name in {'name', 'char_bits', 'short_bits', 'int_bits', 'long_bits',
                    'long_long_bits', 'representation', 'source'}:
            forbidden()
        return object.__getattribute__(self, name)


@pytest.mark.parametrize('cls', [Derived, ClaimedRecord, Unvalidated, DynamicFields])
def test_abi_subclass_cannot_supply_a_model_or_cache_context(cls):
    value = cls(**INTEGER_ABIS['llp64'].record())
    assert resolve_integer_abi(value) is None
    assert integer_abi_record(value) is None
    assert integer_type('long', value) is None
    assert integer_abi_key(value) == 'unknown'
    assert integer_abi_key(value) != integer_abi_key('lp64')


def test_skipped_validation_does_not_admit_unsupported_layout():
    value = Unvalidated('invalid', 8, 8, 16, 32, 64, 'ones-complement')
    assert resolve_integer_abi(value) is None
    assert integer_type('short', value) is None


@pytest.mark.parametrize('name', sorted(INTEGER_ABIS))
def test_base_models_and_declared_records_remain_supported(name):
    value = INTEGER_ABIS[name]
    assert resolve_integer_abi(value) is value
    assert resolve_integer_abi(name) is value
    assert resolve_integer_abi(value.record()) == value
    assert integer_abi_key(value) == integer_abi_key(value.record())
    assert integer_type('long', value).width == value.long_bits


@pytest.mark.parametrize('runner_name', ['_run_smt_verb_inner', '_smt_verb_in_subprocess'])
def test_subclass_refuses_before_source_or_solver_work(monkeypatch, runner_name):
    from core.audit import sweep

    monkeypatch.setattr('core.audit.probe_function_scope.source_for_function', forbidden)
    monkeypatch.setattr(sweep, '_verb_vocab', forbidden)
    monkeypatch.setattr(sweep, '_run_smt_verb_on_source', forbidden)
    monkeypatch.setattr('core.audit.subproc_json.run_json_child', forbidden)
    value = ClaimedRecord(**INTEGER_ABIS['llp64'].record())
    result = getattr(sweep, runner_name)(
        file_path='record.c', function_name='Read', verb='check-overflow',
        source='long Read(long a) { return a; }', hypothesis='overflow in a',
        integer_abi=value,
    )
    assert result.outcome == 'inconclusive'
    assert result.details['integer_abi_status'] == 'unavailable'

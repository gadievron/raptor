"""Incomplete syntax and unbound calls cannot manufacture conclusive proofs."""

import pytest

from core.smt_solver import BV_C_UINT32, BV_C_INT32, z3_available
from packages.hypothesis_validation.adapters.smt import SMTAdapter


@pytest.mark.parametrize('rule', ['!', 'Value == 0\n!', 'Value == 0\nValue != 0\n!'])
def test_empty_negated_condition_declines_the_entire_query(tmp_path, monkeypatch, rule):
    import packages.hypothesis_validation.adapters.smt as adapter
    monkeypatch.setattr(SMTAdapter, 'is_available', lambda self: True)
    monkeypatch.setattr(adapter, 'check_path_feasibility_dual', lambda *a, **kw: pytest.fail('invalid syntax solved'))
    result = SMTAdapter().run(rule, tmp_path)
    assert result.success is False and result.empty_matches_conclusive is False
    assert 'negation requires a condition' in result.error
    assert not result.matches


@pytest.mark.skipif(not z3_available(), reason='Z3 unavailable')
@pytest.mark.parametrize('profile', [None, BV_C_UINT32, BV_C_INT32], ids=['guessed', 'unsigned', 'signed'])
@pytest.mark.parametrize('rule', ['min(0, 4) > 4', 'fetch_width() > 0xffffffffffffffff'])
def test_unbound_calls_cannot_provide_a_conclusive_refutation(tmp_path, monkeypatch, profile, rule):
    from core.smt_solver import path_feasibility
    monkeypatch.setattr(path_feasibility, '_summarise_call', lambda *a, **kw: pytest.fail('unbound summary built'))
    result = SMTAdapter(bv_profile=profile).run(rule, tmp_path)
    # The narrower pinned profile may reject the literal itself; either
    # outcome must remain non-conclusive about a source-level call.
    assert result.empty_matches_conclusive is False
    if not result.success:
        assert 'unbound' in result.error or 'partial' in result.error or 'indeterminate' in result.error


@pytest.mark.skipif(not z3_available(), reason='Z3 unavailable')
@pytest.mark.parametrize('profile', [None, BV_C_UINT32], ids=['guessed', 'pinned'])
def test_independent_scalar_core_remains_usable_with_an_opaque_call(tmp_path, profile):
    result = SMTAdapter(bv_profile=profile).run('Value == 0\nValue != 0\nfetch_width() >= 0', tmp_path)
    assert result.success is True and result.empty_matches_conclusive is True
    assert 'unsat' in result.summary


@pytest.mark.skipif(not z3_available(), reason='Z3 unavailable')
def test_arbitrary_opaque_return_value_is_not_a_verified_execution(tmp_path):
    result = SMTAdapter().run('next_value() == 7', tmp_path)
    assert result.success is False and result.empty_matches_conclusive is False
    assert result.matches == [] and 'unbound call results' in result.error


@pytest.mark.skipif(not z3_available(), reason='Z3 unavailable')
def test_zero_adapter_timeout_is_immediate_inconclusive_not_unlimited(tmp_path):
    result = SMTAdapter().run('Value == 0\nValue != 0', tmp_path, timeout=0)
    assert result.success is False and result.empty_matches_conclusive is False
    assert 'budget exhausted' in result.error


@pytest.mark.parametrize('timeout', [True, -1, '5', 0.5, None])
def test_adapter_timeout_is_not_coerced(tmp_path, timeout):
    result = SMTAdapter().run('Value == 7', tmp_path, timeout=timeout)
    assert result.success is False and 'nonnegative integer' in result.error

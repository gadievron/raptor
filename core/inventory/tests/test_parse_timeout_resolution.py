"""Positive parse budgets must not round down to native timeout opt-out."""

import warnings

import pytest

from core.inventory import _ts_cache

ts = pytest.importorskip('tree_sitter')


def _timeout(parser):
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        return parser.timeout_micros


@pytest.mark.parametrize('seconds', [5e-324, 1e-9, 0.999e-6])
def test_positive_submicrosecond_budget_remains_bounded(seconds):
    parser = _ts_cache.BoundedParser(ts.Parser(), budget_s=seconds)
    assert _timeout(parser) == 1


@pytest.mark.parametrize('seconds, micros', [
    (0.0, 0), (-0.1, 0), (1e-6, 1), (0.25, 250000), (20.0, 20000000),
])
def test_existing_budget_resolution_and_opt_out_remain(seconds, micros):
    parser = _ts_cache.BoundedParser(ts.Parser(), budget_s=seconds)
    assert _timeout(parser) == micros


def test_environment_resync_keeps_small_positive_budget_bounded(monkeypatch):
    monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', '1e-9')
    parser = _ts_cache.BoundedParser(ts.Parser())
    assert _timeout(parser) == 1
    monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', '0')
    assert parser._sync_budget() == 0
    assert _timeout(parser) == 0
    monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', '1e-9')
    assert parser._sync_budget() == 1e-9
    assert _timeout(parser) == 1

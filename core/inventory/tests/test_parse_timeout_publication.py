"""Rejected timeout updates must not be cached as installed native state."""

import warnings

import pytest

from core.inventory import _ts_cache

ts = pytest.importorskip('tree_sitter')


@pytest.mark.parametrize('initial', [0.0, 0.25])
def test_rejected_timeout_is_not_published(monkeypatch, initial):
    monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', str(initial))
    native = ts.Parser()
    parser = _ts_cache.BoundedParser(native)
    monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', '1e308')
    with warnings.catch_warnings():
        warnings.simplefilter('ignore', DeprecationWarning)
        for _ in range(2):
            with pytest.raises(OverflowError):
                parser._sync_budget()
            assert native.timeout_micros == int(initial * 1000000)
        monkeypatch.setenv('RAPTOR_TS_PARSE_BUDGET_S', '0.5')
        assert parser._sync_budget() == 0.5
        assert native.timeout_micros == 500000

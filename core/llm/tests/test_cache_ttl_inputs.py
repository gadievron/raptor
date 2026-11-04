"""Invalid environment values must not silently disable response expiry."""

import pytest
from core.llm.config import _default_cache_ttl


@pytest.mark.parametrize("raw", ["nan", "NaN", "inf", "-inf", "Infinity", "1e309"])
def test_nonfinite_ttl_uses_documented_default(monkeypatch, raw):
    monkeypatch.setenv("RAPTOR_LLM_CACHE_TTL_S", raw)
    assert _default_cache_ttl() == 86400.0


@pytest.mark.parametrize("raw", ["none", "off", "0", "-1"])
def test_explicit_expiry_opt_out_still_works(monkeypatch, raw):
    monkeypatch.setenv("RAPTOR_LLM_CACHE_TTL_S", raw)
    assert _default_cache_ttl() is None

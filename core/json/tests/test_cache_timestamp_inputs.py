"""Cache stamps must remain finite after parsing strings or exponent syntax."""

import pytest
from core.json import JsonCache, TTL_FOREVER


@pytest.mark.parametrize(
    "written", ['"nan"', '"inf"', '"-inf"', '"Infinity"', '"1e999"', "1e999", "-1e999"]
)
@pytest.mark.parametrize("ttl", [60, TTL_FOREVER])
def test_nonfinite_timestamp_is_a_cache_miss(tmp_path, written, ttl):
    cache = JsonCache(root=tmp_path)
    path = tmp_path / "entry.json"
    path.write_text(
        '{"written_at": '
        + written
        + ', "ttl_seconds": '
        + str(ttl)
        + ', "value": "untrustworthy"}'
    )
    assert cache.get("entry", ttl_seconds=ttl) is None


def test_legacy_finite_timestamp_string_still_works(tmp_path):
    import time

    cache = JsonCache(root=tmp_path)
    (tmp_path / "entry.json").write_text(
        '{"written_at": "'
        + str(time.time())
        + '", "ttl_seconds": 60, "value": "cached"}'
    )
    assert cache.get("entry", ttl_seconds=60) == "cached"

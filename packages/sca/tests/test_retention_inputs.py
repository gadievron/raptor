"""Reject invalid cache-GC bounds before taking locks or deleting data."""

import pytest
from packages.sca.cache_budget import prune_cache


@pytest.mark.parametrize(
    "name",
    ["max_age_days", "stress_max_age_days", "max_bytes", "stress_max_bytes", "now"],
)
@pytest.mark.parametrize("value", [float("nan"), float("inf"), -float("inf")])
@pytest.mark.parametrize("existing", [False, True])
def test_nonfinite_bound_is_rejected_without_filesystem_changes(
    tmp_path, name, value, existing
):
    root = tmp_path / "cache"
    entry = root / "entry.json"
    if existing:
        root.mkdir()
        entry.write_text("cached data")
    with pytest.raises(ValueError):
        prune_cache(root, **{name: value})
    assert root.exists() is existing
    if existing:
        assert entry.read_text() == "cached data"
        assert list(root.iterdir()) == [entry]


@pytest.mark.parametrize("name", ["max_age_days", "stress_max_age_days"])
def test_age_conversion_overflow_is_rejected(tmp_path, name):
    with pytest.raises(ValueError):
        prune_cache(tmp_path, **{name: 1e308})
    assert list(tmp_path.iterdir()) == []

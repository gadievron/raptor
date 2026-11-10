"""Optional encoder refusals preserve native cache state and retryability."""
import pytest

from core.json import cache as cache_module
from core.json.cache import JsonCache
from core.testing.module_bindings import patch_module_attribute


def test_encoder_recursion_refusal_preserves_existing_entry_and_retry(tmp_path, monkeypatch):
    cache = JsonCache(root=tmp_path)
    cache.put("entry", {"version": 1}, ttl_seconds=60)
    assert cache.try_get("entry", ttl_seconds=60) == {"version": 1}
    before = {path.name: path.read_bytes() for path in tmp_path.iterdir()}
    attempted = []

    def refuse(value, **kwargs):
        attempted.append(value)
        raise RecursionError("controlled encoder refusal")

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, cache_module, "json", "dumps", refuse)
        cache.put("entry", {"version": 2}, ttl_seconds=60)
    assert len(attempted) == 1 and attempted[0]["value"] == {"version": 2}
    assert {path.name: path.read_bytes() for path in tmp_path.iterdir()} == before
    assert cache.try_get("entry", ttl_seconds=60) == {"version": 1}
    cache.put("entry", {"version": 3}, ttl_seconds=60)
    assert cache.try_get("entry", ttl_seconds=60) == {"version": 3}
    assert (tmp_path / "entry.json").read_bytes() != before["entry.json"]


@pytest.mark.parametrize("failure", [KeyboardInterrupt, SystemExit])
def test_encoder_cancellation_propagates_without_replacing_entry(tmp_path, monkeypatch, failure):
    cache = JsonCache(root=tmp_path)
    cache.put("entry", "previous", ttl_seconds=60)
    before = (tmp_path / "entry.json").read_bytes()
    cancellation = failure("cancelled")

    def refuse(*args, **kwargs):
        raise cancellation

    with monkeypatch.context() as fault:
        patch_module_attribute(fault, cache_module, "json", "dumps", refuse)
        with pytest.raises(failure) as caught:
            cache.put("entry", "replacement", ttl_seconds=60)
    assert caught.value is cancellation
    assert (tmp_path / "entry.json").read_bytes() == before
    assert cache.try_get("entry", ttl_seconds=60) == "previous"

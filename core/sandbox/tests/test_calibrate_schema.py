"""Corrupt calibration cache fields must fail before reaching consumers."""

import json
from unittest.mock import Mock

import pytest

from core.sandbox import calibrate as cal


def profile_dict():
    return {
        "binary_path": "/tool", "binary_sha256": "hash",
        "env_signature": "env", "captured_at": "timestamp",
        "probe_args": ["--version"], "paths_read": ["/config"],
        "paths_written": [], "paths_stat": [],
        "proxy_hosts": ["example.test"],
        "connect_targets": [{"ip": "127.0.0.1", "port": 443, "family": "AF_INET"}],
        "cache_version": cal._CACHE_VERSION,
    }


@pytest.mark.parametrize("field", [
    "binary_path", "binary_sha256", "env_signature", "captured_at",
])
@pytest.mark.parametrize("value", [None, 42, [], {}])
def test_identity_fields_require_strings(field, value):
    profile = profile_dict()
    profile[field] = value
    with pytest.raises(TypeError):
        cal.SandboxProfile.from_json(json.dumps(profile))


@pytest.mark.parametrize("field", [
    "probe_args", "paths_read", "paths_written", "paths_stat", "proxy_hosts",
])
@pytest.mark.parametrize("value", ["example.test", {}, None, [42], [None]])
def test_collection_fields_require_string_lists(field, value):
    profile = profile_dict()
    profile[field] = value
    with pytest.raises(TypeError):
        cal.SandboxProfile.from_json(json.dumps(profile))


@pytest.mark.parametrize("value", [True, None, "1", 1.0])
def test_schema_version_requires_an_integer(value):
    profile = profile_dict()
    profile["cache_version"] = value
    with pytest.raises(TypeError):
        cal.SandboxProfile.from_json(json.dumps(profile))


@pytest.mark.parametrize("value", [
    None, {}, "target", [None], ["target"],
    [{"ip": [], "port": 443, "family": "AF_INET"}],
    [{"ip": "127.0.0.1", "port": True, "family": "AF_INET"}],
    [{"ip": "127.0.0.1", "port": "443", "family": "AF_INET"}],
    [{"ip": "127.0.0.1", "port": 443, "family": []}],
])
def test_connection_fields_are_validated(value):
    profile = profile_dict()
    profile["connect_targets"] = value
    with pytest.raises(TypeError):
        cal.SandboxProfile.from_json(json.dumps(profile))


def test_missing_optional_fields_preserve_defaults():
    profile = profile_dict()
    required = {field: profile[field] for field in (
        "binary_path", "binary_sha256", "env_signature", "captured_at",
    )}
    loaded = cal.SandboxProfile.from_json(json.dumps(required))
    assert loaded.proxy_hosts == []
    assert loaded.connect_targets == []
    assert loaded.cache_version == cal._CACHE_VERSION


def test_corrupt_field_is_a_cache_miss(tmp_path, monkeypatch):
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path)
    path = cal._cache_path_for("fingerprint")
    profile = profile_dict()
    profile["proxy_hosts"] = "example.test"
    path.write_text(json.dumps(profile))
    assert cal._load_from_cache("fingerprint") is None


def test_decoder_recursion_failure_is_a_cache_miss(tmp_path, monkeypatch):
    monkeypatch.setattr(cal, "_CACHE_DIR", tmp_path)
    cal._cache_path_for("fingerprint").write_text("{}")
    monkeypatch.setattr(cal.json, "loads", Mock(side_effect=RecursionError("deep JSON")))
    assert cal._load_from_cache("fingerprint") is None


def test_cache_clear_skips_recursion_failure(tmp_path, monkeypatch):
    binary = tmp_path / "tool"
    binary.write_bytes(b"tool")
    cache = tmp_path / "cache"
    cache.mkdir()
    entry = cache / "broken.json"
    entry.write_text("{}")
    monkeypatch.setattr(cal, "_CACHE_DIR", cache)
    monkeypatch.setattr(cal.json, "loads", Mock(side_effect=RecursionError("deep JSON")))
    assert cal.clear_cache(binary) == 0
    assert entry.exists()

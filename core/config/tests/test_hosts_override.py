"""Contract tests for ``core.config.hosts_override``."""

from __future__ import annotations

import json

from core.config.hosts_override import load_hosts_override


def _write(tmp_path, payload) -> "object":
    cfg = tmp_path / "hosts.json"
    if isinstance(payload, (bytes, bytearray)):
        cfg.write_bytes(payload)
    elif isinstance(payload, str):
        cfg.write_text(payload, encoding="utf-8")
    else:
        cfg.write_text(json.dumps(payload), encoding="utf-8")
    return cfg


def test_missing_file_returns_none(tmp_path):
    assert load_hosts_override(tmp_path / "absent.json") is None


def test_valid_hosts_list(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["a.example", "b.example"]})
    assert load_hosts_override(cfg) == ["a.example", "b.example"]


def test_dedup_preserves_order(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["b", "a", "b", "a"]})
    assert load_hosts_override(cfg) == ["b", "a"]


def test_non_string_and_empty_entries_dropped(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["ok", "", 5, None, {"x": 1}]})
    assert load_hosts_override(cfg) == ["ok"]


def test_all_entries_unusable_treated_as_absent(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["", 0]})
    assert load_hosts_override(cfg) is None


def test_malformed_json_degrades_to_none(tmp_path):
    cfg = _write(tmp_path, "{not json")
    assert load_hosts_override(cfg) is None


def test_non_utf8_degrades_to_none(tmp_path):
    cfg = _write(tmp_path, b"\xff\xfe\x00broken")
    assert load_hosts_override(cfg) is None


def test_wrong_schema_degrades_to_none(tmp_path):
    assert load_hosts_override(_write(tmp_path, ["just", "a", "list"])) is None
    assert load_hosts_override(_write(tmp_path, {"hosts": "not-a-list"})) is None
    assert load_hosts_override(_write(tmp_path, {"no_hosts_key": 1})) is None

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


def test_explicit_empty_override_is_honoured(tmp_path):
    # {"hosts": []} is an operator statement ("allow nothing"), not
    # an absent config — collapsing it to None would silently restore
    # the permissive static default the operator meant to replace.
    cfg = _write(tmp_path, {"hosts": []})
    assert load_hosts_override(cfg) == []


def test_all_entries_unusable_still_honoured_as_empty(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["", 0]})
    assert load_hosts_override(cfg) == []


def test_entries_are_whitespace_stripped(tmp_path):
    # A hand-edited "host.example " passes string validation but can
    # never match the proxy's hostname comparison — strip at load.
    cfg = _write(tmp_path, {"hosts": [" a.example ", "b.example\n"]})
    assert load_hosts_override(cfg) == ["a.example", "b.example"]


def test_stripped_duplicates_collapse(tmp_path):
    cfg = _write(tmp_path, {"hosts": ["a.example", " a.example"]})
    assert load_hosts_override(cfg) == ["a.example"]


def test_malformed_json_degrades_to_none(tmp_path, caplog):
    cfg = _write(tmp_path, "{not json")
    with caplog.at_level("WARNING", logger="core.config.hosts_override"):
        assert load_hosts_override(cfg) is None
    # Fail-open toward the static default must be loud.
    assert any("static default" in r.message for r in caplog.records)


def test_non_utf8_degrades_to_none(tmp_path, caplog):
    cfg = _write(tmp_path, b"\xff\xfe\x00broken")
    with caplog.at_level("WARNING", logger="core.config.hosts_override"):
        assert load_hosts_override(cfg) is None
    assert any("static default" in r.message for r in caplog.records)


def test_wrong_schema_degrades_to_none(tmp_path, caplog):
    with caplog.at_level("WARNING", logger="core.config.hosts_override"):
        assert load_hosts_override(
            _write(tmp_path, ["just", "a", "list"])) is None
        assert load_hosts_override(
            _write(tmp_path, {"hosts": "not-a-list"})) is None
        assert load_hosts_override(
            _write(tmp_path, {"no_hosts_key": 1})) is None
    assert sum(
        "unexpected schema" in r.message for r in caplog.records) == 3


def test_dropped_entries_are_logged(tmp_path, caplog):
    cfg = _write(tmp_path, {"hosts": ["ok.example", 5, ""]})
    with caplog.at_level("WARNING", logger="core.config.hosts_override"):
        assert load_hosts_override(cfg) == ["ok.example"]
    assert any("dropped 2" in r.message for r in caplog.records)

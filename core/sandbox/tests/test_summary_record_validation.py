"""Malformed evidence records cannot suppress surrounding valid denials."""

import json

import pytest

from core.sandbox import summary


@pytest.fixture(autouse=True)
def isolated_state(tmp_path):
    from core.testing.sandbox_state_scope import isolated_sandbox_state
    from core.testing.state_isolation import pin_user_state_dirs
    with isolated_sandbox_state(()):
        with pytest.MonkeyPatch.context() as patch:
            patch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))
            pin_user_state_dirs(patch, tmp_path)
            yield


@pytest.fixture
def monkeypatch(isolated_state):
    """Undo body patches before restoring fixture-owned state."""
    with pytest.MonkeyPatch.context() as patch:
        yield patch


@pytest.mark.parametrize("bad", [
    '{"type":[]}', '{"type":{}}', '{"type":null}', '{"type":42}',
    '{"type":"seccomp","syscall":[]}',
    '{"type":"seccomp","syscall":"socket","args":{"a":1,"b":2}}',
    '{"type":"seccomp","syscall":"socket","args":"17"}',
    '{"type":"network","value":NaN}',
    '{"type":"network","value":Infinity}',
    '{"type":"network","value":-Infinity}',
    '{"type":"network","value":1e9999}',
    '{"type":"network","extra":{"nested":[NaN]}}',
])
def test_bad_record_is_counted_and_valid_neighbors_survive(tmp_path, bad):
    valid = {"type": "network", "cmd": "test", "host": "example.invalid"}
    source = tmp_path / summary.DENIALS_FILE
    source.write_text(json.dumps(valid) + "\n" + bad + "\n"
                      + json.dumps(valid) + "\n", encoding="utf-8")
    result = summary.summarize_and_write(tmp_path)
    assert result["corrupt_lines"] == 1
    assert result["total_denials"] == 2
    assert result["by_type"] == {"network": 2}
    saved = json.loads((tmp_path / summary.SUMMARY_FILE).read_text())
    assert saved["corrupt_lines"] == 1
    assert saved["total_denials"] == 2


@pytest.mark.parametrize("record", [
    {}, {"type": "future-event", "extra": {"value": 1.25}},
    {"type": "seccomp", "syscall": None, "args": None},
    {"type": "network", "denial_type": "extra field"},
])
def test_compatible_records_remain_supported(tmp_path, record):
    (tmp_path / summary.DENIALS_FILE).write_text(
        json.dumps(record) + "\n", encoding="utf-8",
    )
    result = summary.summarize_and_write(tmp_path)
    assert result["total_denials"] == 1
    assert "corrupt_lines" not in result
    for key, value in record.items():
        assert result["denials"][0][key] == value

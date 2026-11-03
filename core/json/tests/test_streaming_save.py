"""Streaming artifact writes retain data fidelity and atomic failure semantics."""
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest


@pytest.mark.parametrize("sort_keys", [False, True])
def test_streaming_save_matches_stdlib_artifact_format(tmp_path, monkeypatch, sort_keys):
    import core.json.utils as module

    # Streaming must not call a whole-document optional encoder.
    monkeypatch.setattr(module, "_orjson", object())
    data = {"unicode": "café / 東京 / 😀", "large_integer": 2**120,
            "nested": [{"ref": "pkg:example@1", "unknown": {"retained": True}}] * 5000,
            "path": Path("relative/file"), "time": datetime(2026, 1, 1, tzinfo=timezone.utc)}
    path = tmp_path / "streamed.json"
    module.save_json(path, data, mode=0o600, sort_keys=sort_keys, stream=True)
    expected = module._stdlib_artifact_dumps(data, sort_keys=sort_keys).encode("utf-8")
    assert path.read_bytes() == expected
    assert json.loads(path.read_bytes())["large_integer"] == 2**120
    assert path.stat().st_mode & 0o777 == 0o600


def test_late_invalid_number_does_not_replace_existing_json(tmp_path):
    from core.json import save_json

    path = tmp_path / "streamed.json"
    path.write_text('{"original":true}\n')
    data = {"rows": [{"id": index} for index in range(10000)], "invalid": float("nan")}
    with pytest.raises(ValueError, match="Out of range"):
        save_json(path, data, stream=True)
    assert path.read_text() == '{"original":true}\n'
    assert list(tmp_path.iterdir()) == [path]


def test_streaming_empty_containers_have_valid_newline_terminated_output(tmp_path):
    from core.json import save_json

    path = tmp_path / "streamed.json"
    for data in ({}, [], None):
        save_json(path, data, stream=True)
        assert path.read_bytes().endswith(b"\n")
        assert json.loads(path.read_bytes()) == data

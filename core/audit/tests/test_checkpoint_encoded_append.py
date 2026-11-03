"""Checkpoint append reuses exactly the size-checked, authenticated bytes."""

import json

import pytest

from core.audit import sweep_checkpoint as sc
from core.audit.tests.test_sweep_checkpoint import _key, _result


@pytest.mark.parametrize("delta", [-1, 0, 1])
def test_exact_bytes_mac_and_record_size_boundary(tmp_path, monkeypatch, delta):
    monkeypatch.setattr(sc, "_usable_mac_key", lambda: b"x" * 32)
    checkpoint = sc.SweepCheckpoint(tmp_path)
    key = _key()
    result = _result("confirmed", matches=[{"text": "é🙂\n\x00\ud800", "line": 3}],
                     details={"note": [None, False, 1.25]})
    tool, parts = sc._key_to_parts(key)
    record = {"v": sc.CHECKPOINT_VERSION, "tool": tool, "parts": parts,
              "result": {field: getattr(result, field) for field in sc._RESULT_FIELDS}}
    record[sc.TOKEN_KEY] = sc._mint_token(checkpoint._mac_key, record, checkpoint._run_binding)
    expected = (json.dumps(record, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    checkpoint._max_record_bytes = len(expected) + delta
    dumps = json.dumps
    signed_serializations = []

    def counted(value, **kwargs):
        if isinstance(value, dict) and sc.TOKEN_KEY in value:
            signed_serializations.append(1)
        return dumps(value, **kwargs)

    monkeypatch.setattr(sc.json, "dumps", counted)
    checkpoint.record(key, result)
    assert len(signed_serializations) == 1
    path = tmp_path / sc.CHECKPOINT_FILENAME
    if delta < 0:
        assert checkpoint.recorded == 0 and not path.exists()
    else:
        assert checkpoint.recorded == 1
        assert path.read_bytes() == expected
        resumed = sc.SweepCheckpoint(tmp_path)
        replay = resumed.lookup(key)
        assert replay is not None and replay.matches == result.matches


@pytest.mark.parametrize("value", [float("nan"), float("inf"), object()])
def test_non_json_result_still_skips_without_disabling_writes(tmp_path, monkeypatch, value):
    monkeypatch.setattr(sc, "_usable_mac_key", lambda: b"x" * 32)
    checkpoint = sc.SweepCheckpoint(tmp_path)
    checkpoint.record(_key(rule="bad"), _result(details={"value": value}))
    assert checkpoint.recorded == 0
    checkpoint.record(_key(rule="good"), _result())
    assert checkpoint.recorded == 1

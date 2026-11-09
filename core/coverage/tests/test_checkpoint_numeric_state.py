"""Checkpoint polling refuses oversized numeric state without float overflow."""
import json

import pytest

from core.coverage import journal_checkpoint as checkpoint


@pytest.fixture(autouse=True)
def stdlib_reader(monkeypatch):
    from core.json import load_json
    # Re-exported functions may outlive a package reload: patch the reader
    # namespace actually consumed by the local import in _load_state.
    monkeypatch.setitem(load_json.__globals__, '_orjson', None)


@pytest.mark.parametrize('value', [pytest.param(10**400, id='positive'), pytest.param(-(10**400), id='negative')])
def test_oversized_fraction_is_refused_and_poll_still_fires(tmp_path, monkeypatch, value):
    from core.json import load_json

    path = tmp_path / checkpoint.CHECKPOINT_STATE_FILENAME
    path.write_text(json.dumps({'schema_version': 1, 'effective': False,
                                'max_shard_bytes_after': 1024,
                                'bytes_before': 1024, 'bytes_after': 1024,
                                'freed_fraction': value}))
    parsed = load_json(path, strict=True, max_bytes=checkpoint._MAX_STATE_BYTES)
    assert type(parsed['freed_fraction']) is int and parsed['freed_fraction'] == value
    assert checkpoint._load_state(tmp_path) is None
    monkeypatch.setattr(checkpoint, 'max_shard_bytes', lambda out: 1024)
    monkeypatch.setattr(checkpoint, 'trigger_bytes', lambda: 64)
    assert checkpoint.evaluate_trigger(tmp_path).fire


@pytest.mark.parametrize('value,effective', [(0, False), (0.0, False), (0.5, True), (1, True), (1.0, True)])
def test_finite_fraction_boundaries_keep_checkpoint_state_and_advisory(
    tmp_path, monkeypatch, value, effective,
):
    after = int(1024 * (1 - value))
    path = tmp_path / checkpoint.CHECKPOINT_STATE_FILENAME
    path.write_text(json.dumps({'schema_version': 1, 'effective': effective,
                                'max_shard_bytes_after': after,
                                'bytes_before': 1024, 'bytes_after': after,
                                'freed_fraction': value}))
    state = checkpoint._load_state(tmp_path)
    assert state is not None and state['freed_fraction'] == value
    monkeypatch.setattr(checkpoint, 'max_shard_bytes', lambda out: 1024)
    monkeypatch.setattr(checkpoint, 'trigger_bytes', lambda: 64)
    decision = checkpoint.evaluate_trigger(tmp_path)
    assert decision.fire is effective
    assert decision.advisory is not effective

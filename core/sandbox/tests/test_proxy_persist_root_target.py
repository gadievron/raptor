"""Root targets obey the existing proxy-event target-pollution exclusion."""
import json
import threading

import pytest

from core.sandbox import context, proxy, summary, telemetry_mac


@pytest.fixture(autouse=True)
def isolated_persistence(monkeypatch):
    monkeypatch.setattr(context, '_PROXY_STREAM_STATE', {})
    monkeypatch.setattr(context, '_PROXY_PERSIST_LOCK', threading.Lock())
    monkeypatch.setattr(summary, '_proxy_persist_state', {})
    # Path exclusion is independent of provenance. Never read/create a key.
    monkeypatch.setattr(telemetry_mac, 'mint', lambda fields: None)
    monkeypatch.setattr(telemetry_mac, 'verify', lambda fields, token: False)


def _events():
    return [{'host': 'example.test', 'port': 443, 'result': 'allowed'}]


def _assert_skipped(output, target, existing):
    paths = [output / name for name in [proxy.PROXY_EVENTS_FILENAME, proxy.PROXY_EVENTS_COUNT_FILENAME]]
    saved = b'{"operator":"existing output"}\n'
    if existing:
        for path in paths:
            path.write_bytes(saved)
    events = _events()
    before = [dict(event) for event in events]
    context._persist_proxy_events(events, output=output, target=target)
    for path in paths:
        if existing:
            assert path.read_bytes() == saved
        else:
            assert not path.exists()
    assert events == before
    assert context._PROXY_STREAM_STATE == {}
    assert summary.get_proxy_persist_state(output) is None
    assert context._PROXY_PERSIST_LOCK.acquire(blocking=False)
    context._PROXY_PERSIST_LOCK.release()


@pytest.mark.parametrize('spelling', ['/', '//', '///', '/.', 'alias'], ids=['root', 'double-slash', 'triple-slash', 'dot', 'symlink'])
@pytest.mark.parametrize('existing', [False, True], ids=['absent', 'preserved'])
def test_root_target_skips_all_descendant_outputs(tmp_path, spelling, existing):
    output = tmp_path / 'output'
    output.mkdir()
    if spelling == 'alias':
        alias = tmp_path / 'root-alias'
        alias.symlink_to('/', target_is_directory=True)
        target = alias
    else:
        target = spelling
    _assert_skipped(output, target, existing)


@pytest.mark.parametrize('layout', ['equal', 'nested', 'output-alias', 'target-alias'])
@pytest.mark.parametrize('existing', [False, True], ids=['absent', 'preserved'])
def test_nonroot_targets_keep_existing_pollution_exclusion(tmp_path, layout, existing):
    target = tmp_path / 'tree'
    target.mkdir()
    output = target if layout == 'equal' else target / 'output'
    output.mkdir(exist_ok=True)
    if layout == 'output-alias':
        alias = tmp_path / 'output-alias'
        alias.symlink_to(output, target_is_directory=True)
        output = alias
    elif layout == 'target-alias':
        alias = tmp_path / 'target-alias'
        alias.symlink_to(target, target_is_directory=True)
        target = alias
    _assert_skipped(output, target, existing)


@pytest.mark.parametrize('layout', ['sibling', 'common-prefix', 'output-ancestor', 'no-target'])
def test_outputs_outside_target_still_persist(tmp_path, layout):
    output = tmp_path / 'tree-output'
    output.mkdir()
    target = output / 'nested' if layout == 'output-ancestor' else tmp_path / 'tree'
    target.mkdir()
    if layout == 'sibling':
        target = tmp_path / 'other'
        target.mkdir()
    if layout == 'no-target':
        target = None
    events = _events()
    context._persist_proxy_events(events, output=output, target=target)
    assert [json.loads(line) for line in (output / proxy.PROXY_EVENTS_FILENAME).read_text().splitlines()] == events
    assert summary.get_proxy_persist_state(output)['expected_count'] == 1

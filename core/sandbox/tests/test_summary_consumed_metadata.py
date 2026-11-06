"""Reject malformed consumed metadata before signing an entire evidence batch."""
import json

import pytest

from core.sandbox import evidence, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


@pytest.mark.parametrize('canonical', [False, True], ids=['legacy', 'canonical'])
@pytest.mark.parametrize('field,bad', [
    ('path', []), ('path', {'name': '/tmp/bad'}), ('path', 17), ('path', False),
    ('profile', []), ('profile', {'name': 'full'}), ('profile', 17), ('profile', False),
], ids=['array-path', 'object-path', 'integer-path', 'boolean-path',
        'array-profile', 'object-profile', 'integer-profile', 'boolean-profile'])
def test_malformed_text_marks_loss_and_preserves_neighbors(tmp_path, canonical, field, bad):
    run = tmp_path / 'run'
    path = (evidence.evidence_write_path(run, summary.DENIALS_FILE) if canonical else
            evidence.legacy_read_path(run, summary.DENIALS_FILE))
    path.parent.mkdir(parents=True, exist_ok=True)
    first = {'type': 'write', 'path': '/tmp/first'}
    last = {'type': 'write', 'path': '/tmp/last'}
    malformed = {'type': 'write', field: bad}
    path.write_text('\n'.join(map(json.dumps, [first, malformed, last])) + '\n')
    result = summary.summarize_and_write(run)
    assert result['corrupt_lines'] == 1
    assert result['total_denials'] == 2
    assert [record['path'] for record in result['denials']] == ['/tmp/first', '/tmp/last']
    assert result['mac']
    assert json.loads((run / summary.SUMMARY_FILE).read_text()) == result
    assert triage.triage_run(run, allow_legacy=False)['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    assert not path.exists()
    assert not list(path.parent.glob(path.name + '.summarising.*'))


@pytest.mark.parametrize('metadata', [
    {}, {'path': None, 'profile': None},
    {'path': '', 'profile': ''}, {'path': '/tmp/caf\u00e9', 'profile': 'future-profile'},
    {'args': [{'detail': 1}, {'detail': 2}], 'metadata': {'detail': 'opaque'}},
], ids=['missing', 'null', 'empty', 'unicode-future', 'opaque-unconsumed'])
def test_supported_metadata_round_trips(tmp_path, metadata):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True)
    record = {'type': 'write', **metadata}
    path.write_text(json.dumps(record) + '\n')
    result = summary.summarize_and_write(run)
    assert 'corrupt_lines' not in result
    assert result['total_denials'] == 1
    assert all(result['denials'][0][key] == value for key, value in metadata.items())
    assert triage.triage_run(run, allow_legacy=False)['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_VERIFIED

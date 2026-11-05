"""Ambiguous JSON objects must not become normalized signed evidence."""
import json

import pytest

from core.sandbox import evidence, summary, triage
from core.testing.state_isolation import pin_user_state_dirs


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'xdg'))


BAD_RECORDS = [
    pytest.param('{"type":"write","type":"network"}', id='type'),
    pytest.param('{"type":"write","path":"/tmp/first","path":"/tmp/last"}', id='path'),
    pytest.param(r'{"type":"write","path":"/tmp/first","pa\u0074h":"/tmp/last"}',
                 id='escaped-field'),
    pytest.param('{"type":"write","metadata":{"detail":"first","detail":"last"}}',
                 id='nested-object'),
    pytest.param('{"type":"write","args":[{"detail":1,"detail":2}]}', id='object-in-array'),
    pytest.param('{"type":"write","metadata":{"detail":1,"detail":1}}', id='equal-values'),
    pytest.param('{"type":"write","\\u2603":1,"\u2603":2}', id='unicode-field'),
]


def source(run, canonical):
    path = (evidence.evidence_write_path(run, summary.DENIALS_FILE) if canonical else
            evidence.legacy_read_path(run, summary.DENIALS_FILE))
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@pytest.mark.parametrize('canonical', [False, True], ids=['legacy', 'canonical'])
@pytest.mark.parametrize('bad', BAD_RECORDS)
def test_duplicate_fields_flag_summary_and_preserve_neighbors(tmp_path, canonical, bad):
    run = tmp_path / 'run'
    first = {'type': 'write', 'path': '/tmp/first'}
    last = {'type': 'write', 'path': '/tmp/last'}
    path = source(run, canonical)
    path.write_text(json.dumps(first) + '\n' + bad + '\n' + json.dumps(last) + '\n')
    result = summary.summarize_and_write(run)
    assert result is not None
    assert result['corrupt_lines'] == 1
    assert result['total_denials'] == 2
    assert [rec['path'] for rec in result['denials']] == ['/tmp/first', '/tmp/last']
    assert result.get('mac')
    assert json.loads((run / summary.SUMMARY_FILE).read_text()) == result
    report = triage.triage_run(run, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_TAMPERED
    assert not path.exists()
    assert not list(path.parent.glob(path.name + '.summarising.*'))


@pytest.mark.parametrize('text', [
    '{"type":"write","metadata":{"left":{"detail":1},"right":{"detail":2}}}',
    '{"type":"write","args":[{"detail":1},{"detail":2}]}',
    r'{"type":"write","pa\u0074h":"/tmp/escaped"}',
    '{"type":"write","\u00e9":1,"e\u0301":2}',
    '{"type":"write","":1,"metadata":{"":2}}',
])
def test_unique_fields_remain_compatible(tmp_path, text):
    run = tmp_path / 'run'
    path = source(run, True)
    path.write_text(text + '\n')
    result = summary.summarize_and_write(run)
    assert result is not None
    assert result['total_denials'] == 1
    assert 'corrupt_lines' not in result
    for key, value in json.loads(text).items():
        assert result['denials'][0][key] == value
    report = triage.triage_run(run, allow_legacy=False)
    assert report['inputs']['integrity']['sandbox_summary'] == triage._INTEGRITY_VERIFIED

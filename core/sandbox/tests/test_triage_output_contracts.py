"""Machine output stays JSON; human refusal metadata stays inert."""
import json
import logging

import pytest

from core.sandbox import evidence, summary, triage, triage_deep
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))
    from core.llm import factory
    def unexpected_client():
        pytest.fail('empty, clean and refused reports must not acquire an LLM client')
    monkeypatch.setattr(factory, 'get_client', unexpected_client)


def clean_summary(run):
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True, mode=0o700)
    path.write_text(json.dumps({'type': 'write', 'cmd': 'owned compilation',
                               'path': '/tmp/owned-output', 'returncode': 1}) + '\n')
    result = summary.summarize_and_write(run)
    assert result['mac']
    return run / summary.SUMMARY_FILE


@pytest.mark.parametrize('deep', [False, True], ids=['rules', 'deep'])
@pytest.mark.parametrize('legacy', [False, True], ids=['current', 'legacy'])
def test_no_telemetry_json_is_null_without_creating_a_report(tmp_path, capsys, deep, legacy):
    args = [str(tmp_path), '--json'] + (['--deep'] if deep else []) + (['--legacy'] if legacy else [])
    assert triage._cli_main(args) == 0
    captured = capsys.readouterr()
    assert json.loads(captured.out) is None
    assert not (tmp_path / triage.TRIAGE_FILE).exists()
    assert not (tmp_path / triage_deep.DEEP_FILE).exists()


@pytest.mark.parametrize('deep', [False, True], ids=['rules', 'deep'])
@pytest.mark.parametrize('legacy', [False, True], ids=['current', 'legacy'])
def test_clean_json_is_exactly_the_persisted_report(tmp_path, capsys, deep, legacy):
    path = clean_summary(tmp_path)
    original = path.read_bytes()
    args = [str(tmp_path), '--json'] + (['--deep'] if deep else []) + (['--legacy'] if legacy else [])
    assert triage._cli_main(args) == 0
    captured = capsys.readouterr()
    report = json.loads(captured.out)
    assert report == json.loads((tmp_path / triage.TRIAGE_FILE).read_text())
    assert report['verdict'] == 'clean'
    assert triage.verify_triage_report(report, tmp_path) == 'verified'
    assert path.read_bytes() == original
    assert not (tmp_path / triage_deep.DEEP_FILE).exists()


@pytest.mark.parametrize('kind', ['empty', 'clean'])
def test_human_empty_and_clean_deep_status_remains_available(tmp_path, capsys, kind):
    if kind == 'clean':
        clean_summary(tmp_path)
    assert triage._cli_main([str(tmp_path), '--deep']) == 0
    captured = capsys.readouterr()
    expected = 'no sandbox telemetry found' if kind == 'empty' else 'clean verdict — deep pass has nothing to assess'
    assert expected in captured.out


@pytest.mark.parametrize('kind', ['missing', 'legacy', 'tampered'])
def test_deep_refusal_log_escapes_run_path_without_touching_report(tmp_path, caplog, kind):
    run = tmp_path / CONTROL
    run.mkdir()
    path = run / triage.TRIAGE_FILE
    if kind != 'missing':
        path.write_text(json.dumps({'verdict': 'clean', 'signals': [],
                                   **({'mac': 'invalid'} if kind == 'tampered' else {})}))
    before = path.read_bytes() if path.exists() else None
    assert triage_deep.deep_analyse(run) is None
    records = [r for r in caplog.records if r.name == triage_deep.__name__]
    assert len(records) == 1
    text = logging.Formatter('%(message)s').format(records[0])
    assert 'triage_deep:' in text
    assert 'owned-' in text
    assert all(c not in text for c in ('\x1b', '\r', '\n', '\x85', '\u202e'))
    assert (path.read_bytes() if path.exists() else None) == before
    assert not (run / triage_deep.DEEP_FILE).exists()

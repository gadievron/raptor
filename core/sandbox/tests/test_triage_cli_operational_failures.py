"""Required reports fail clearly; optional deep I/O/data failures retain the rules status."""
import json

import pytest

from core.llm.budget_errors import LLMBudgetExceededError
from core.llm.transcript import TranscriptError
from core.sandbox import evidence, summary, triage, triage_deep
from core.testing.state_isolation import pin_user_state_dirs


CONTROL = 'owned-\x1b[31m\r\n\x85\u202e' + 'x' * 1500


class OwnedClient:
    model_name = 'owned-model'

    def __init__(self, failure=None):
        self.failure = failure
        self.calls = []

    def generate(self, user, *, system_prompt='', **kwargs):
        self.calls.append((user, system_prompt, kwargs))
        if self.failure is not None:
            raise self.failure
        return '{"assessments":[],"overall_note":"owned note"}'


@pytest.fixture(autouse=True)
def owned_state(tmp_path, monkeypatch):
    pin_user_state_dirs(monkeypatch, tmp_path / 'state')
    monkeypatch.setenv('XDG_DATA_HOME', str(tmp_path / 'data'))


@pytest.fixture
def run(tmp_path):
    run = tmp_path / 'run'
    path = evidence.evidence_write_path(run, summary.DENIALS_FILE)
    path.parent.mkdir(parents=True, mode=0o700)
    # A real, generic unattributed-denial record yields a notable rules
    # verdict without constructing any target execution or attack activity.
    path.write_text(json.dumps({'type': 'seccomp', 'profile': 'full',
                               'cmd': 'owned operation', 'returncode': 1}) + '\n')
    result = summary.summarize_and_write(run)
    assert result['mac']
    return run


def install_client(monkeypatch, client):
    from core.llm import factory
    requests = []
    def acquire():
        requests.append(True)
        return client
    monkeypatch.setattr(factory, 'get_client', acquire)
    return requests


def check_rules_output(captured, run, json_output):
    stored = json.loads((run / triage.TRIAGE_FILE).read_text())
    assert stored['verdict'] == 'notable'
    assert triage.verify_triage_report(stored, run) == 'verified'
    if json_output:
        assert json.loads(captured.out) == stored
    else:
        assert 'Verdict: Notable' in captured.out
    return stored


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('deep', [False, True], ids=['rules', 'deep'])
def test_required_report_write_failure_has_error_status(run, monkeypatch, capsys, json_output, deep):
    client = OwnedClient()
    requests = install_client(monkeypatch, client)
    destination = run / triage.TRIAGE_FILE
    destination.mkdir()
    before = (run / summary.SUMMARY_FILE).read_bytes()
    args = [str(run)] + (['--json'] if json_output else []) + (['--deep'] if deep else [])
    assert triage._cli_main(args) == 1
    captured = capsys.readouterr()
    assert captured.out == ''
    assert 'cannot produce triage report' in captured.err
    assert destination.is_dir()
    assert requests == client.calls == []
    assert (run / summary.SUMMARY_FILE).read_bytes() == before


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_optional_report_write_failure_keeps_rules_status(run, monkeypatch, capsys, json_output):
    client = OwnedClient()
    requests = install_client(monkeypatch, client)
    destination = run / triage_deep.DEEP_FILE
    destination.mkdir()
    before = (run / summary.SUMMARY_FILE).read_bytes()
    args = [str(run), '--deep'] + (['--json'] if json_output else [])
    assert triage._cli_main(args) == 3
    captured = capsys.readouterr()
    check_rules_output(captured, run, json_output)
    assert 'deep pass failed' in captured.err
    assert 'IsADirectoryError' in captured.err
    assert 'Deep assessment' not in captured.out
    assert len(requests) == len(client.calls) == 1
    assert destination.is_dir()
    assert (run / summary.SUMMARY_FILE).read_bytes() == before
    assert not list(run.glob('.~triage-deep-*'))


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
@pytest.mark.parametrize('failure_type', [OSError, ValueError], ids=['io', 'data'])
def test_optional_io_and_data_errors_are_bounded_diagnostics(run, monkeypatch, capsys, json_output, failure_type):
    client = OwnedClient(failure_type(CONTROL))
    install_client(monkeypatch, client)
    assert triage._cli_main([str(run), '--deep'] + (['--json'] if json_output else [])) == 3
    captured = capsys.readouterr()
    check_rules_output(captured, run, json_output)
    assert 'deep pass failed' in captured.err
    assert failure_type.__name__ in captured.err
    assert len(captured.err) < 500
    assert captured.err.count('\n') == 1
    assert all(c not in captured.err for c in ('\x1b', '\r', '\x85', '\u202e'))
    assert len(client.calls) == 1
    assert not (run / triage_deep.DEEP_FILE).exists()


def terminal_failure(kind):
    return {'interrupt': KeyboardInterrupt, 'exit': SystemExit,
            'budget': LLMBudgetExceededError, 'transcript': TranscriptError,
            'runtime': RuntimeError}[kind]('owned stop')


@pytest.mark.parametrize('stage', ['rules', 'deep'])
@pytest.mark.parametrize('kind', ['interrupt', 'exit', 'budget', 'transcript', 'runtime'])
def test_terminal_and_unexpected_failures_still_propagate(run, monkeypatch, stage, kind):
    failure = terminal_failure(kind)
    client = OwnedClient(failure)
    requests = install_client(monkeypatch, client)
    if stage == 'rules':
        def stopped(*args, **kwargs):
            raise failure
        monkeypatch.setattr(triage, 'triage_run', stopped)
    with pytest.raises(type(failure)) as caught:
        triage._cli_main([str(run), '--deep', '--json'])
    assert caught.value is failure
    assert len(requests) == len(client.calls) == (1 if stage == 'deep' else 0)
    assert not (run / triage_deep.DEEP_FILE).exists()


@pytest.mark.parametrize('json_output', [False, True], ids=['text', 'json'])
def test_successful_deep_pass_keeps_its_report_and_rules_status(run, monkeypatch, capsys, json_output):
    client = OwnedClient()
    install_client(monkeypatch, client)
    assert triage._cli_main([str(run), '--deep'] + (['--json'] if json_output else [])) == 3
    captured = capsys.readouterr()
    check_rules_output(captured, run, json_output)
    value = json.loads((run / triage_deep.DEEP_FILE).read_text())
    assert triage_deep.verify_deep_report(value, run) == 'verified'
    assert value['rules_verdict'] == 'notable'
    assert len(client.calls) == 1

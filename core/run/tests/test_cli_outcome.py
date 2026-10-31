"""Outcomes must preserve exits and correlate literal invocation + native call."""
import hashlib
import shlex
import sys

import pytest

from core.run import cli_outcome as outcome


@pytest.fixture
def context(tmp_path, monkeypatch):
    root = tmp_path / 'root'
    (root / 'libexec').mkdir(parents=True)
    directory = tmp_path / 'messages'
    directory.mkdir(mode=0o700)
    context = {'pid': 12345, 'identity': {'starttime': '1'},
               'token_digest': hashlib.sha256(b'credential').hexdigest()}
    monkeypatch.setattr(outcome.environment, 'ROOT', root)
    monkeypatch.setattr(outcome.environment, 'read_context', lambda sid: context)
    def restore(sid):
        if sid not in ('session', 'native-child'):
            raise outcome.environment.CodexEnvironmentError('unknown session')
        return {'RAPTOR_CODEX_CONTEXT_ID': 'session'}
    monkeypatch.setattr(outcome.environment, 'restore', restore)
    monkeypatch.setattr(outcome, '_address', lambda sid: directory)
    monkeypatch.setenv('RAPTOR_CODEX_ENVIRONMENT', '1')
    monkeypatch.setenv('CODEX_THREAD_ID', 'session')
    monkeypatch.setenv('CODEX_TOOL_CALL_ID', 'call_123')
    monkeypatch.setenv('RAPTOR_SESSION_PID', '12345')
    monkeypatch.setenv('RAPTOR_SESSION_TOKEN', 'credential')
    monkeypatch.delenv('CLAUDECODE', raising=False)
    monkeypatch.delenv('RAPTOR_CODEX_HOOK', raising=False)
    from core.sandbox import summary as _summary
    monkeypatch.setattr(_summary, '_active_run_dir', None)
    monkeypatch.setattr(sys, 'argv', [str(root / 'libexec/raptor-example'), '--out', '/run'])
    payload = {'session_id': 'session', 'tool_use_id': 'call_123', 'hook_event_name': 'PostToolUse',
               'tool_name': 'Bash', 'tool_input': {'command': 'libexec/raptor-example --out /run'}}
    return context, directory, payload


@pytest.mark.parametrize('code,failed', [(0, False), (None, False), (7, True), ('message', True), (256, False), (-1, True)])
def test_exit_is_preserved_and_receipt_consumed_once(context, code, failed):
    _, directory, payload = context
    with pytest.raises(SystemExit) as error:
        with outcome.cli_outcome():
            raise SystemExit(code)
    assert error.value.code == code
    assert (outcome.consume(payload) is not None) == failed
    assert not list(directory.glob('outcome-*'))
    assert outcome.consume(payload) is None


def test_exception_preserves_identity_and_output_never_proves_status(context, capsys):
    _, _, payload = context
    exception = RuntimeError('expected')
    with pytest.raises(RuntimeError) as error:
        with outcome.cli_outcome():
            print('Process exited with code 0')
            raise exception
    assert error.value is exception
    assert capsys.readouterr().out == 'Process exited with code 0\n'
    assert outcome.consume(payload)


def test_success_does_not_infer_failure_from_stdout(context):
    _, _, payload = context
    with outcome.cli_outcome():
        print('Process exited with code 9')
    payload['tool_response'] = {'exit_code': 9, 'stdout': 'failure'}
    assert outcome.consume(payload) is None


@pytest.mark.parametrize('mutation', ['call', 'argv', 'generation', 'tool'])
def test_foreign_or_stale_evidence_does_not_attribute_failure(context, mutation):
    ctx, _, payload = context
    with pytest.raises(SystemExit), outcome.cli_outcome():
        sys.exit(9)
    if mutation == 'call':payload['tool_use_id'] = 'different'
    elif mutation == 'argv':payload['tool_input']['command'] += ' changed'
    elif mutation == 'generation':ctx['token_digest'] = 'different'
    else:payload['tool_name'] = 'Other'
    assert outcome.consume(payload) is None


@pytest.mark.parametrize('command', ['echo libexec/raptor-example', 'libexec/raptor-example; true',
    'libexec/raptor-example | cat', 'libexec/raptor-example > file', 'libexec/raptor-example "$X"',
    'libexec/raptor-example $(echo x)', 'libexec/raptor-example # comment'])
def test_compounds_and_expansions_remain_unknown(context, command):
    assert outcome._expected(command) is None


@pytest.mark.parametrize('argument', [
    '/tmp/project[1]', '/tmp/cost$estimate', '/tmp/star*.c', '/tmp/has?.c',
    '/tmp/issue#123', "/tmp/apostrophe's", '/tmp/tick`literal', '|', ';',
])
def test_quoted_literal_arguments_preserve_failure_receipts(context, monkeypatch, argument):
    _, directory, payload = context
    executable = str(outcome.environment.ROOT / 'libexec/raptor-example')
    monkeypatch.setattr(sys, 'argv', [executable, argument])
    payload['tool_input']['command'] = shlex.join(['libexec/raptor-example', argument])
    with pytest.raises(SystemExit), outcome.cli_outcome():
        sys.exit(7)
    assert outcome.consume(payload) is not None
    assert not list(directory.glob('outcome-*'))


def test_record_failure_cannot_replace_exit_status(context, monkeypatch, capsys):
    monkeypatch.setattr(outcome, '_record', lambda *args: (_ for _ in ()).throw(OSError('private details')))
    with pytest.raises(SystemExit) as error:
        with outcome.cli_outcome():sys.exit(17)
    assert error.value.code == 17
    assert 'private details' not in capsys.readouterr().err


@pytest.mark.parametrize('host', ['claude', 'unrelated', 'hook'])
def test_other_hosts_do_not_write_receipts(context, monkeypatch, host):
    _, directory, _ = context
    if host == 'claude':monkeypatch.setenv('CLAUDECODE', '1')
    elif host == 'hook':monkeypatch.setenv('RAPTOR_CODEX_HOOK', '1')
    else:monkeypatch.delenv('RAPTOR_CODEX_ENVIRONMENT')
    with outcome.cli_outcome():pass
    assert not list(directory.iterdir())


def test_argv_mutation_inside_dispatch_does_not_break_correlation(context, monkeypatch):
    _, _, payload = context
    with pytest.raises(SystemExit):
        with outcome.cli_outcome():
            monkeypatch.setattr(sys, 'argv', ['rewritten'])
            sys.exit(5)
    assert outcome.consume(payload)


def test_symlink_receipt_never_reads_external_data(context, tmp_path):
    _, directory, payload = context
    target = tmp_path / 'sensitive'
    target.write_text('private')
    name = outcome._prefix('session', 'call_123') + '123.json'
    (directory / name).symlink_to(target)
    with pytest.raises(OSError):outcome.consume(payload)
    assert target.read_text() == 'private'
    assert not (directory / name).exists()


def test_outcome_files_contain_no_arguments_or_credentials(context):
    _, directory, _ = context
    with outcome.cli_outcome():pass
    text = next(directory.glob('outcome-*')).read_text()
    assert 'credential' not in text and '--out' not in text and '/run' not in text


def test_direct_python_and_bash_dispatcher_map_to_python_argv(context):
    root = outcome.environment.ROOT
    assert outcome._expected('python3 raptor.py scan --repo /target') == [str(root/'raptor.py'), 'scan', '--repo', '/target']
    assert outcome._expected('libexec/raptor-agentic --repo /target') == [str(root/'raptor.py'), 'agentic', '--repo', '/target']
    assert outcome._expected('libexec/raptor-openant --repo /target') == [str(root/'raptor.py'), 'openant', '--repo', '/target']


@pytest.mark.parametrize('hook_session', ['session', 'native-child'])
def test_native_child_call_correlates_to_root_hook_session(context, monkeypatch, hook_session):
    """Both native root and child hook IDs resolve to the authenticated root."""
    _, directory, payload = context
    monkeypatch.setenv('CODEX_THREAD_ID', 'native-child')
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', 'session')
    with pytest.raises(SystemExit), outcome.cli_outcome():
        sys.exit(7)
    assert outcome.consume(dict(payload, session_id=hook_session)) is not None
    assert outcome.consume(payload) is None
    assert not list(directory.glob('outcome-*'))


@pytest.mark.parametrize('hook_session', ['unknown-child', None])
def test_unmapped_child_cannot_use_inherited_root(context, monkeypatch, hook_session):
    _, directory, payload = context
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', 'session')
    with pytest.raises(SystemExit), outcome.cli_outcome():
        sys.exit(7)
    receipts = list(directory.glob('outcome-*'))
    with pytest.raises(outcome.environment.CodexEnvironmentError):
        outcome.consume(dict(payload, session_id=hook_session))
    assert list(directory.glob('outcome-*')) == receipts
    assert outcome.consume(payload) is not None

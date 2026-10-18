"""Real source reads, live ownership and private IPC; no shell-output guesses."""
import io
import json
import os
import shlex
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from core.coverage import codex_read as reader
from core.coverage import track_read
from core.hash import sha256_string
from core.project import sessions
from core.startup import codex_environment as environment
from core.startup.tests.test_codex_broker import host  # noqa: F401

pytestmark = pytest.mark.skipif(sys.platform != 'linux', reason='live Linux Codex owner fixture')


@pytest.fixture
def case(host, tmp_path, monkeypatch):  # noqa: F811 — shared pytest fixture
    sid, process, credential = host
    environment.restore(sid)
    monkeypatch.setenv('CODEX_THREAD_ID', sid)
    monkeypatch.setenv('CODEX_TOOL_CALL_ID', 'read-call-123')
    monkeypatch.delenv('CLAUDECODE', raising=False)
    monkeypatch.delenv('RAPTOR_CODEX_HOOK', raising=False)
    source = tmp_path / 'source.c'
    source.write_text('int a;\nint b;\nint c;\n')
    run = tmp_path / 'run'
    run.mkdir()
    meta = {'status': 'running', 'session_pid': process.pid, 'session_harness': 'codex',
            'session_id': sid, 'session_generation': sha256_string(credential[1]),
            'target_path': str(tmp_path)}
    (run / '.raptor-run.json').write_text(json.dumps(meta))
    ledger = sessions._sessions_dir() / f'{process.pid}.run'
    ledger.write_text(f'running 100 run {run}\n')
    assert track_read._find_active_run() == (str(run), str(tmp_path))
    return sid, source, run, ledger


def fire(case, words=None, output=None):
    sid, source, _run, _ledger = case
    words = [str(source)] if words is None else words
    output = io.StringIO() if output is None else output
    code = reader.read_main(words, output=output)
    payload = {'hook_event_name': 'PostToolUse', 'tool_name': 'Bash',
               'session_id': sid, 'tool_use_id': 'read-call-123',
               'tool_input': {'command': shlex.join(['libexec/raptor-read', *words])},
               'tool_response': output.getvalue()}
    return code, payload


def receipts(case):
    return list(reader.outcome._address(case[0]).glob('read-*.json'))


def manifest(case):
    path = case[2] / track_read.MANIFEST_NAME
    return path.read_text().splitlines() if path.exists() else []


def lifecycle_hook(raw, monkeypatch):
    import runpy
    monkeypatch.setenv('_RAPTOR_TRUSTED', '1')
    monkeypatch.setenv('RAPTOR_CODEX_HOOK', '1')
    monkeypatch.setattr(sys, 'argv', ['raptor-lifecycle-hook', 'codex-outcome'])
    monkeypatch.setattr(sys, 'stdin', io.StringIO(raw))
    module = runpy.run_path(str(environment.ROOT / 'libexec/raptor-lifecycle-hook'))
    return module['_main']([])


def test_successful_read_is_recorded_only_after_matching_native_event(case):
    code, payload = fire(case, [str(case[1]), '--start-line', '2', '--end-line', '2'])
    assert code == 0 and payload['tool_response'] == 'int b;\n'
    assert manifest(case) == [] and len(receipts(case)) == 1
    reader.consume(payload)
    assert manifest(case) == [str(case[1])]
    reader.consume(payload)
    assert manifest(case) == [str(case[1])]
    assert receipts(case) == []


@pytest.mark.parametrize('mutation', ['stdout', 'missing_response', 'argv', 'call', 'tool', 'event'])
def test_wrong_native_evidence_earns_no_coverage(case, mutation):
    _, payload = fire(case)
    if mutation == 'stdout': payload['tool_response'] += 'error or truncated output'
    elif mutation == 'missing_response': payload.pop('tool_response')
    elif mutation == 'argv': payload['tool_input']['command'] += ' --start-line 2'
    elif mutation == 'call': payload['tool_use_id'] = 'another-call'
    elif mutation == 'tool': payload['tool_name'] = 'Read'
    else: payload['hook_event_name'] = 'PreToolUse'
    reader.consume(payload)
    assert manifest(case) == []


@pytest.mark.parametrize('command', [
    'libexec/raptor-read /target > /tmp/redirected',
    'libexec/raptor-read /target | head', 'libexec/raptor-read /target; true',
    'libexec/raptor-read "$SOURCE"', 'libexec/raptor-read $(echo /target)',
    'cat /target', 'sed -n 1,20p /target',
])
def test_shell_commands_are_never_inferred_or_rewritten(case, command):
    _, payload = fire(case)
    payload['tool_input']['command'] = command
    reader.consume(payload)
    assert manifest(case) == []


@pytest.mark.parametrize('field', ['generation', 'argv', 'content', 'path', 'run', 'target'])
def test_receipt_tampering_fails_closed(case, field):
    _, payload = fire(case)
    path = receipts(case)[0]
    value = json.loads(path.read_text())
    value[field] = 'different'
    path.write_text(json.dumps(value))
    reader.consume(payload)
    assert manifest(case) == []
    assert receipts(case) == []


def test_other_live_root_and_rotated_generation_cannot_claim_read(case, monkeypatch):
    import uuid
    _, payload = fire(case)
    original = environment.read_context(case[0])
    other = str(uuid.uuid4())
    monkeypatch.setenv('RAPTOR_CODEX_CONTEXT_ID', other)
    credentials = sessions.ensure_codex_session(original['pid'])
    environment.publish(other, original['pid'])
    try:
        reader.consume(dict(payload, session_id=other))
        assert manifest(case) == []
        environment.restore(case[0])
        assert sessions.end_codex_session(original['pid'], os.environ['RAPTOR_SESSION_TOKEN'])
        assert sessions.ensure_codex_session(original['pid'])
        environment.publish(case[0], original['pid'])
        reader.consume(payload)
        assert manifest(case) == []
    finally:
        environment.restore(other)
        sessions.end_codex_session(original['pid'], credentials[1])


def test_delayed_read_does_not_move_to_new_run(case):
    class SwitchingOutput(io.StringIO):
        def flush(self):
            replacement = case[2].with_name('successor')
            replacement.mkdir()
            (replacement / '.raptor-run.json').write_bytes((case[2] / '.raptor-run.json').read_bytes())
            case[3].write_text(f'running 200 successor {replacement}\n')
    _, payload = fire(case, output=SwitchingOutput())
    reader.consume(payload)
    assert manifest(case) == []
    assert not (case[2].with_name('successor') / track_read.MANIFEST_NAME).exists()


def test_completed_run_and_changed_target_earn_nothing(case):
    _, payload = fire(case)
    meta = case[2] / '.raptor-run.json'
    value = json.loads(meta.read_text())
    value['status'] = 'completed'
    meta.write_text(json.dumps(value))
    reader.consume(payload)
    assert manifest(case) == []


def test_duplicate_receipts_do_not_attribute_ambiguous_invocations(case):
    _, payload = fire(case)
    first = receipts(case)[0]
    duplicate = first.with_name(first.name.replace(f'-{os.getpid()}.json', '-99999999.json'))
    duplicate.write_bytes(first.read_bytes())
    duplicate.chmod(0o600)
    reader.consume(payload)
    assert manifest(case) == [] and receipts(case) == []


def test_parallel_hook_consumers_append_at_most_once(case):
    _, payload = fire(case)
    # Restore once outside the threads: environment overlays are process-global.
    # Real hooks run in separate processes; this forces the receipt unlink race.
    from unittest.mock import patch
    from threading import Barrier
    barrier = Barrier(2)
    unlink = os.unlink
    def competing_unlink(name, **kwargs):
        barrier.wait(timeout=5)
        return unlink(name, **kwargs)
    with patch.object(environment, 'restore', return_value=None), \
            patch.object(reader.os, 'unlink', competing_unlink):
        def consume():
            try:
                reader.consume(payload)
            except FileNotFoundError:
                pass  # lifecycle hook suppresses a concurrent consumer's unlink
        with ThreadPoolExecutor(max_workers=2) as pool:
            list(pool.map(lambda _: consume(), range(2)))
    assert manifest(case) == [str(case[1])]


@pytest.mark.parametrize('kind', ['missing', 'directory', 'fifo', 'binary', 'oversize', 'empty', 'past_eof'])
def test_failed_or_empty_reads_never_mint_receipts(case, kind):
    source = case[1]
    if kind == 'missing': source.unlink()
    elif kind == 'directory': source.unlink(); source.mkdir()
    elif kind == 'fifo': source.unlink(); os.mkfifo(source)
    elif kind == 'binary': source.write_bytes(b'a\0b')
    elif kind == 'oversize':
        with source.open('wb') as stream: stream.truncate(reader._MAX_SOURCE_BYTES + 1)
    elif kind == 'empty': source.write_text('')
    words = [str(source)] + (['--start-line', '999'] if kind == 'past_eof' else [])
    code, payload = fire(case, words)
    assert code == (0 if kind in ('empty', 'past_eof') else 1)
    assert payload['tool_response'] == '' and receipts(case) == []


def test_broken_output_does_not_record_read(case):
    class BrokenOutput(io.StringIO):
        def flush(self): raise BrokenPipeError
    code, _ = fire(case, output=BrokenOutput())
    assert code == 1 and receipts(case) == []


@pytest.mark.parametrize('host_marker', ['CLAUDECODE', 'no_codex', 'hook'])
def test_other_hosts_keep_reading_without_receipts(case, monkeypatch, host_marker):
    if host_marker == 'CLAUDECODE': monkeypatch.setenv('CLAUDECODE', '1')
    elif host_marker == 'hook': monkeypatch.setenv('RAPTOR_CODEX_HOOK', '1')
    else: monkeypatch.delenv('RAPTOR_CODEX_ENVIRONMENT')
    code, payload = fire(case)
    assert code == 0 and payload['tool_response'] == case[1].read_text()
    assert receipts(case) == []


def test_symlink_and_fifo_receipts_never_read_or_block(case, monkeypatch):
    _, payload = fire(case)
    path = receipts(case)[0]
    path.unlink()
    os.mkfifo(path, 0o600)
    assert lifecycle_hook(json.dumps(payload), monkeypatch) is None and manifest(case) == []
    path.symlink_to(case[1])
    assert lifecycle_hook(json.dumps(payload), monkeypatch) is None and manifest(case) == []
    assert case[1].read_text() == 'int a;\nint b;\nint c;\n'


def test_manifest_symlink_cannot_redirect_append(case):
    _, payload = fire(case)
    victim = case[1].with_name('untouched')
    victim.write_text('unchanged')
    (case[2] / track_read.MANIFEST_NAME).symlink_to(victim)
    reader.consume(payload)
    assert victim.read_text() == 'unchanged'


def test_receipts_do_not_contain_source_or_credentials(case):
    fire(case)
    text = receipts(case)[0].read_text()
    assert 'int a;' not in text
    assert os.environ['RAPTOR_SESSION_TOKEN'] not in text
    assert receipts(case)[0].stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('raw', ['[]', 'null', '{', '{"tool_input":null}', '[' * 10000, ' ' * (1024 * 1024 + 1)])
def test_malformed_hook_input_is_a_quiet_noop(monkeypatch, capsys, raw):
    assert lifecycle_hook(raw, monkeypatch) is None
    assert capsys.readouterr() == ('', '')


def test_source_symlink_swap_does_not_relabel_observed_file(case):
    _, payload = fire(case)
    original = case[1]
    other = original.with_name('replacement.c')
    other.write_text('different source\n')
    original.unlink()
    original.symlink_to(other)
    reader.consume(payload)
    assert manifest(case) == [str(original)]


def test_source_directory_swap_is_refused_by_anchored_read(case, monkeypatch):
    # Resolve first, then replace an intermediate directory before the open.
    directory = case[1].parent / 'nested'
    directory.mkdir()
    source = directory / 'file.c'
    source.write_text('original\n')
    outside = directory.with_name('outside')
    outside.mkdir()
    (outside / 'file.c').write_text('replacement\n')
    original = reader.open_regular_beneath
    def swapped(root, path, mode):
        directory.rename(directory.with_name('moved'))
        directory.symlink_to(outside, target_is_directory=True)
        return original(root, path, mode)
    monkeypatch.setattr(reader, 'open_regular_beneath', swapped)
    code, payload = fire(case, [str(source)])
    assert code == 1 and payload['tool_response'] == ''
    assert receipts(case) == []


def test_outside_target_read_emits_content_but_earns_no_coverage(case, tmp_path):
    outside = tmp_path / 'outside-target'
    outside.mkdir()
    meta = case[2] / '.raptor-run.json'
    value = json.loads(meta.read_text())
    value['target_path'] = str(outside)
    meta.write_text(json.dumps(value))
    code, payload = fire(case)
    assert code == 0 and payload['tool_response'] == case[1].read_text()
    reader.consume(payload)
    assert manifest(case) == []


def test_changed_target_during_read_earns_no_coverage(case):
    _, payload = fire(case)
    meta = case[2] / '.raptor-run.json'
    value = json.loads(meta.read_text())
    value['target_path'] = ''
    meta.write_text(json.dumps(value))
    reader.consume(payload)
    assert manifest(case) == []


def test_output_budget_refuses_before_delivery(case):
    case[1].write_text('x' * (reader._MAX_OUTPUT_BYTES + 1))
    code, payload = fire(case)
    assert code == 1 and payload['tool_response'] == '' and receipts(case) == []


@pytest.mark.parametrize('words', [
    ['--start-line', '0'], ['--start-line', '3', '--end-line', '2'],
    ['--start-line', '-1'], ['--end-line', '2001'],
    ['--start-line', str(sys.maxsize + 1)], ['--end-line', str(sys.maxsize + 1)],
])
def test_invalid_ranges_do_not_emit_or_record(case, words):
    with pytest.raises(SystemExit) as error:
        fire(case, [str(case[1]), *words])
    assert error.value.code == 2 and receipts(case) == []


def test_receipt_failure_preserves_read_result(case, monkeypatch, capsys):
    def fail(*_args): raise OSError('sensitive detail')
    monkeypatch.setattr(reader, '_record', fail)
    code, payload = fire(case)
    assert code == 0 and payload['tool_response'] == case[1].read_text()
    assert receipts(case) == [] and 'sensitive detail' not in capsys.readouterr().err


def test_real_lifecycle_hook_dispatches_read_receipt_without_failure_marker(case, monkeypatch):
    _, payload = fire(case)
    lifecycle_hook(json.dumps(payload), monkeypatch)
    assert manifest(case) == [str(case[1])]
    assert not (case[2] / '.raptor-tool-failure').exists()


def test_receipt_budget_is_enforced_before_private_write(case):
    with pytest.raises(ValueError, match='IPC budget'):
        reader._record(str(case[1]), (str(case[2]), 'x' * reader._MAX_RECEIPT_BYTES),
                       'content', [str(environment.ROOT / 'libexec/raptor-read'), str(case[1])])
    assert receipts(case) == []


def test_line_selection_preserves_crlf_and_cr(case):
    case[1].write_bytes(b'first\r\nsecond\rthird\n')
    code, payload = fire(case, [str(case[1]), '--start-line', '2', '--end-line', '2'])
    assert code == 0 and payload['tool_response'] == 'second\r'
    reader.consume(payload)
    assert manifest(case) == [str(case[1])]


def test_separate_hook_processes_share_single_use_receipt(case):
    import subprocess
    from core.config import RaptorConfig
    _, payload = fire(case)
    child_env = RaptorConfig.get_safe_env()
    child_env.update({'HOME': os.environ['HOME'], '_RAPTOR_TRUSTED': '1',
                      'RAPTOR_CODEX_HOOK': '1', 'CODEX': '1'})
    def hook(_):
        return subprocess.run([sys.executable, '-I',
            str(environment.ROOT / 'libexec/raptor-lifecycle-hook'), 'codex-outcome'],
            env=child_env, input=json.dumps(payload), text=True,
            capture_output=True, timeout=15)
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(hook, range(2)))
    assert [(p.returncode, p.stdout, p.stderr) for p in results] == [(0, '', ''), (0, '', '')]
    assert manifest(case) == [str(case[1])]


@pytest.mark.parametrize('style', ['single', 'double', 'escaped'])
@pytest.mark.parametrize('relative', [
    'app/[slug]/page.tsx', 'star*.c', 'has?.c', 'cost$price.c', 'hash#tag.c',
    'tick`name.c', "apostrophe's.c",
])
def test_quoted_paths_reach_real_lifecycle_dispatch(case, monkeypatch, relative, style):
    from core.run.tests.test_literal_command import quote_word
    source = case[1].parent / relative
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text('int quoted_path;\n')
    code, payload = fire(case, [str(source)])
    assert code == 0 and len(receipts(case)) == 1
    payload['tool_input']['command'] = 'libexec/raptor-read ' + quote_word(str(source), style)
    lifecycle_hook(json.dumps(payload), monkeypatch)
    assert manifest(case) == [str(source)]
    assert receipts(case) == []

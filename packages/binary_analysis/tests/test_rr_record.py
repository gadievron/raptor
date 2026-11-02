"""Record and pack must scope writes and never follow trace-derived host roots."""
from pathlib import Path
import subprocess

import pytest

from core.sandbox import SandboxSetupError
from packages.binary_analysis import rr_record as module
from packages.binary_analysis import rr_cli

_REAL_VERIFY = module._verify_recording


@pytest.fixture
def setup(tmp_path, monkeypatch):
    home = tmp_path/'home'
    home.mkdir()
    root = tmp_path/'workspace'
    root.mkdir()
    binary = root/'owned target'
    binary.write_text('fixture')
    binary.chmod(0o700)
    monkeypatch.setenv('HOME', str(home))
    monkeypatch.setattr(module.RaptorConfig, 'get_safe_env', lambda: {'PATH': '/usr/bin:/bin'})
    monkeypatch.setattr(module, '_runtime', lambda *args, **kwargs: (Path('/usr/bin/rr'), None, ['/usr/bin']))
    monkeypatch.setattr(module, '_verify_recording', lambda *args: None)
    return home, root, binary


def _save_recording(command):
    trace = Path(command[3])
    trace.mkdir()
    (trace/'version').write_text('fixture')


@pytest.mark.parametrize('status', [0, 3, 139])
def test_record_preserves_target_exit_and_pins_stdin(setup, monkeypatch, status):
    _, root, binary = setup
    source = root/'input with spaces;$(false)'
    source.write_bytes(b'input witness')
    calls = []
    def dispatch(command, **kwargs):
        calls.append(kwargs)
        assert command == ['/usr/bin/rr', 'record', '-o', str(root/'trace'), str(binary), 'a b', '-o']
        assert kwargs['profile'] == 'rr'
        assert kwargs['output'] == str(root)
        assert not kwargs.get('target')
        assert not kwargs.get('readable_paths')
        assert kwargs['stdin'].read() == b'input witness'
        assert kwargs['cwd'] == str(root)
        _save_recording(command)
        return subprocess.CompletedProcess(command, status, b'output', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    result = module.record(root, 'trace', [str(binary), 'a b', '-o'], input_file=source)
    assert result.returncode == status
    assert calls[0]['stdin'].closed


def test_external_executable_gets_only_file_grant(setup, tmp_path, monkeypatch):
    _, root, binary = setup
    external = tmp_path/'external'
    external.mkdir()
    outside_binary = external/'target'
    outside_binary.write_text('fixture')
    outside_binary.chmod(0o700)
    link = root/'target-link'
    link.symlink_to(outside_binary)
    def dispatch(command, **kwargs):
        assert command[4] == str(link)
        assert kwargs['readable_paths'] == [str(outside_binary)]
        assert str(external) not in kwargs.get('tool_paths', [])
        _save_recording(command)
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    module.record(root, 'trace', ['./target-link'])


def test_relative_executable_and_cwd_follow_workspace(setup, monkeypatch):
    _, root, _ = setup
    subdir = root/'repo'
    subdir.mkdir()
    binary = subdir/'target'
    binary.write_text('fixture')
    binary.chmod(0o700)
    def dispatch(command, **kwargs):
        assert command[4] == str(binary)
        assert kwargs['cwd'] == str(subdir)
        assert kwargs['stdin'] == subprocess.DEVNULL
        _save_recording(command)
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, 'run', dispatch)
    module.record(root, 'trace', ['./target'], cwd='repo')


def test_pack_has_no_counter_or_ptrace_exception(setup, monkeypatch):
    _, root, _ = setup
    trace = root/'trace'
    trace.mkdir()
    (trace/'version').write_text('fixture')
    def dispatch(command, **kwargs):
        assert command == ['/usr/bin/rr', 'pack', str(trace)]
        assert kwargs['target'] == str(root)
        assert kwargs['output'] == str(trace)
        assert 'profile' not in kwargs
        assert not kwargs.get('writable_paths')
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, 'run_untrusted', dispatch)
    assert module.pack(root, trace).returncode == 0


@pytest.mark.parametrize('case', ['trace-outside', 'trace-root', 'trace-existing', 'stdin-outside', 'cwd-outside', 'home'])
def test_invalid_roots_refuse_before_dispatch(setup, tmp_path, monkeypatch, case):
    home, root, binary = setup
    trace = root/'trace'
    kwargs = {}
    error = (ValueError, FileExistsError, SandboxSetupError)
    if case == 'trace-outside':
        trace = tmp_path/'outside'
    elif case == 'trace-root':
        trace = root
    elif case == 'trace-existing':
        trace.mkdir()
    elif case == 'stdin-outside':
        source = tmp_path/'private'
        source.write_text('private')
        kwargs['input_file'] = source
    elif case == 'cwd-outside':
        kwargs['cwd'] = tmp_path
    else:
        root, trace = home, home/'trace'
    def forbidden(*args, **kwargs):
        raise AssertionError('invalid request dispatched')
    monkeypatch.setattr(module, 'run', forbidden)
    with pytest.raises(error):
        module.record(root, trace, [str(binary)], **kwargs)


@pytest.mark.parametrize('status', [0, 3, 139, -11])
def test_cli_record_success_means_verified_capture(setup, monkeypatch, capsys, status):
    _, root, binary = setup
    def dispatch(*args, **kwargs):
        result = subprocess.CompletedProcess([], status, b'', b'')
        result.recording_verified = True
        return result
    monkeypatch.setattr(rr_cli, 'record', dispatch)
    assert rr_cli.main(['record', '--workspace', str(root), '--trace', 'trace', '--', str(binary)]) == 0
    diagnostics = capsys.readouterr().err
    assert 'consistency check passed' in diagnostics
    if status:
        assert f'status {status}' in diagnostics


@pytest.mark.parametrize('flag', [False, None])
def test_cli_cannot_succeed_without_positive_verification(setup, monkeypatch, capsys, flag):
    _, root, binary = setup
    def dispatch(*args, **kwargs):
        result = subprocess.CompletedProcess([], 0, b'target output', b'')
        if flag is not None:
            result.recording_verified = flag
        return result
    monkeypatch.setattr(rr_cli, 'record', dispatch)
    assert rr_cli.main(['record', '--workspace', str(root), '--trace', 'trace', '--', str(binary)]) == 1
    assert 'no verified recording' in capsys.readouterr().err


@pytest.mark.parametrize('status,cli_status', [(0, 0), (3, 1), (139, 139), (-11, 139)])
def test_cli_plain_run_preserves_execution_status(setup, monkeypatch, status, cli_status):
    _, root, binary = setup
    monkeypatch.setattr(rr_cli, 'run_target', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], status, b'', b''))
    assert rr_cli.main(['run', '--workspace', str(root), '--', str(binary)]) == cli_status


def test_cli_setup_refusal_is_three(setup, monkeypatch):
    _, root, binary = setup
    def refuse(*args, **kwargs):
        raise SandboxSetupError('namespace unavailable')
    monkeypatch.setattr(rr_cli, 'record', refuse)
    assert rr_cli.main(['record', '--workspace', str(root), '--trace', 'trace', '--', str(binary)]) == 3


def test_plain_reproduction_is_confined_and_does_not_need_rr(setup, monkeypatch):
    _, root, binary = setup
    def no_rr(*args, **kwargs):
        raise AssertionError('plain reproduction must not load rr')
    def dispatch(command, **kwargs):
        assert command == [str(binary), 'argument']
        assert kwargs['output'] == str(root)
        assert kwargs['stdin'] == subprocess.DEVNULL
        assert 'profile' not in kwargs
        return subprocess.CompletedProcess(command, 0, b'', b'')
    monkeypatch.setattr(module, '_runtime', no_rr)
    monkeypatch.setattr(module, 'run_untrusted', dispatch)
    assert module.run_target(root, [str(binary), 'argument']).returncode == 0


def test_missing_trace_never_falls_back_to_plain_run(setup, monkeypatch):
    _, root, binary = setup
    def forbidden(*args, **kwargs):
        raise AssertionError('missing trace must not dispatch')
    monkeypatch.setattr(module, 'run_untrusted', forbidden)
    with pytest.raises(ValueError, match='new trace directory'):
        module.record(root, None, [str(binary)])


def test_recording_runtime_does_not_require_gdb(setup, monkeypatch):
    from packages.binary_analysis import rr_replay as runtime
    calls = []
    def which(name, **kwargs):
        calls.append(name)
        return '/usr/bin/rr' if name == 'rr' else None
    monkeypatch.setattr(runtime.shutil, 'which', which)
    binary, debugger, _ = runtime._runtime({'PATH': '/usr/bin:/bin'}, need_debugger=False)
    assert binary == Path('/usr/bin/rr')
    assert debugger is None
    assert calls == ['rr']


def test_sanitizer_mode_preserves_leaks_and_existing_floor(setup, monkeypatch):
    _, root, binary = setup
    def dispatch(command, **kwargs):
        assert command == [str(binary)]
        assert kwargs['profile'] == 'debug'
        assert kwargs['restrict_reads'] and kwargs['fake_home']
        assert 'require_fresh_procfs' in kwargs
        assert kwargs['omit_proc_reads'] is (not kwargs['require_fresh_procfs'])
        assert kwargs['block_network']
        assert kwargs['strict_env']
        assert 'detect_leaks=0' not in kwargs['env'].get('ASAN_OPTIONS', '')
        return subprocess.CompletedProcess(command, 1, b'', b'LeakSanitizer report')
    monkeypatch.setattr(module, 'run', dispatch)
    assert module.run_target(root, [str(binary)], sanitizer=True).returncode == 1


def test_zero_exit_without_recording_is_failure(setup, monkeypatch):
    _, root, binary = setup
    monkeypatch.setattr(module, 'run', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, b'', b''))
    with pytest.raises(RuntimeError, match='without saved recording'):
        module.record(root, 'trace', [str(binary)])


@pytest.mark.parametrize('phase', ['success', 'terminal', 'replay', 'fatal-zero'])
def test_verification_scopes_and_failures(setup, tmp_path, monkeypatch, phase):
    _, root, _ = setup
    trace = root/'trace'
    trace.mkdir()
    scratch = tmp_path/'chosen-scratch'
    scratch.mkdir()
    calls = []
    def dispatch(command, **kwargs):
        calls.append((command, kwargs))
        assert kwargs['target'] == str(root)
        assert kwargs['output'] != str(root)
        assert Path(kwargs['output']).parent == scratch
        assert kwargs['stdin'] == subprocess.DEVNULL
        assert kwargs['readable_paths'] == ['/selected/executable']
        assert not kwargs.get('writable_paths')
        assert 0 < kwargs['timeout'] <= 10
        if command[1] == 'dump':
            assert command == ['/usr/bin/rr', 'dump', str(trace), 'end']
            if phase == 'terminal':
                return subprocess.CompletedProcess(command, 0, b"event:`TRACE_TERMINATION'", b'')
            return subprocess.CompletedProcess(command, 0,
                b"  real_time:1 global_time:7, event:`EXIT' tid:2, ticks:0\n", b'')
        assert command == ['/usr/bin/rr', 'replay', '--autopilot', str(trace)]
        assert kwargs['profile'] == 'rr'
        return subprocess.CompletedProcess(command, 1 if phase == 'replay' else 0, b'',
            b'[FATAL source:1] inconsistent replay\n' if phase == 'fatal-zero' else b'')
    monkeypatch.setattr(module, 'run', dispatch)
    monkeypatch.setattr(module, 'run_untrusted', dispatch)
    result = _REAL_VERIFY(root, trace, Path('/usr/bin/rr'), ['/usr/bin'],
                         ['/selected/executable'], {'TMPDIR': str(scratch)},
                         module.time.monotonic()+10)
    assert (result is None) == (phase == 'success')
    assert len(calls) == (1 if phase == 'terminal' else 2)
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize('text', [False, True])
def test_invalid_recording_keeps_diagnostics_and_refuses_success(setup, monkeypatch, text):
    _, root, binary = setup
    def dispatch(command, **kwargs):
        _save_recording(command)
        return subprocess.CompletedProcess(command, 139,
            'target output' if text else b'target output',
            'target error' if text else b'target error')
    monkeypatch.setattr(module, 'run', dispatch)
    monkeypatch.setattr(module, '_verify_recording', lambda *args: 'inconsistent replay')
    result = module.record(root, 'trace', [str(binary)])
    assert result.returncode == 1
    assert result.recording_verified is False
    assert result.stdout == ('target output' if text else b'target output')
    message = result.stderr if text else result.stderr.decode()
    assert 'target error' in message
    assert 'original status 139' in message
    assert 'inconsistent replay' in message
    assert (root/'trace'/'version').exists()


def test_verification_timeout_never_returns_a_verified_recording(setup, monkeypatch):
    _, root, binary = setup
    def dispatch(command, **kwargs):
        _save_recording(command)
        return subprocess.CompletedProcess(command, 0, b'target output', b'')
    def expired(*args):
        raise subprocess.TimeoutExpired(['rr', 'verify'], 0)
    monkeypatch.setattr(module, 'run', dispatch)
    monkeypatch.setattr(module, '_verify_recording', expired)
    result = module.record(root, 'trace', [str(binary)])
    assert result.returncode == 1
    assert result.recording_verified is False
    assert result.stdout == b'target output'
    assert b'timeout budget' in result.stderr


@pytest.mark.parametrize('binary_output', [False, True])
def test_cli_escapes_hostile_captured_output(setup, monkeypatch, capsys, binary_output):
    _, root, binary = setup
    hostile = 'first\n\x1b]52;c;payload\x07\r\u202eend\n'
    output = hostile.encode() if binary_output else hostile
    monkeypatch.setattr(rr_cli, 'run_target', lambda *args, **kwargs:
                        subprocess.CompletedProcess([], 0, output, output))
    assert rr_cli.main(['run', '--workspace', str(root), '--', str(binary)]) == 0
    captured = capsys.readouterr()
    for rendered in (captured.out, captured.err):
        assert rendered.startswith('first\n') and rendered.endswith('end\n')
        assert '\x1b' not in rendered and '\x07' not in rendered
        assert '\r' not in rendered and '\u202e' not in rendered
        assert 'payload' in rendered


def test_cli_bounds_captured_output():
    rendered = rr_cli._term('x' * 100000)
    assert len(rendered) < 5000
    assert 'omitted' in rendered


def test_cli_sanitises_exception_diagnostics(setup, monkeypatch, capsys):
    _, root, binary = setup
    def refuse(*args, **kwargs):
        raise SandboxSetupError('bad path \x1b[2J\r')
    monkeypatch.setattr(rr_cli, 'run_target', refuse)
    assert rr_cli.main(['run', '--workspace', str(root), '--', str(binary)]) == 3
    error = capsys.readouterr().err
    assert 'bad path' in error and '\x1b' not in error and '\r' not in error

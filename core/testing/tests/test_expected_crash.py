"""Real signal containment, strict attribution, output, and owned-child cleanup."""
import os
import signal
import sys

import pytest

from core.testing.expected_crash import ExpectedCrashError


def command(marker, suffix):
    return [sys.executable, '-c',
            f'from pathlib import Path; import os, signal; '
            f'Path({str(marker)!r}).touch(); {suffix}']


@pytest.mark.parametrize('sig', [signal.SIGABRT, signal.SIGSEGV], ids=['abort', 'segfault'])
def test_expected_signal_is_observed_without_forwarding(tmp_path, expected_crash_runner, sig):
    marker = tmp_path / 'entered'
    result = expected_crash_runner(command(marker, f'os.kill(os.getpid(), {int(sig)})'),
                                   expected_signal=sig, ready_file=marker)
    assert result.observed_signal == sig
    assert result.process.returncode == -signal.SIGKILL
    assert result.trace['ready'] is True
    with pytest.raises(ProcessLookupError):
        os.kill(result.trace['pid'], 0)


def test_stdout_stderr_and_stdin_survive(tmp_path, expected_crash_runner):
    marker = tmp_path / 'entered'
    code = ('import sys; print(sys.stdin.buffer.read().decode(), flush=True); '
            'print("diagnostic", file=sys.stderr, flush=True); os.abort()')
    result = expected_crash_runner(command(marker, code), ready_file=marker, input=b'payload')
    assert result.process.stdout == b'payload\n'
    assert result.process.stderr == b'diagnostic\n'


@pytest.mark.parametrize('suffix,pattern', [
    ('os._exit(0)', 'expected SIGABRT'),
    ('os._exit(23)', 'expected SIGABRT'),
    ('os.kill(os.getpid(), signal.SIGSEGV)', 'expected SIGABRT'),
    ('os.kill(os.getpid(), signal.SIGTRAP)', 'expected SIGABRT'),
], ids=['clean-exit', 'nonzero-exit', 'unexpected-signal', 'trap-after-ready'])
def test_other_outcomes_fail_visibly(tmp_path, expected_crash_runner, suffix, pattern):
    marker = tmp_path / 'entered'
    with pytest.raises(ExpectedCrashError, match=pattern):
        expected_crash_runner(command(marker, suffix), ready_file=marker)


def test_signal_before_fixture_readiness_is_not_success(tmp_path, expected_crash_runner):
    with pytest.raises(ExpectedCrashError, match='expected SIGABRT'):
        expected_crash_runner([sys.executable, '-c', 'import os; os.abort()'],
                              ready_file=tmp_path / 'never-created')


def test_stale_readiness_marker_is_refused(tmp_path, expected_crash_runner):
    marker = tmp_path / 'already-exists'
    marker.touch()
    with pytest.raises(ValueError, match='already exists'):
        expected_crash_runner([sys.executable, '-c', 'pass'], ready_file=marker)


def test_hanging_fixture_times_out_and_is_reaped(tmp_path, expected_crash_runner):
    marker = tmp_path / 'entered'
    pid_file = tmp_path / 'pid'
    suffix = f'Path({str(pid_file)!r}).write_text(str(os.getpid())); import time; time.sleep(30)'
    with pytest.raises(ExpectedCrashError, match="'timed_out': True"):
        expected_crash_runner(command(marker, suffix), ready_file=marker, timeout=1)
    pid = int(pid_file.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_failed_exec_is_not_an_expected_crash(tmp_path, expected_crash_runner):
    with pytest.raises(ExpectedCrashError, match='exec'):
        expected_crash_runner([str(tmp_path / 'missing-executable')])

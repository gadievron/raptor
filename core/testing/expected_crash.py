"""Contain expected fatal signals in owned test children on Linux and macOS.

This is test scaffolding, never a RAPTOR execution backend. The tracer
records the attempted fatal signal, then kills the stopped child with
SIGKILL before a desktop crash reporter handles it. The real final status
remains -SIGKILL; no return status or RAPTOR evidence is forged.

Use only for a direct, test-owned child. Tests of raw sandbox wait status
must run unwrapped under the intentional_crash opt-in instead.
"""
from __future__ import annotations

import argparse
import ctypes
from dataclasses import dataclass
import json
import math
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import tempfile
import time

_FATAL = {signal.SIGABRT, signal.SIGSEGV, signal.SIGBUS, signal.SIGFPE, signal.SIGILL}


@dataclass(frozen=True)
class ExpectedCrashResult:
    process: subprocess.CompletedProcess
    observed_signal: int
    trace: dict


class ExpectedCrashError(AssertionError):
    """The expected signal was not observed, or containment failed."""


def _trace(command, deadline, ready_file):
    """CLI-only tracer: fork in a fresh, single-threaded interpreter."""
    libc = ctypes.CDLL('/usr/lib/libSystem.B.dylib' if sys.platform == 'darwin' else None,
                       use_errno=True)
    libc.ptrace.restype = ctypes.c_long if sys.platform == 'linux' else ctypes.c_int
    libc.ptrace.argtypes = [ctypes.c_uint, ctypes.c_int, ctypes.c_void_p,
                           ctypes.c_void_p if sys.platform == 'linux' else ctypes.c_int]

    def ptrace(request, pid=0, address=None, data=0):
        if libc.ptrace(request, pid, address, data) == -1:
            code = ctypes.get_errno()
            raise OSError(code, os.strerror(code))

    read_fd, write_fd = os.pipe()  # non-inheritable, so successful exec closes it
    pid = os.fork()
    if pid == 0:
        os.close(read_fd)
        stage = 'ptrace'
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            ptrace(0)  # PT_TRACE_ME / PTRACE_TRACEME
            stage = 'exec'
            os.execvpe(command[0], command, os.environ)
        except BaseException as exc:
            error = {'stage': stage, 'errno': getattr(exc, 'errno', None), 'message': str(exc)}
            os.write(write_fd, json.dumps(error).encode()[:4000])
            os._exit(125)

    os.close(write_fd)
    result = {'pid': pid, 'stops': [], 'observed_signal': None, 'returncode': None,
              'timed_out': False, 'error': None}
    reaped = False
    first_stop = True
    try:
        while time.monotonic() < deadline:
            found, status = os.waitpid(pid, os.WNOHANG | os.WUNTRACED)
            if not found:
                time.sleep(0.005)
                continue
            if os.WIFSTOPPED(status):
                sig = os.WSTOPSIG(status)
                result['stops'].append(sig)
                if len(result['stops']) > 32:
                    raise RuntimeError('too many ptrace stops in an owned crash fixture')
                if first_stop and sys.platform == 'linux':
                    ptrace(0x4200, pid, None, 0x00100000)  # SETOPTIONS: EXITKILL
                first_stop = False
                # macOS's venv launcher may exec a second interpreter. Once
                # the fixture's readiness marker exists, a SIGTRAP is no
                # longer an exec-startup stop and must fail visibly.
                startup_trap = sig == signal.SIGTRAP and not (
                    ready_file and Path(ready_file).exists())
                if startup_trap:
                    ptrace(7, pid, 1, 0)
                    continue
                result['observed_signal'] = sig
                result['ready'] = not ready_file or Path(ready_file).exists()
                # Do not forward even an unexpected fatal signal to the OS.
                # The caller must assert which signal was actually observed.
                ptrace(8, pid)  # PT_KILL / PTRACE_KILL
            elif os.WIFEXITED(status) or os.WIFSIGNALED(status):
                result['returncode'] = os.waitstatus_to_exitcode(status)
                reaped = True
                break
        if not reaped:
            result['timed_out'] = True
    except BaseException as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    finally:
        if not reaped:
            try:
                os.kill(pid, signal.SIGKILL)
                _, status = os.waitpid(pid, 0)
                result['returncode'] = os.waitstatus_to_exitcode(status)
            except (ProcessLookupError, ChildProcessError):
                pass
        setup = os.read(read_fd, 4096)
        os.close(read_fd)
        if setup:
            result['setup_error'] = json.loads(setup)
    return result


def _invoke(command, *, timeout, ready_file=None, cwd=None, env=None,
            input=None, text=False, encoding=None, errors=None):
    if sys.platform not in {'linux', 'darwin'}:
        raise ExpectedCrashError('expected-crash tracing requires Linux or macOS')
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError('timeout must be positive and finite')
    if not command:
        raise ValueError('command is empty')
    with tempfile.TemporaryDirectory(prefix='raptor-expected-crash-') as scratch:
        report = Path(scratch) / 'trace.json'
        argv = [sys.executable, '-I', str(Path(__file__).resolve()),
                '--report', str(report), '--timeout', str(timeout)]
        if ready_file is not None:
            ready_file = Path(ready_file).absolute()
            if ready_file.exists():
                raise ValueError('readiness marker already exists; use a fresh fixture path')
            argv += ['--ready-file', str(ready_file)]
        argv += ['--', *map(os.fspath, command)]
        proc = subprocess.Popen(argv, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=text, encoding=encoding, errors=errors,
                                start_new_session=True)
        try:
            stdout, stderr = proc.communicate(input=input, timeout=timeout + 5)
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGKILL)  # this invocation's private group
            except ProcessLookupError:
                pass
            proc.communicate()
            raise
        if proc.returncode or not report.is_file():
            raise ExpectedCrashError(f'crash tracer failed ({proc.returncode}): {stderr!r}')
        data = json.loads(report.read_text())
    return subprocess.CompletedProcess(command, data['returncode'], stdout, stderr), data


def trace_unavailable_reason():
    """Non-crashing capability probe; a failed real trace never counts as a pass."""
    try:
        proc, data = _invoke([sys.executable, '-c', 'pass'], timeout=10)
    except (OSError, ExpectedCrashError) as exc:
        return str(exc)
    setup = data.get('setup_error')
    if setup or data['error'] or data['timed_out'] or proc.returncode or not data['stops']:
        return f'owned-child ptrace unavailable: {setup or data}'
    return None


def run_expected_crash(command, *, expected_signal=signal.SIGABRT, timeout=10,
                       ready_file=None, **kwargs):
    """Run an owned fixture and require a specific intercepted fatal signal.

    The result contains the actual SIGKILL status, captured stdout/stderr,
    and a separate observed_signal. No native wait-status claim is made.
    A fresh ready_file written just before the fatal operation also rules
    out a matching signal from interpreter/fixture startup.
    """
    if expected_signal not in _FATAL:
        raise ValueError('expected_signal must be ABRT, SEGV, BUS, FPE, or ILL')
    proc, data = _invoke(command, timeout=timeout,
                         ready_file=ready_file, **kwargs)
    if (data.get('setup_error') or data['error'] or data['timed_out']
            or data['observed_signal'] != expected_signal
            or proc.returncode != -signal.SIGKILL or not data.get('ready')):
        raise ExpectedCrashError(f'expected {signal.Signals(expected_signal).name}; trace={data}; '
                                 f'stderr={proc.stderr!r}')
    return ExpectedCrashResult(proc, data['observed_signal'], data)


def _main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--report', required=True)
    parser.add_argument('--timeout', type=float, default=10)
    parser.add_argument('--ready-file')
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command or sys.platform not in {'linux', 'darwin'}:
        parser.error('supply an owned command on Linux or macOS')
    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error('timeout must be positive and finite')
    data = _trace(command, time.monotonic() + args.timeout, args.ready_file)
    Path(args.report).write_text(json.dumps(data))


if __name__ == '__main__':
    _main()

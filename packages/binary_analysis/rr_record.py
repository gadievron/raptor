"""Contained crash reproduction, rr recording and trace packing."""
from contextlib import ExitStack
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
from typing import IO

from core.config import RaptorConfig
from core.sandbox import run, run_untrusted, SandboxSetupError
from core.sandbox.python_paths import _home_roots
from core.source import open_regular_beneath
from packages.binary_analysis.rr_replay import _runtime
from packages.binary_analysis._execution_policy import crash_execution_policy


def _workspace(path) -> Path:
    root = Path(path).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('rr workspace must be a directory')
    if any(root == home or root in home.parents for home in _home_roots()):
        raise SandboxSetupError('rr requires a dedicated workspace, not HOME or its ancestors')
    return root


def _trace(root: Path, path, *, existing: bool) -> Path:
    trace = Path(path)
    if not trace.is_absolute():
        trace = root/trace
    trace = trace.resolve(strict=existing)
    if trace == root or not trace.is_relative_to(root):
        raise ValueError('rr trace must be a dedicated directory beneath the workspace')
    if existing:
        if not trace.is_dir() or not (trace/'version').is_file():
            raise ValueError('selected directory is not an rr recording')
    elif trace.exists():
        raise FileExistsError('rr trace already exists; select a new trace directory')
    elif not trace.parent.is_dir():
        raise FileNotFoundError('rr trace parent directory must already exist')
    return trace


def _verification_error(result):
    output = result.stderr or b''
    text = output.decode(errors='replace') if isinstance(output, bytes) else output
    if result.returncode != 0 or any(line.startswith('[FATAL ') for line in text.splitlines()):
        return text or f'exited with status {result.returncode}'
    return None


def _verify_recording(root, trace, binary, tools, reads, env, deadline):
    """Check a terminal exit and replay consistency under confined policies.

    This validates replayability, not provenance: the trace remains
    attacker-influenced input and never supplies extra filesystem grants.
    """
    def remaining():
        if deadline is None:
            return None
        value = deadline-time.monotonic()
        if value <= 0:
            raise subprocess.TimeoutExpired([str(binary), 'verify', str(trace)], 0)
        return value
    with tempfile.TemporaryDirectory(prefix='raptor-rr-verify-',
            dir=env.get('TMPDIR') or tempfile.gettempdir()) as scratch:
        options = dict(target=str(root), output=scratch, tool_paths=tools,
                       readable_paths=reads or None,
                       cwd=scratch, env=env, stdin=subprocess.DEVNULL, capture_output=True)
        terminal = run_untrusted([str(binary), 'dump', str(trace), 'end'],
                                 timeout=remaining(), **options)
        failure = _verification_error(terminal)
        if failure:
            return 'terminal event check failed:\n'+failure
        output = terminal.stdout or b''
        text = output.decode(errors='replace') if isinstance(output, bytes) else output
        if len(text) > 16384 or not any(line.lstrip().startswith('real_time:')
                and ", event:`EXIT' tid:" in line for line in text.splitlines()):
            return 'trace has no terminal EXIT event; retained recording may be incomplete'
        replayed = run([str(binary), 'replay', '--autopilot', str(trace)],
                       profile='rr', timeout=remaining(), **options)
        failure = _verification_error(replayed)
        if failure:
            return 'replay consistency check failed:\n'+failure
    return None


def _execute_target(workspace, command: list[str], *, input_file=None, cwd=None,
                    timeout=120, trace_dir=None, sanitizer=False):
    root = _workspace(workspace)
    trace = _trace(root, trace_dir, existing=False) if trace_dir is not None else None
    directory = Path(cwd) if cwd is not None else root
    if not directory.is_absolute():
        directory = root/directory
    directory = directory.resolve(strict=True)
    if not directory.is_dir() or not directory.is_relative_to(root):
        raise ValueError('rr cwd must be a directory beneath the workspace')
    if not command or isinstance(command, str) or not all(isinstance(arg, str) for arg in command):
        raise ValueError('target execution requires an executable and an argument list')
    env = RaptorConfig.get_safe_env()
    binary, tools = None, []
    if trace is not None:
        binary, _, tools = _runtime(env, need_debugger=False)
    executable = Path(command[0])
    if os.sep in command[0]:
        if not executable.is_absolute():
            executable = directory/executable
    else:
        # PATH entries relative to cwd refer to the chosen workspace, not
        # the launcher's cwd. Pin one executable; never reconstruct a shell.
        search = os.pathsep.join(str(Path(item) if Path(item).is_absolute() else directory/item)
                                 for item in env.get('PATH', os.defpath).split(os.pathsep))
        found = shutil.which(command[0], path=search)
        if not found:
            raise FileNotFoundError('recording executable not found')
        executable = Path(found)
    executable = executable.absolute()
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise PermissionError('recording executable must be an executable regular file')
    reads = []
    # External executables get a FILE grant, never their parent directory.
    # Repository-controlled symlinks cannot widen access to HOME directories.
    for path in (executable, executable.resolve(strict=True)):
        if not path.is_relative_to(root) and str(path) not in reads:
            reads.append(str(path))
    env.pop('RR_TMPDIR', None)
    with ExitStack() as stack:
        stdin: int | IO[bytes] = subprocess.DEVNULL
        if input_file is not None:
            source = Path(input_file)
            if not source.is_absolute():
                source = root/source
            source = source.resolve(strict=True)
            if not source.is_relative_to(root):
                raise ValueError('rr stdin file must be beneath the workspace')
            handle = open_regular_beneath(root, source.relative_to(root), 'rb')
            if handle is None:
                raise ValueError('rr stdin must be a readable regular workspace file')
            stdin = stack.enter_context(handle)
        options = dict(output=str(root), readable_paths=reads or None,
                       tool_paths=tools, cwd=str(directory), env=env, stdin=stdin,
                       capture_output=True, timeout=timeout)
        arguments = [str(executable), *command[1:]]
        if trace is not None:
            deadline = time.monotonic()+timeout if timeout is not None else None
            result = run([str(binary), 'record', '-o', str(trace), *arguments],
                         profile='rr', **options)
            setattr(result, "recording_verified", False)
            marker = open_regular_beneath(root, trace.relative_to(root)/'version', 'rb')
            if marker is None:
                if result.returncode == 0:
                    raise RuntimeError('rr returned success without saved recording metadata')
                return result
            marker.close()
            try:
                failure = _verify_recording(root, trace, binary, tools, reads, env, deadline)
            except subprocess.TimeoutExpired:
                failure = 'verification exceeded the recording timeout budget'
            if failure:
                message = ('\nrr: recording verification failed (original status '
                           +str(result.returncode)+'); trace retained for diagnosis:\n'+failure+'\n')
                stderr = result.stderr
                result.stderr = (stderr+message if isinstance(stderr, str)
                                 else (stderr or b'')+message.encode())
                result.returncode = 1
            else:
                setattr(result, "recording_verified", True)
            return result
        if sanitizer:
            # LSan stops its own threads with ptrace. Use the established
            # debugger policy and untrusted floor, not weaker global filters
            # or detect_leaks=0 (which would hide the finding).
            return run(arguments, profile='debug', **crash_execution_policy(root), **options)
        return run_untrusted(arguments, **options)


def run_target(workspace, command: list[str], *, input_file=None, cwd=None, timeout=120, sanitizer=False):
    """Reproduce without instrumentation, under the normal untrusted policy."""
    return _execute_target(workspace, command, input_file=input_file, cwd=cwd,
                           timeout=timeout, sanitizer=sanitizer)


def record(workspace, trace_dir, command: list[str], *, input_file=None, cwd=None, timeout=120):
    """Verify saved recordings before preserving their rr/target exit status."""
    if trace_dir is None:
        raise ValueError('record requires a new trace directory')
    return _execute_target(workspace, command, input_file=input_file, cwd=cwd,
                           timeout=timeout, trace_dir=trace_dir)


def pack(workspace, trace_dir, *, timeout=120):
    """Read only the declared workspace/runtime; modify only the trace."""
    root = _workspace(workspace)
    trace = _trace(root, trace_dir, existing=True)
    env = RaptorConfig.get_safe_env()
    binary, _, tools = _runtime(env, need_debugger=False)
    env.pop('RR_TMPDIR', None)
    # Packing parses trace-supplied paths. It needs no ptrace or counters;
    # use the normal untrusted policy rather than widening its syscall set.
    return run_untrusted([str(binary), 'pack', str(trace)],
                         target=str(root), output=str(trace), tool_paths=tools,
                         cwd=str(trace), env=env, capture_output=True, timeout=timeout)

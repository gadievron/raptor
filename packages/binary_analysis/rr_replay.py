"""Replay packed rr recordings inside a dedicated Linux sandbox."""
from pathlib import Path
import os
import shutil
import sys
import tempfile

from core.config import RaptorConfig
from core.sandbox import run, SandboxSetupError
from core.sandbox.python_paths import _home_roots


def replay(trace_dir=None, *, commands: bytes | None = None, timeout=60):
    """Use private scratch and the dedicated rr containment policy."""
    if sys.platform != 'linux':
        raise SandboxSetupError('rr replay requires Linux')
    if trace_dir is None:
        base = os.environ.get('_RR_TRACE_DIR')
        if not base:
            base = str(Path(os.environ.get('XDG_DATA_HOME') or Path.home()/'.local'/'share')/'rr')
        trace_dir = Path(base)/'latest-trace'
    trace = Path(trace_dir).resolve(strict=True)
    if not trace.is_dir():
        raise ValueError('rr recording must be a directory')
    if any(trace == home or trace in home.parents for home in _home_roots()):
        raise SandboxSetupError('rr requires a dedicated recording directory, not HOME or its ancestors')
    if not (trace/'version').is_file():
        raise ValueError('selected directory is not an rr recording (missing version file)')
    env = RaptorConfig.get_safe_env()
    binary = shutil.which('rr', path=env.get('PATH', os.defpath))
    if not binary:
        raise FileNotFoundError('rr not installed')
    binary = Path(binary).resolve()
    debugger = shutil.which('gdb', path=env.get('PATH', os.defpath))
    if not debugger:
        raise FileNotFoundError('GDB not installed')
    debugger = Path(debugger).resolve()
    tools = [binary.parent, debugger.parent]
    for executable, name in ((binary, 'rr'), (debugger, 'gdb')):
        for relative in ('lib/'+name, 'lib64/'+name, 'share/'+name):
            resource = executable.parent.parent/relative
            if resource.is_dir():
                tools.append(resource)
    if any(path.resolve() == home or path.resolve() in home.parents
           for path in tools for home in _home_roots()):
        raise SandboxSetupError('rr runtime must use a dedicated tool directory, not HOME')
    command = [str(binary), 'replay', '--serve-files',
               '--debugger='+str(debugger), str(trace), '--',
               '-nx', '-iex', 'set auto-load off',
               '-iex', 'set auto-load python-scripts off',
               '-iex', 'set auto-load safe-path /dev/null']
    # RR_TMPDIR overrides TMPDIR inside rr. Omit the inherited override so
    # rr uses the trusted per-run TMPDIR selected after namespace setup.
    env.pop('RR_TMPDIR', None)
    with tempfile.TemporaryDirectory(prefix='raptor-rr-replay-',
            dir=env.get('TMPDIR') or tempfile.gettempdir()) as scratch:
        kwargs = dict(profile='rr', target=str(trace), output=scratch,
                      tool_paths=list(dict.fromkeys(str(path) for path in tools)), cwd=scratch,
                      env=env, timeout=timeout, start_new_session=True)
        if commands is not None:
            kwargs.update(input=commands, capture_output=True)
        else:
            kwargs.update(stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr)
        result = run(command, **kwargs)
        # rr can return GDB's zero status after its replay server aborts.
        # Captured automation must not promote a fatal/divergent replay to
        # successful evidence merely because GDB handled remote EOF cleanly.
        if commands is not None and result.returncode == 0:
            stderr = result.stderr or b''
            marker = b'[FATAL ' if isinstance(stderr, bytes) else '[FATAL '
            if any(line.startswith(marker) for line in stderr.splitlines()):
                result.returncode = 1
        return result

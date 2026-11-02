"""Containment for crash targets, including inferiors launched by debuggers."""
import sys
from pathlib import Path


def crash_execution_policy(directory) -> dict:
    from core.sandbox.python_paths import _home_roots
    nominal = Path(directory).absolute()
    resolved = nominal.resolve()
    if any(path == home or path in home.parents
           for path in (nominal, resolved) for home in _home_roots()):
        from core.sandbox import SandboxSetupError
        raise SandboxSetupError('Crash replay requires a dedicated target directory, '
                         'not HOME or its ancestors; stage the binary in a working directory')
    # Debuggers need ptrace, so run_untrusted(profile='debug') is deliberately
    # unavailable. Use the same floor resolver as the other target-execution
    # consumers while retaining the debugger's narrow seccomp exception.
    from core.sandbox.context import untrusted_fresh_procfs_required
    fresh = untrusted_fresh_procfs_required()
    policy = dict(
        block_network=True,
        require_fresh_procfs=fresh,
        omit_proc_reads=not fresh,
        restrict_reads=True,
        fake_home=True,
        strict_env=True,
        strip_trust_markers=True,
        start_new_session=True,
    )
    if sys.platform == 'darwin':
        policy['exclude_tmp_baseline'] = True
    return policy


def gdb_command(script, binary) -> list[str]:
    """Disable implicit scripts before GDB loads attacker-controlled symbols."""
    return ['gdb', '-nx', '-batch', '-iex', 'set auto-load off',
            '-iex', 'set startup-with-shell off', '-x', str(script), str(binary)]


def lldb_command(script, binary) -> list[str]:
    """Skip init files and symbol-associated scripts before loading the target."""
    return ['lldb', '--no-lldbinit', '-b', '-O',
            'settings set target.load-script-from-symbol-file false',
            '-s', str(script), str(binary)]


def lldb_path(path) -> str:
    """Quote a path for an LLDB command file without admitting new commands."""
    value = str(path)
    if any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('LLDB redirect paths must not contain control characters')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

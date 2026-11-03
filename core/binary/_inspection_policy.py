"""Read boundaries for trusted parsers consuming untrusted binary bytes."""
from pathlib import Path


def inspection_options(binary, tool: str, scratch: str) -> dict:
    """Admit the input directory and declared tool runtime, never ambient HOME.

    Keep sibling debug files readable, but refuse a loose binary whose parent
    would admit HOME, an ancestor, or the shared temporary base. System inputs
    already live in the sandbox baseline and need no additional directory bind.
    """
    from core.sandbox import SandboxSetupError
    from core.sandbox.context import untrusted_fresh_procfs_required
    from core.sandbox.python_paths import _home_roots, _under_system_prefix, python_tool_paths
    from core.security.env_sanitisation import subprocess_tmpdir
    reads = []
    if binary is not None:
        parent = Path(binary).resolve().parent
        if any(parent == home or parent in home.parents for home in _home_roots()):
            raise SandboxSetupError('Binary inspection requires a dedicated input directory, not HOME or its ancestors')
        base = subprocess_tmpdir()
        shared = {Path(path).resolve() for path in ('/tmp', '/var/tmp', '/dev/shm')}
        if base:
            shared.add(Path(base).resolve())
        if parent in shared:
            raise SandboxSetupError('Binary inspection requires a dedicated input directory, not the shared temporary base')
        if not _under_system_prefix(str(parent)):
            reads.append(str(parent))
    fresh = untrusted_fresh_procfs_required()
    return dict(
        target=scratch, output=scratch, cwd=scratch,
        readable_paths=reads, tool_paths=python_tool_paths(tool),
        block_network=True, restrict_reads=True, fake_home=True,
        strict_env=True, strip_trust_markers=True, exclude_tmp_baseline=True,
        require_fresh_procfs=fresh, omit_proc_reads=not fresh,
        _untrusted_workload=True,
    )


def inspection_command(argv: list[str], scratch: str) -> list[str]:
    """Pin the admitted workspace after sanitisation and HOME relocation.

    fake_home=True creates these directories in output. Keep using those
    writable paths even when the namespace lane stages a second HOME in
    private /tmp, whose grants this inspection policy deliberately excludes.
    """
    home = str(Path(scratch) / '.home')
    return ['/usr/bin/env', 'TMPDIR=' + scratch, 'TEMP=' + scratch,
            'TMP=' + scratch, 'HOME=' + home,
            'XDG_CONFIG_HOME=' + home + '/.config',
            'XDG_CACHE_HOME=' + home + '/.cache',
            'XDG_DATA_HOME=' + home + '/.local/share',
            'XDG_STATE_HOME=' + home + '/.local/state', *argv]

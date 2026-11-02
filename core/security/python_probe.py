"""Run installed Python dependency probes without importing from target cwd."""
from __future__ import annotations

import os
import subprocess

from core.security.env_sanitisation import safe_subprocess_env


def run_python_probe(executable: str, source: str, *arguments: str,
                     timeout: float, tmpdir: str | None = None) -> subprocess.CompletedProcess:
    """Probe installed dependencies, retaining normal user-site support.

    A neutral cwd removes the target's implicit search entry. -E ignores
    Python startup environment overrides without disabling user packages.
    Use -E rather than -I/-P here because a tool's separate interpreter
    may predate Python 3.11. The interpreter and source are trusted caller
    choices; this is not an API for executing untrusted Python code.
    """
    env = safe_subprocess_env(strip_target_markers=True)
    if tmpdir is not None:
        # Symbolic workers pin tempfile.tempdir to their private write grant.
        # The effective value must cross exec even if ambient TMPDIR differs.
        env['TMPDIR'] = tmpdir
    return subprocess.run(
        [executable, '-E', '-c', source, *arguments],
        cwd=os.sep, env=env, input=b'', stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, timeout=timeout,
    )

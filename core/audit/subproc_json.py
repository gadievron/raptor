"""Sandboxed, resource-limited JSON children for SMT/Z3 verification.

Only the two audited dispatchers may run. Source and vocabulary arrive as
bounded data; they never authorize host filesystem grants. Worker failures
return None so callers remain inconclusive. Isolation refusals propagate.
"""
from __future__ import annotations

import logging
import math
from pathlib import Path
import site
import subprocess
import sys
import tempfile
from typing import Any

from core.audit._json_protocol import ALLOWED_ENTRIES, MAX_REQUEST_BYTES, MAX_REPLY_BYTES, decode, encode
from core.sandbox import run as _sandbox_run

from core.security.log_sanitisation import escape_nonprintable

logger = logging.getLogger(__name__)
_CHILD_SCRIPT_PATH = str(Path(__file__).resolve().with_name('_json_child.py'))
_MEMORY_MB = 2048


def run_json_child(entry: str, request: Any, *, env: dict, timeout: int = 10, label: str = '') -> Any:
    """Run one bounded request under the shared untrusted containment floor.

    env is filtered to the safe baseline; code roots come from this module,
    never RAPTOR_DIR or a path carried by the request. User-site hooks run
    only inside confinement. There is no in-process or bare spawn fallback.
    """
    from core.binary._inspection_policy import inspection_command, inspection_options
    from core.config import RaptorConfig
    from core.sandbox import SandboxSetupError
    from core.sandbox.python_paths import _home_roots, python_runtime_tool_paths
    from core.security.env_sanitisation import subprocess_tmpdir
    tag = escape_nonprintable(label or entry)
    if entry not in ALLOWED_ENTRIES:
        return None
    try:
        if not math.isfinite(timeout) or timeout <= 0 or timeout > 300:
            return None
        request_bytes = encode(request, MAX_REQUEST_BYTES)
    except (TypeError, ValueError, RecursionError, OverflowError):
        logger.debug('SMT child request refused')
        return None
    root = Path(__file__).resolve().parents[2]
    paths = [str(root / 'core'), str(root / 'packages'), *python_runtime_tool_paths()]
    user_site = site.getusersitepackages()
    if not isinstance(user_site, str) or not Path(user_site).is_dir():
        user_site = ''
    if user_site:
        paths.append(str(Path(user_site).resolve()))
    if any(Path(path).resolve() == home or Path(path).resolve() in home.parents
           for path in paths for home in _home_roots()):
        raise SandboxSetupError('SMT runtime requires dedicated code directories, not HOME or its ancestors')
    # A caller can narrow/customise safe values, but cannot introduce arbitrary
    # environment names, Python search paths, credentials or framework markers.
    safe = RaptorConfig.get_safe_env()
    child_env = {name: env.get(name, value) for name, value in safe.items()}
    child_env = RaptorConfig.strip_target_exec_markers(RaptorConfig.strip_llm_env_vars(child_env))
    cpu = max(1, math.ceil(timeout))
    try:
        with tempfile.TemporaryDirectory(prefix='raptor-smt-child-', dir=subprocess_tmpdir()) as scratch:
            policy = inspection_options(None, sys.executable, scratch)
            policy['tool_paths'] = list(dict.fromkeys([*policy['tool_paths'], *paths, _CHILD_SCRIPT_PATH]))
            command = inspection_command([sys.executable, '-I', '-B', _CHILD_SCRIPT_PATH,
                                          entry, user_site, str(_MEMORY_MB), str(cpu)], scratch)
            # Anonymous owned files avoid unbounded pipe buffering in backend
            # subprocess implementations. FSIZE bounds child-written storage;
            # only cap+1 stdout bytes and a diagnostic tail enter the parent.
            with tempfile.TemporaryFile(dir=scratch) as output, tempfile.TemporaryFile(dir=scratch) as errors:
                proc = _sandbox_run(command, **policy, env=child_env,
                                    input=request_bytes, capture_output=False,
                                    stdout=output, stderr=errors,
                                    timeout=timeout, start_new_session=True,
                                    limits=dict(memory_mb=_MEMORY_MB, cpu_seconds=cpu, max_file_mb=16))
                output.seek(0)
                reply = output.read(MAX_REPLY_BYTES + 1)
                errors.seek(0, 2)
                errors.seek(max(0, errors.tell() - 2048))
                diagnostic = errors.read(2048)
    except (OSError, subprocess.TimeoutExpired):
        logger.debug('SMT child unavailable or timed out (%s)', tag)
        return None
    if proc.returncode != 0:
        logger.debug('SMT child exited %s (%s; stderr=%s)', proc.returncode, tag,
                     escape_nonprintable(diagnostic.decode('utf-8', errors='replace')))
        return None
    try:
        return decode(reply, MAX_REPLY_BYTES)
    except (UnicodeError, ValueError, RecursionError, TypeError, OverflowError):
        logger.debug('SMT child result refused (%s)', tag)
        return None

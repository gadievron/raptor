"""Discover a selected Ruby tool's libraries without running its launcher."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess

from core.sandbox.python_paths import _home_roots, _under_system_prefix
from core.source.contained import read_text_capped

_METADATA = """
require 'rubygems'
require 'json'
puts JSON.generate({paths: Gem.path, version: RbConfig::CONFIG['ruby_version'], engine: RUBY_ENGINE})
"""


def ruby_tool_runtime(executable: str, scratch: str) -> tuple[list[str], list[str]]:
    """Return code-only read grants and explicit RubyGems environment values.

    Inspect only the installed launcher's shebang. A fixed, bounded Ruby query
    runs without the target directory, ambient Ruby options or account HOME.
    Unknown shim layouts retain caller-declared --sandbox-tool-path handling.
    """
    header = read_text_capped(Path(executable).resolve(), max_chars=4096)
    if header is None or not header[0].startswith('#!'):
        return [], []
    try:
        words = shlex.split(header[0].partition('\n')[0][2:].strip())
    except ValueError:
        return [], []
    if words and Path(words[0]).name == 'env':
        words = words[1:]
        if words and words[0] == '-S':
            words = words[1:]
        if words:
            selected = shutil.which(words[0])
            words = [selected] if selected else []
    if not words or not re.fullmatch(r'ruby(?:\d+(?:\.\d+)*)?', Path(words[0]).name):
        return [], []
    interpreter = Path(words[0])
    if not interpreter.is_absolute() or not interpreter.is_file():
        return [], []
    paths: list[str] = []
    homes = _home_roots()

    def add(candidate: Path, *, beneath: Path | None = None) -> bool:
        resolved = candidate.resolve()
        if beneath is not None and resolved != beneath and beneath not in resolved.parents:
            return False
        if not resolved.exists() or any(resolved == home or resolved in home.parents for home in homes):
            return False
        if not _under_system_prefix(str(resolved)) and str(resolved) not in paths:
            paths.append(str(resolved))
        return True

    for binary in dict.fromkeys((interpreter, interpreter.resolve())):
        add(binary.parent)
        prefix = binary.parent.parent.resolve()
        add(prefix / 'lib' / 'ruby', beneath=prefix)
        # Exact shared-library files, never a wholesale HOME-rooted lib/.
        library = prefix / 'lib'
        for index, shared in enumerate(library.glob('libruby*')):
            if index >= 32:
                break
            if shared.is_file():
                add(shared, beneath=prefix)
    from core.binary._inspection_policy import inspection_command, inspection_options
    from core.sandbox import SandboxSetupError, run
    options = inspection_options(None, str(interpreter), scratch)
    options['tool_paths'] = list(dict.fromkeys([*options['tool_paths'], *paths]))
    result = run(inspection_command([str(interpreter), '--disable-gems', '-e', _METADATA], scratch),
                 **options, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                 timeout=10, max_capture_bytes=64 * 1024)
    if result.returncode != 0:
        raise SandboxSetupError('Ruby runtime discovery failed; declare its libraries with --sandbox-tool-path')
    try:
        metadata = json.loads(result.stdout)  # json-budget: fixed sandboxed query, capture capped at 64 KiB.
        roots = metadata['paths']
        version, engine = metadata['version'], metadata['engine']
        if (not isinstance(roots, list) or len(roots) > 32
                or not all(isinstance(root, str) and len(root) <= 4096 for root in roots)
                or not isinstance(version, str) or not re.fullmatch(r'\d+\.\d+\.\d+', version)
                or not isinstance(engine, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,32}', engine)):
            raise ValueError('invalid metadata shape')
    except (ValueError, TypeError, KeyError):
        raise SandboxSetupError('Ruby runtime discovery returned invalid metadata') from None
    # RubyGems' private query HOME must not hide user-installed tool code.
    # These are library roots only, not .gemrc or the enclosing account tree.
    roots.extend(str(home / folder / engine / version)
                 for home in homes for folder in ('.gem', '.local/share/gem'))
    roots.append(str(Path(executable).resolve().parent.parent))
    # Explicit operator tool roots may live anywhere (custom GEM_HOME, RVM,
    # or a trusted Bundler installation). Target metadata supplies none.
    from core.sandbox import state
    roots.extend(state._cli_sandbox_tool_paths or [])
    admitted = []
    for raw in roots:
        if not os.path.isabs(raw) or os.pathsep in raw:
            continue
        root = Path(raw).resolve()
        if not (root / 'gems').is_dir() or not (root / 'specifications').is_dir():
            continue
        granted = [add(root / child, beneath=root) for child in ('gems', 'specifications', 'extensions')]
        if all(granted[:2]) and str(root) not in admitted:
            admitted.append(str(root))
    gem_env = {}
    gem_env['GEM_HOME'] = str(Path(scratch) / '.home' / '.gem')
    gem_env['GEM_PATH'] = os.pathsep.join(admitted)
    return paths, [name + '=' + value for name, value in gem_env.items()]

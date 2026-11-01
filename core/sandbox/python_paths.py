"""Discover Python runtime paths for sandbox tool_paths allowlists.

When a sandbox call spawns a Python interpreter, the sandbox's Landlock
read allowlist (and mount-ns bind tree) must include the interpreter's
runtime directories.  The mount-ns baseline covers ``/usr``, ``/lib``,
``/lib64``, ``/etc``, ``/bin``, ``/sbin`` (see ``_SYSTEM_PREFIXES``) —
but framework installs (Homebrew, Xcode), pyenv, Nix,
conda, and virtualenvs place the interpreter and its shared libraries
outside those prefixes.

Use ``python_runtime_tool_paths()`` for the running interpreter, or
``python_tool_paths()`` for a selected tool launcher without executing it.
The latter avoids granting a whole HOME-rooted virtualenv prefix.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")


def _home_roots() -> tuple[Path, ...]:
    """Include account HOME even when a tool/test overrides the environment."""
    homes = [Path.home().resolve()]
    try:
        import pwd
        homes.append(Path(pwd.getpwuid(os.getuid()).pw_dir).resolve())
    except (ImportError, KeyError):
        pass
    return tuple(dict.fromkeys(homes))


def python_runtime_tool_paths() -> list[str]:
    """Return Python runtime roots needed as sandbox read-allowed paths.

    Inspects the running interpreter's ``sys.prefix``, ``sys.base_prefix``,
    ``sys.exec_prefix``, ``sys.base_exec_prefix``, and ``sys.executable``
    to cover:

    - **prefix / base_prefix**: the interpreter root (site-packages,
      lib/pythonX.Y).  ``base_prefix`` differs from ``prefix`` inside a
      virtualenv — both are needed so the venv's own packages AND the
      underlying runtime's shared library are readable.
    - **exec_prefix / base_exec_prefix**: where platform-specific files
      live (``libpython3.so``, ``_struct.cpython-*.so``).  On Debian/Ubuntu
      multiarch these can differ from prefix.
    - **sys.executable parent**: the directory containing the ``python3``
      binary itself.  Covers layouts where the binary lives outside its
      prefix tree (e.g. ``/opt/homebrew/bin/python3`` with prefix
      ``/opt/homebrew/Frameworks/Python.framework/Versions/3.14``).

    Paths already under the mount-ns baseline (``/usr``, ``/lib``, etc.)
    are excluded — they're already readable.  Non-absolute, non-existent,
    and duplicate paths are silently dropped.

    A HOME-rooted prefix is narrowed to bin, versioned Python libraries
    and the exact pyvenv.cfg file. Never grant HOME or its ancestors.

    Returns a deduplicated list of absolute runtime paths, stable order.
    """
    candidates: list[str] = []

    for attr in ("prefix", "base_prefix", "exec_prefix", "base_exec_prefix"):
        val = getattr(sys, attr, None)
        if isinstance(val, str) and val:
            candidates.append(val)

    exe = getattr(sys, "executable", None)
    if isinstance(exe, str) and exe:
        candidates.append(str(Path(exe).parent))

    # A prefix may be HOME itself (python -m venv ~). Never translate
    # that into a recursive read grant for credentials and account state.
    import sysconfig
    homes = _home_roots()
    narrow_candidates: list[str] = []
    for raw in candidates:
        prefix = Path(os.path.realpath(raw))
        if any(prefix == home or prefix in home.parents for home in homes):
            narrow_candidates.extend(str(prefix / item) for item in (
                'bin', 'lib/python' + sysconfig.get_python_version(),
                'lib64/python' + sysconfig.get_python_version(), 'pyvenv.cfg'))
        else:
            narrow_candidates.append(raw)
    paths: list[str] = []
    for raw in narrow_candidates:
        resolved = os.path.realpath(raw)
        if not os.path.isabs(resolved):
            continue
        if not (os.path.isdir(resolved) or (Path(raw).name == 'pyvenv.cfg' and os.path.isfile(resolved))):
            continue
        node = Path(resolved)
        if any(node == home or node in home.parents for home in homes):
            continue
        if _under_system_prefix(resolved):
            continue
        if resolved not in paths:
            paths.append(resolved)

    return paths


def _under_system_prefix(path: str) -> bool:
    """True if *path* is under a mount-ns baseline prefix."""
    return any(
        path == prefix.rstrip("/") or path.startswith(prefix)
        for prefix in _SYSTEM_PREFIXES
    )


def python_tool_paths(executable: str) -> list[str]:
    """Declare an operator-selected tool's runtime without executing it.

    Unlike running-interpreter prefix discovery, this keeps a HOME-rooted
    virtualenv narrow: bin/, lib/pythonX.Y/ and pyvenv.cfg, never HOME itself.
    Unknown launcher layouts still require explicit caller tool paths.
    """
    import re
    import shlex
    import shutil
    from core.source.contained import open_regular

    selected = shutil.which(executable) or executable
    if not os.path.isabs(selected):
        return []
    script = Path(selected)
    paths: list[str] = []
    homes = _home_roots()

    def add(path: Path) -> None:
        resolved = path.resolve()
        # Check both spellings before adding either: binding a library
        # symlink to HOME would expose HOME through the library alias.
        if any(resolved == home or resolved in home.parents for home in homes):
            return
        for candidate in (path, resolved):
            value = str(candidate)
            if not candidate.exists() or _under_system_prefix(value):
                continue
            if value not in paths:
                paths.append(value)

    add(script.parent)
    add(script.resolve().parent)
    interpreter = script if re.fullmatch(r'python\d*(?:\.\d+)*', script.name) else None
    if interpreter is None:
        stream = open_regular(script.resolve(), 'rb')
        if stream is not None:
            with stream:
                first = stream.readline(4096)
            if first.startswith(b'#!'):
                try:
                    words = shlex.split(first[2:].decode('utf-8').strip())
                except (UnicodeDecodeError, ValueError):
                    words = []
                if words and Path(words[0]).name == 'env':
                    words = words[1:]
                    if words and words[0] == '-S':
                        words = words[1:]
                    if words:
                        resolved = shutil.which(words[0])
                        words = [resolved] if resolved else []
                if words and re.fullmatch(r'python\d*(?:\.\d+)*', Path(words[0]).name):
                    interpreter = Path(words[0])
    if interpreter is None or not interpreter.is_absolute() or not interpreter.is_file():
        return paths
    for binary in (interpreter, interpreter.resolve()):
        add(binary.parent)
    version = next((match.group(1) for name in (interpreter.name, interpreter.resolve().name)
                    if (match := re.fullmatch(r'python(\d+\.\d+)(?:\.\d+)*', name))), None)
    for prefix in dict.fromkeys((interpreter.parent.parent, interpreter.resolve().parent.parent)):
        configuration = prefix / 'pyvenv.cfg'
        if configuration.is_file():
            add(configuration)
        if version:
            for library in ('lib', 'lib64'):
                add(prefix / library / ('python' + version))
    return paths

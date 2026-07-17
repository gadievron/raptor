"""Discover Python runtime paths for sandbox tool_paths allowlists.

When a sandbox call spawns a Python interpreter, the sandbox's Landlock
read allowlist (and mount-ns bind tree) must include the interpreter's
runtime directories.  The mount-ns baseline covers ``/usr``, ``/lib``,
``/lib64`` — but framework installs (Homebrew, Xcode), pyenv, Nix,
conda, and virtualenvs place the interpreter and its shared libraries
outside those prefixes.

This module provides a single ``python_runtime_tool_paths()`` helper
that all sandbox call sites use instead of ad-hoc discovery.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

_SYSTEM_PREFIXES = ("/usr/", "/lib/", "/lib64/", "/etc/", "/bin/", "/sbin/")


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

    Returns a deduplicated list of absolute directory paths, stable order.
    """
    candidates: list[str] = []

    for attr in ("prefix", "base_prefix", "exec_prefix", "base_exec_prefix"):
        val = getattr(sys, attr, None)
        if isinstance(val, str) and val:
            candidates.append(val)

    exe = getattr(sys, "executable", None)
    if isinstance(exe, str) and exe:
        candidates.append(str(Path(exe).parent))

    paths: list[str] = []
    for raw in candidates:
        resolved = os.path.realpath(raw)
        if not os.path.isabs(resolved):
            continue
        if not os.path.isdir(resolved):
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

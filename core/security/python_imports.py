"""Startup search-path hygiene for installation-protected RAPTOR helpers.

This is not a Python sandbox. It cannot undo interpreter startup hooks or
stop already-executing Python from changing its import machinery.
"""
from __future__ import annotations

import os
import sys


def _read_only(path: str | os.PathLike[str]) -> bool:
    try:
        return bool(os.statvfs(path).f_flag & os.ST_RDONLY)
    except (OSError, ValueError):
        return False


def _bootstrap_paths(entries: list[str]) -> list[str]:
    # Establish a small bootstrap path before importing the guard's stdlib
    # dependencies. Otherwise a writable argparse.py could run during setup.
    root = os.path.realpath(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
    stdlib = getattr(sys, '_stdlib_dir', None) or os.path.join(
        sys.base_prefix, getattr(sys, 'platlibdir', 'lib'),
        f'python{sys.version_info[0]}.{sys.version_info[1]}')
    stdlib = os.path.realpath(stdlib)
    kept = []
    for entry in entries:
        if not isinstance(entry, str) or not entry or not os.path.isabs(entry):
            continue
        try:
            resolved = os.path.realpath(entry)
        except (OSError, ValueError):
            continue
        if (resolved == root or resolved == stdlib or resolved.startswith(stdlib + os.sep)) and _read_only(resolved):
            if resolved not in kept:
                kept.append(resolved)
    return kept


def harden_import_paths() -> tuple[str, ...]:
    """Keep only declared, currently read-only code roots in sys.path.

    The existing mount guard defines the installation/runtime footprint.
    A read-only filesystem elsewhere is not automatically trusted. Keep
    ordinary launches unchanged, including their user-site dependencies.
    """
    if os.environ.get('RAPTOR_INSTALL_PROTECTED') != '1':
        return ()
    original = list(sys.path)
    cache_prefix, write_disabled = sys.pycache_prefix, sys.dont_write_bytecode
    cache_environment = os.environ.pop('PYTHONPYCACHEPREFIX', None)
    # Apply before bootstrap imports too: their code is just as sensitive.
    sys.pycache_prefix = None
    sys.dont_write_bytecode = True
    try:
        sys.path[:] = _bootstrap_paths(original)
        sys.path_importer_cache.clear()
        from core.startup.install_guard import protected_paths, verify_inside, writable_locations
        from pathlib import Path
        verify_inside()
        roots = tuple(path.resolve() for path in protected_paths() if path.is_dir())
        data_roots = tuple(path.resolve() for path in writable_locations())
    except BaseException:
        sys.pycache_prefix, sys.dont_write_bytecode = cache_prefix, write_disabled
        if cache_environment is not None:
            os.environ['PYTHONPYCACHEPREFIX'] = cache_environment
        raise
    finally:
        sys.path[:] = original
    kept: list[str] = []
    removed: list[str] = []
    for entry in original:
        if not isinstance(entry, str) or not entry or not os.path.isabs(entry):
            removed.append(str(entry))
            continue
        try:
            resolved = Path(entry).resolve(strict=True)
            approved = (any(resolved == root or root in resolved.parents for root in roots)
                        and not any(resolved == root or root in resolved.parents for root in data_roots))
        except (OSError, ValueError, RuntimeError):
            approved = False
        if not approved or not _read_only(resolved):
            removed.append(entry)
            continue
        # Keep the validated canonical spelling; don't re-walk a path alias
        # on the next import. Mount protection pins the code tree's names.
        value = str(resolved)
        if value not in kept:
            kept.append(value)
    sys.path[:] = kept
    # A writable tree must not retain an importer cached before this pass.
    sys.path_importer_cache.clear()
    return tuple(removed)

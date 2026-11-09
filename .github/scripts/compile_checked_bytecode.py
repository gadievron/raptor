#!/usr/bin/env python3
"""Reuse checked-hash bytecode across CI cache prefix restores."""
from __future__ import annotations

import compileall
import importlib.util
import marshal
import os
from pathlib import Path
import py_compile
import sys
from types import CodeType


def is_current(source: Path) -> bool:
    """Check the interpreter, invalidation mode, source and code payload."""
    try:
        data = Path(importlib.util.cache_from_source(str(source))).read_bytes()
        return (
            data[:4] == importlib.util.MAGIC_NUMBER
            and data[4:8] == b'\x03\x00\x00\x00'
            and data[8:16] == importlib.util.source_hash(source.read_bytes())
            and isinstance(marshal.loads(data[16:]), CodeType)
        )
    except (OSError, EOFError, ValueError, TypeError, OverflowError, RecursionError):
        return False


def sources(roots):
    for root in map(Path, roots):
        if not root.is_dir():
            if not root.is_file():
                raise FileNotFoundError(root)
            if root.suffix == '.py':
                yield root
            continue
        for directory, dirs, files in os.walk(root, onerror=_raise_walk_error):
            dirs[:] = sorted(name for name in dirs if name != '__pycache__'
                             and not (Path(directory) / name).is_symlink())
            for name in sorted(files):
                if name.endswith('.py'):
                    yield Path(directory) / name


def _raise_walk_error(error):
    raise error


def main(roots=None) -> int:
    roots = sys.argv[1:] if roots is None else roots
    if not roots:
        print('Supply Python files or directories.', file=sys.stderr)
        return 1
    reused = compiled = failed = 0
    try:
        for source in sources(roots):
            if is_current(source):
                reused += 1
            elif compileall.compile_file(
                str(source), quiet=1, force=True,
                invalidation_mode=py_compile.PycInvalidationMode.CHECKED_HASH,
            ):
                compiled += 1
            else:
                failed += 1
    except OSError as error:
        print(error, file=sys.stderr)
        failed += 1
    print(f'Bytecode: {reused} reused, {compiled} compiled, {failed} failed')
    return int(bool(failed))


if __name__ == '__main__':
    raise SystemExit(main())

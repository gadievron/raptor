"""Discover credential names declared by installed RAPTOR Python code.

The catalog cannot claim an existing application's credential. Read source,
never import it, and cache the inventory for the same lifetime as the catalog.
Tests and fixtures are not application declarations. No broker names live here.
"""

from __future__ import annotations

import ast
import os
import re
from functools import lru_cache
from pathlib import Path

from core.source.gated import read_bytes_gated

_SOURCE_ROOT = Path(__file__).resolve().parents[3]
_CREDENTIAL_NAME = re.compile(r"\b[A-Z][A-Z0-9_]*_API_(?:KEY|TOKEN)\b")
_LITERAL_CANDIDATE = re.compile(rb'''["'][A-Z][A-Z0-9_]*_API_(?:KEY|TOKEN)["']''')
_MAX_SOURCE_BYTES = 8 * 1024 * 1024
_SKIP_DIRS = frozenset({"tests", "test", "fixtures", "__pycache__", "node_modules"})


def _python_files(root: Path):
    yield from (p for p in root.glob("*.py")
                if not p.name.startswith(("test_", "conftest."))
                and not p.name.endswith("_test.py"))

    def refuse_unreadable_source(error: OSError):
        raise error

    for relative in ("core", "packages", "libexec", ".github/scripts"):
        base = root / relative
        if not base.exists():
            continue
        for directory, subdirs, filenames in os.walk(base, onerror=refuse_unreadable_source):
            subdirs[:] = [d for d in subdirs if d not in _SKIP_DIRS and not d.startswith(".")]
            for filename in filenames:
                if filename.startswith(("test_", "conftest.")) or filename.endswith("_test.py"):
                    continue
                path = Path(directory) / filename
                if path.suffix == ".py":
                    yield path
                elif relative == "libexec" and not path.suffix:
                    yield path  # Python entry points need not have a .py suffix.


@lru_cache(maxsize=None)
def python_credential_names(root: Path = _SOURCE_ROOT) -> frozenset[str]:
    """Reserve exact credential-name literals, including policy-table entries.

    Looking at all matching literals also covers indirect os.environ access
    through constants and helper functions. Comments and docstring examples
    containing extra prose do not become declarations. Source read errors
    propagate so the optional catalog fails closed.
    """
    names = set()
    for path in _python_files(root):
        text = read_bytes_gated(path, max_bytes=_MAX_SOURCE_BYTES)
        if path.suffix != ".py":
            first = text.split(b"\n", 1)[0]
            if not first.startswith(b"#!") or b"python" not in first:
                continue
        if not _LITERAL_CANDIDATE.search(text):
            continue
        try:
            tree = ast.parse(text, filename=str(path))
        except SyntaxError:
            # Non-importable templates are not application declarations.
            continue
        for node in ast.walk(tree):
            if (isinstance(node, ast.Constant) and isinstance(node.value, str)
                    and _CREDENTIAL_NAME.fullmatch(node.value)):
                names.add(node.value)
    return frozenset(names)

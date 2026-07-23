"""Public API detection from C/C++ header files.

Scans header files (.h, .hpp) in a target directory to identify
function declarations — the authoritative signal for "this function
is part of the public API" in C/C++ libraries.

For C/C++ libraries, the set of functions declared in public headers
is a far more precise entry-point signal than visibility (non-static):
a library may have hundreds of non-static internal functions, but only
the ones declared in headers are callable by consumers.

Usage:
    api = scan_public_api("/path/to/libxml2")
    if "xmlAddID" in api:
        ...  # this is a public entry point

The scanner extracts function names from declarations (prototypes
ending in `;`), ignoring definitions (which have `{`). It handles
common patterns: macros between return type and name (XMLPUBFUN,
ZEXTERN), __attribute__ annotations, and multi-line declarations.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import FrozenSet, Optional, Set

logger = logging.getLogger(__name__)

_HEADER_EXTENSIONS = frozenset({".h", ".hpp", ".hxx", ".hh", ".h++"})

# Standard declaration: `[qualifiers] type name(args);`
# The qualifier/type group accepts keywords, macros (XMLPUBFUN),
# __declspec, __attribute__, and any identifier (covers library
# typedefs like xmlIDPtr, z_stream, etc.).
_DECL_RE = re.compile(
    r"(?a)"
    r"(?:^|;|\})\s*"
    r"(?:(?:extern|static|inline|const|volatile|unsigned|signed|struct|enum|union"
    r"|long|short|void|int|char|float|double|size_t|ssize_t|bool|_Bool"
    r"|__attribute__\s*\(\([^)]*\)\)"
    r"|__declspec\s*\([^)]*\)"
    r"|\w+"                        # any identifier (typedefs, macros, types)
    r"|\*)\s+)*"
    r"[*\s]*"
    r"(\w+)"                       # capture: function name
    r"\s*\([^)]*\)"                # parameter list
    r"\s*(?:__attribute__\s*\(\([^)]*\)\)\s*)*"
    r"\s*;",                       # ends with `;`
    re.MULTILINE,
)

# zlib-style OF((...)) macro: `ZEXTERN int ZEXPORT inflate OF((args));`
_OF_DECL_RE = re.compile(
    r"(?a)(\w+)\s+OF\s*\(\(",
    re.MULTILINE,
)

# Generic *EXPORT* macro wrapping a declaration. The function name
# is the identifier immediately before `, (` (the parameter list).
# Examples:
#   PNG_EXPORT(1, png_uint_32, png_access_version_number, (void));
#   MY_API_EXPORT(int, my_function, (int x));
_EXPORT_MACRO_RE = re.compile(
    r"(?a)\b[A-Z_]*EXPORT[A-Z_]*\s*\(.*?,\s*(\w+)\s*,\s*\(",
    re.MULTILINE,
)

_SKIP_NAMES = frozenset({
    "if", "for", "while", "switch", "return", "sizeof", "typeof",
    "defined", "typedef", "else", "do", "case", "goto",
})

_EXCLUDE_DIRS = frozenset({
    "test", "tests", "testing", "t", "spec", "specs",
    "example", "examples", "sample", "samples",
    "benchmark", "benchmarks", "bench",
    "doc", "docs", "documentation",
    "build", "cmake", ".git", "__pycache__",
    "third_party", "thirdparty", "vendor", "vendored",
    "internal", "private",
})


def scan_public_api(
    target_path: str,
    *,
    include_dirs: Optional[list[str]] = None,
) -> FrozenSet[str]:
    """Scan header files and return function names declared in them.

    Args:
        target_path: Root directory of the C/C++ project.
        include_dirs: If provided, only scan headers under these
            subdirectories (relative to target_path). When None,
            scans all headers not under excluded directories.

    Returns:
        Frozen set of function names declared in public headers.
    """
    target = Path(target_path)
    if not target.is_dir():
        return frozenset()

    names: Set[str] = set()
    headers_scanned = 0

    for root, dirs, files in os.walk(target):
        rel_root = Path(root).relative_to(target)
        parts = set(rel_root.parts)

        if parts & _EXCLUDE_DIRS:
            dirs.clear()
            continue

        if include_dirs is not None:
            rel_str = str(rel_root)
            if not any(
                rel_str == d or rel_str.startswith(d + "/")
                for d in include_dirs
            ):
                if not any(
                    d.startswith(rel_str + "/") or d == rel_str
                    for d in include_dirs
                ):
                    continue

        dirs[:] = [d for d in dirs if d not in _EXCLUDE_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext not in _HEADER_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)
            try:
                with open(fpath, errors="replace") as f:
                    content = f.read()
            except OSError:
                continue

            headers_scanned += 1
            for m in _DECL_RE.finditer(content):
                name = m.group(1)
                if name and name not in _SKIP_NAMES and not name.startswith("_"):
                    names.add(name)
            for pat in (_OF_DECL_RE, _EXPORT_MACRO_RE):
                for m in pat.finditer(content):
                    name = m.group(1)
                    if name and name not in _SKIP_NAMES and not name.startswith("_"):
                        names.add(name)

    if headers_scanned > 0:
        logger.debug(
            "header_api: scanned %d headers in %s, found %d declared functions",
            headers_scanned, target_path, len(names),
        )

    return frozenset(names)

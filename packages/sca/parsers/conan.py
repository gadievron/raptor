"""Conan parser — ``conanfile.txt``, ``conanfile.py``, ``conan.lock``.

Conan is a C/C++ package manager with three relevant file shapes:

  * ``conanfile.txt`` — declarative INI-ish format with sections like
    ``[requires]``, ``[tool_requires]``, ``[test_requires]``. Each
    entry is a recipe reference: ``name/version[@user/channel]``.
  * ``conanfile.py`` — Python class with class-level attributes
    (``requires`` / ``build_requires`` / ``test_requires``) or a
    ``requirements()`` method calling ``self.requires(...)``. We
    parse the static-attribute form via AST; the method form is
    skipped (Turing-complete; would need a real interpreter).
  * ``conan.lock`` — JSON lockfile (Conan 2). Has ``requires``
    array of ``name/version[@user/channel]#revision`` strings, plus
    ``build_requires`` and ``python_requires``.

OSV ecosystem is ``ConanCenter``. The package name is the Conan
recipe name (``boost``, ``fmt``, etc.) — same as the part before
the first ``/`` in the reference.

What's NOT covered (yet):

  * Dynamic ``requirements()`` method bodies in ``conanfile.py``.
    Would require running Python to evaluate; out of scope for a
    static parser. Operators using the dynamic shape get nothing
    from ``conanfile.py`` and should rely on ``conan.lock``
    instead.
  * ``conanfile.py`` ``self.tool_requires(...)`` calls inside
    methods — same reason.
  * ``user/channel`` qualifiers — extracted but treated purely as
    annotation; the dep name is just the recipe name.
"""

from __future__ import annotations

import ast
import json
import logging
import re
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "ConanCenter"
_PURL_TYPE = "conan"

# Conan recipe ref: name/version[@user/channel][#revision]
# Version can be a normal token OR a bracketed range
# (``[>=9.0 <10]``) — Conan's version-range syntax.
_REF_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9._\-+]+)"
    r"/(?P<version>\[[^\]]+\]|[A-Za-z0-9._\-+]+)"
    r"(?:@(?P<userchannel>[A-Za-z0-9._\-+]+/[A-Za-z0-9._\-+]+))?"
    r"(?:#[A-Fa-f0-9]+)?$"
)


# ---------------------------------------------------------------------------
# conanfile.txt
# ---------------------------------------------------------------------------


# Each TXT section name → SCA scope.
_TXT_SECTION_TO_SCOPE = {
    "requires": "main",
    "tool_requires": "build",
    "test_requires": "test",
    "build_requires": "build",            # Conan 1 alias of tool_requires
}


@register(filenames=["conanfile.txt"])
def parse_txt(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.conan: read failed for %s: %s", path, e)
        return []

    out: List[Dependency] = []
    current_scope: Optional[str] = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip().lower()
            current_scope = _TXT_SECTION_TO_SCOPE.get(section)
            continue
        if current_scope is None:
            continue
        # Lines after a non-requires section are option / generator
        # entries; ignore.
        dep = _build_dep_from_ref(stripped, current_scope, path)
        if dep is not None:
            out.append(dep)
    return out


# ---------------------------------------------------------------------------
# conanfile.py — static-attribute extraction only
# ---------------------------------------------------------------------------


_PY_ATTR_TO_SCOPE = {
    "requires": "main",
    "tool_requires": "build",
    "build_requires": "build",
    "test_requires": "test",
    "python_requires": "build",
}


@register(filenames=["conanfile.py"])
def parse_py(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.conan: read failed for %s: %s", path, e)
        return []
    try:
        tree = ast.parse(text)
    except SyntaxError as e:
        logger.warning(
            "sca.parsers.conan: AST parse failed for %s: %s", path, e,
        )
        return []

    out: List[Dependency] = []
    for cls in ast.iter_child_nodes(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        for stmt in cls.body:
            if not isinstance(stmt, ast.Assign):
                continue
            for target in stmt.targets:
                if not isinstance(target, ast.Name):
                    continue
                scope = _PY_ATTR_TO_SCOPE.get(target.id)
                if scope is None:
                    continue
                for ref in _refs_from_value(stmt.value):
                    dep = _build_dep_from_ref(ref, scope, path)
                    if dep is not None:
                        out.append(dep)
    return out


def _refs_from_value(node: ast.AST) -> Iterable[str]:
    """Pull literal strings out of a class-attribute value.

    Supports:
      * ``requires = "foo/1.0"``
      * ``requires = ("foo/1.0", "bar/2.0")``
      * ``requires = ["foo/1.0", "bar/2.0"]``
      * Tuple-of-tuples: ``requires = (("foo/1.0",), ("bar/2.0",))``
        — Conan-1 syntax for grouped requirements.
    """
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        yield node.value
        return
    if isinstance(node, (ast.Tuple, ast.List)):
        for elt in node.elts:
            yield from _refs_from_value(elt)


# ---------------------------------------------------------------------------
# conan.lock — Conan 2 JSON lockfile
# ---------------------------------------------------------------------------


@register(filenames=["conan.lock"])
def parse_lock(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.conan: read failed for %s: %s", path, e)
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.conan: JSON parse failed for %s: %s", path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    out: List[Dependency] = []
    # Conan 2 lockfile shape: top-level keys ``requires`` /
    # ``build_requires`` / ``python_requires``, each an array of
    # qualified-ref strings.
    for key, scope in _PY_ATTR_TO_SCOPE.items():
        block = data.get(key)
        if not isinstance(block, list):
            continue
        for ref in block:
            if not isinstance(ref, str):
                continue
            dep = _build_dep_from_ref(
                ref, scope, path, is_lockfile=True,
            )
            if dep is not None:
                out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Shared
# ---------------------------------------------------------------------------


def _build_dep_from_ref(
    ref: str, scope: str, path: Path, *,
    is_lockfile: bool = False,
) -> Optional[Dependency]:
    name, version = _split_ref(ref)
    if name is None:
        return None
    pin_style = (
        PinStyle.EXACT if (version and not _is_range(version))
        else PinStyle.RANGE if (version and _is_range(version))
        else PinStyle.WILDCARD
    )
    purl = _build_purl(name, version)
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=is_lockfile,
        pin_style=pin_style,
        direct=not is_lockfile,
        purl=purl,
        parser_confidence=Confidence(
            "high" if version else "medium",
            reason=(
                "conan.lock pinned ref" if is_lockfile
                else "conanfile structured ref"
                if version else "conanfile ref without version"
            ),
        ),
    )


def _split_ref(ref: str) -> Tuple[Optional[str], Optional[str]]:
    """Split a Conan reference into (name, version).

    Recognised shapes:
      * ``name/version`` → (name, version)
      * ``name/version@user/channel`` → (name, version)
      * ``name/version#revision`` → (name, version)
      * ``name`` (no slash) → (name, None) — bare name; allowed in
        Conan 1's ``requires`` blocks for ports without a default
        version. Treated as wildcard.
    """
    ref = ref.strip()
    if not ref:
        return None, None
    m = _REF_RE.match(ref)
    if m is None:
        # Bare name fallback — only safe when no slash present.
        if "/" not in ref and re.match(r"^[A-Za-z0-9._\-+]+$", ref):
            return ref, None
        return None, None
    return m.group("name"), m.group("version")


def _is_range(version: str) -> bool:
    """Conan version strings can carry comparators (``[>=1.0]``) for
    version-range constraints. Detect them so we surface RANGE pin
    style accurately."""
    return version.startswith("[") and version.endswith("]")


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base

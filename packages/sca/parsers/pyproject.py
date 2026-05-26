"""pyproject.toml parser — PEP 621, Poetry, PDM, and build-system requires.

Reads (in this order, since a single file may declare deps under several
schemes — Poetry projects often add ``[build-system].requires``, and a
PEP 621 project may also list a few PDM dev groups):

- ``[project.dependencies]``                    → PEP 621, main scope
- ``[project.optional-dependencies][<extra>]``  → PEP 621, "optional" scope
- ``[tool.poetry.dependencies]``                → main
- ``[tool.poetry.dev-dependencies]``            → dev   (legacy Poetry)
- ``[tool.poetry.group.<name>.dependencies]``   → dev   (modern Poetry)
- ``[tool.pdm.dev-dependencies][<group>]``      → dev
- ``[build-system].requires``                   → build (PEP 518/517)

The ``python`` entry under Poetry's deps is the project's own Python
constraint, not a dep — we skip it.

Poetry's dict-form entries (``foo = {version = "^1.0", optional = true}``)
are flattened to a string spec for classification when possible; ``git``
or ``path`` keys override pin style without a string spec.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

# tomllib is stdlib on 3.11+; older interpreters need the `tomli` backport.
_tomllib = None
if sys.version_info >= (3, 11):
    import tomllib as _tomllib            # type: ignore[no-redef]
else:                                     # pragma: no cover — env-dependent
    try:
        import tomli as _tomllib          # type: ignore[no-redef]
    except ImportError:
        logger.warning(
            "sca.parsers.pyproject: 'tomli' not installed (required on "
            "Python <3.11) — pyproject.toml files will be skipped. "
            "`pip install tomli` to enable."
        )

try:
    from packaging.requirements import InvalidRequirement, Requirement
    _HAS_PACKAGING = True
except ImportError:                       # pragma: no cover — env-dependent
    InvalidRequirement = Exception        # type: ignore[assignment,misc]
    Requirement = None                    # type: ignore[assignment]
    _HAS_PACKAGING = False
    logger.warning(
        "sca.parsers.pyproject: 'packaging' not installed — PEP 621/PDM "
        "string-spec rows from pyproject.toml will be skipped. Poetry "
        "tool tables remain parsed. `pip install packaging` to enable."
    )

ECOSYSTEM = "PyPI"

# Poetry caret/tilde grammar that PEP 508 doesn't accept directly.
_POETRY_PREFIX_OPS = ("^", "~")


def parse(path: Path) -> List[Dependency]:
    if _tomllib is None:
        logger.warning(
            "sca.parsers.pyproject: skipping %s — no TOML reader available",
            path,
        )
        return []
    try:
        text = path.read_bytes()
    except OSError as e:
        logger.warning("sca.parsers.pyproject: read failed for %s: %s", path, e)
        return []

    try:
        data = _tomllib.loads(text.decode("utf-8", errors="replace"))
    except _tomllib.TOMLDecodeError as e:
        logger.warning("sca.parsers.pyproject: TOML parse failed for %s: %s", path, e)
        return []

    project_license = _extract_license(data)

    deps: List[Dependency] = []

    # --- PEP 621 ---------------------------------------------------------
    project = data.get("project")
    if isinstance(project, dict):
        for spec in project.get("dependencies", []) or []:
            d = _from_pep508(spec, path, scope="main")
            if d is not None:
                if project_license:
                    d.declared_license = project_license
                deps.append(d)
        opt = project.get("optional-dependencies") or {}
        if isinstance(opt, dict):
            for _group, items in opt.items():
                for spec in items or []:
                    d = _from_pep508(spec, path, scope="optional")
                    if d is not None:
                        if project_license:
                            d.declared_license = project_license
                        deps.append(d)

    # --- Poetry ----------------------------------------------------------
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        for name, spec in (poetry.get("dependencies") or {}).items():
            d = _from_poetry(name, spec, path, scope="main")
            if d is not None:
                deps.append(d)
        for name, spec in (poetry.get("dev-dependencies") or {}).items():
            d = _from_poetry(name, spec, path, scope="dev")
            if d is not None:
                deps.append(d)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for _gname, gbody in groups.items():
                if not isinstance(gbody, dict):
                    continue
                for name, spec in (gbody.get("dependencies") or {}).items():
                    d = _from_poetry(name, spec, path, scope="dev")
                    if d is not None:
                        deps.append(d)

    # --- PDM -------------------------------------------------------------
    pdm = tool.get("pdm") if isinstance(tool, dict) else None
    if isinstance(pdm, dict):
        pdm_dev = pdm.get("dev-dependencies") or {}
        if isinstance(pdm_dev, dict):
            for _group, items in pdm_dev.items():
                for spec in items or []:
                    d = _from_pep508(spec, path, scope="dev")
                    if d is not None:
                        deps.append(d)

    # --- build-system.requires ------------------------------------------
    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        for spec in build_system.get("requires", []) or []:
            d = _from_pep508(spec, path, scope="build")
            if d is not None:
                deps.append(d)

    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _extract_license(data: Dict[str, Any]) -> Optional[str]:
    """Read the project license from PEP 621 ``[project]`` or Poetry's
    ``[tool.poetry]`` table.

    PEP 639 (Python 3.12+) makes ``license`` a SPDX string. PEP 621
    earlier allowed a dict with ``text``/``file``; we accept either.
    """
    project = data.get("project")
    if isinstance(project, dict):
        raw = project.get("license")
        if isinstance(raw, str) and raw.strip():
            return raw.strip()
        if isinstance(raw, dict):
            for key in ("text", "name"):
                v = raw.get(key)
                if isinstance(v, str) and v.strip():
                    return v.strip()
    tool = data.get("tool")
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        v = poetry.get("license")
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _from_pep508(
    spec: Any, path: Path, *, scope: str
) -> Optional[Dependency]:
    if not isinstance(spec, str) or not spec.strip():
        return None
    if not _HAS_PACKAGING:
        # Without `packaging`, PEP 508 lines are skipped — the operator
        # was warned at import time. Poetry tool-table dict rows are
        # still parsed.
        return None
    try:
        req = Requirement(spec)
    except InvalidRequirement as e:
        logger.debug(
            "sca.parsers.pyproject: invalid PEP 508 %r in %s: %s",
            spec, path, e,
        )
        return None

    pin_style, version = _classify_specifier(req)
    if req.url:
        if req.url.startswith(("git+", "git:", "git@", "hg+", "svn+", "bzr+")):
            pin_style = PinStyle.GIT
        else:
            pin_style = PinStyle.PATH

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=_normalise_name(req.name),
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(req.name, version),
        parser_confidence=_confidence_for_pep508(pin_style, version),
    )


def _from_poetry(
    name: str, spec: Any, path: Path, *, scope: str
) -> Optional[Dependency]:
    if not isinstance(name, str) or not name:
        return None
    if name.lower() == "python":
        # Poetry uses 'python' to declare the project's own interpreter
        # range; not a runtime dep.
        return None

    pin_style: PinStyle
    version: Optional[str]

    if isinstance(spec, str):
        pin_style, version = _classify_poetry_string(spec)
    elif isinstance(spec, dict):
        pin_style, version = _classify_poetry_dict(spec)
    elif isinstance(spec, list):
        # Poetry allows multiple constraint dicts (one per platform marker).
        # Use the first usable entry; record medium confidence to flag it.
        for entry in spec:
            if isinstance(entry, str):
                pin_style, version = _classify_poetry_string(entry)
                break
            if isinstance(entry, dict):
                pin_style, version = _classify_poetry_dict(entry)
                break
        else:
            return None
        return Dependency(
            ecosystem=ECOSYSTEM,
            name=_normalise_name(name),
            version=version,
            declared_in=path,
            scope=scope,
            is_lockfile=False,
            pin_style=pin_style,
            direct=True,
            purl=_build_purl(name, version),
            parser_confidence=Confidence(
                "medium",
                reason="Poetry multi-constraint entry; first match recorded",
            ),
        )
    else:
        return None

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=_normalise_name(name),
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(name, version),
        parser_confidence=_confidence_for_poetry(pin_style, version),
    )


def _classify_specifier(req: Requirement) -> Tuple[PinStyle, Optional[str]]:
    items = list(req.specifier)
    if req.url:
        return PinStyle.UNKNOWN, None
    if not items:
        return PinStyle.WILDCARD, None
    if len(items) == 1:
        only = items[0]
        op, ver = only.operator, only.version
        if op in ("==", "==="):
            return PinStyle.EXACT, ver
        if op == "~=":
            return PinStyle.TILDE, ver
        return PinStyle.RANGE, ver
    return PinStyle.RANGE, None


def _classify_poetry_string(spec: str) -> Tuple[PinStyle, Optional[str]]:
    s = spec.strip()
    if not s or s == "*":
        return PinStyle.WILDCARD, None
    if s.startswith("^"):
        return PinStyle.CARET, s[1:].strip() or None
    if s.startswith("~"):
        return PinStyle.TILDE, s[1:].strip() or None
    if any(ch in s for ch in "<>=!,"):
        return PinStyle.RANGE, s
    if any(ch in s for ch in " "):
        return PinStyle.RANGE, s
    return PinStyle.EXACT, s


def _classify_poetry_dict(spec: Dict[str, Any]) -> Tuple[PinStyle, Optional[str]]:
    if "git" in spec:
        # ``rev``/``branch``/``tag`` becomes the version handle.
        ver = spec.get("rev") or spec.get("tag") or spec.get("branch")
        return PinStyle.GIT, ver if isinstance(ver, str) else None
    if "url" in spec:
        return PinStyle.PATH, None
    if "path" in spec:
        return PinStyle.PATH, None
    if "version" in spec and isinstance(spec["version"], str):
        return _classify_poetry_string(spec["version"])
    return PinStyle.UNKNOWN, None


def _confidence_for_pep508(
    pin_style: PinStyle, version: Optional[str]
) -> Confidence:
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium",
            reason="pyproject.toml git/path dep; version best-effort",
        )
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="pyproject.toml spec unrecognised")
    if version is None:
        return Confidence("medium", reason="pyproject.toml wildcard version")
    return Confidence("high", reason="pyproject.toml PEP 621 entry")


def _confidence_for_poetry(
    pin_style: PinStyle, version: Optional[str]
) -> Confidence:
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="Poetry dep table without version")
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium",
            reason="Poetry git/path source; version best-effort",
        )
    if version is None:
        return Confidence("medium", reason="Poetry wildcard version")
    return Confidence("high", reason="Poetry tool table")


def _normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["pyproject.toml"])(parse)

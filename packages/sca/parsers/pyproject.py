"""pyproject.toml parser — PEP 621/735, Poetry, PDM, and build requirements.

Reads (in this order, since a single file may declare deps under several
schemes — Poetry projects often add ``[build-system].requires``, and a
PEP 621 project may also list a few PDM dev groups):

- ``[project.dependencies]``                    → PEP 621, main scope
- ``[project.optional-dependencies][<extra>]``  → PEP 621, "optional" scope
- ``[dependency-groups][<group>]``              → PEP 735, dev scope
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
from typing import Any, TYPE_CHECKING

from ..models import Confidence, Dependency, PinStyle
from . import _safe_read, register
from .requirements import _spec_bounds

if TYPE_CHECKING:
    from pathlib import Path

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


def parse(path: Path) -> list[Dependency]:
    data = _load(path)
    if data is None:
        return []

    deps: list[Dependency] = []

    # --- PEP 621 ---------------------------------------------------------
    # Dependency arrays are only iterated when they really are lists.
    # A malformed ``dependencies = "foo==1.0"`` (string, not array)
    # would otherwise be iterated CHARACTER-WISE, and single letters
    # are valid PEP 508 names — the parse emitted one phantom dep per
    # character.
    project = data.get("project")
    if isinstance(project, dict):
        for spec in _str_items(project.get("dependencies")):
            d = _from_pep508(spec, path, scope="main")
            if d is not None:
                deps.append(d)
        opt = project.get("optional-dependencies") or {}
        if isinstance(opt, dict):
            for items in opt.values():
                for spec in _str_items(items):
                    d = _from_pep508(spec, path, scope="optional")
                    if d is not None:
                        deps.append(d)

    # --- PEP 735 dependency groups -------------------------------------
    # Include-group tables only link groups; each concrete requirement is
    # parsed once at its defining location, avoiding duplicate findings.
    dependency_groups = data.get("dependency-groups") or {}
    if isinstance(dependency_groups, dict):
        for items in dependency_groups.values():
            for spec in _str_items(items):
                if not isinstance(spec, str):
                    continue
                d = _from_pep508(spec, path, scope="dev")
                if d is not None:
                    deps.append(d)

    # --- Poetry ----------------------------------------------------------
    tool = data.get("tool") or {}
    poetry = tool.get("poetry") if isinstance(tool, dict) else None
    if isinstance(poetry, dict):
        _poetry_deps = poetry.get("dependencies") or {}
        if isinstance(_poetry_deps, dict):
            for name, spec in _poetry_deps.items():
                d = _from_poetry(name, spec, path, scope="main")
                if d is not None:
                    deps.append(d)
        _poetry_dev = poetry.get("dev-dependencies") or {}
        if isinstance(_poetry_dev, dict):
            for name, spec in _poetry_dev.items():
                d = _from_poetry(name, spec, path, scope="dev")
                if d is not None:
                    deps.append(d)
        groups = poetry.get("group") or {}
        if isinstance(groups, dict):
            for gbody in groups.values():
                if not isinstance(gbody, dict):
                    continue
                _gbody_deps = gbody.get("dependencies") or {}
                if not isinstance(_gbody_deps, dict):
                    continue
                for name, spec in _gbody_deps.items():
                    d = _from_poetry(name, spec, path, scope="dev")
                    if d is not None:
                        deps.append(d)

    # --- PDM -------------------------------------------------------------
    pdm = tool.get("pdm") if isinstance(tool, dict) else None
    if isinstance(pdm, dict):
        pdm_dev = pdm.get("dev-dependencies") or {}
        if isinstance(pdm_dev, dict):
            for items in pdm_dev.values():
                for spec in _str_items(items):
                    d = _from_pep508(spec, path, scope="dev")
                    if d is not None:
                        deps.append(d)

    # --- build-system.requires ------------------------------------------
    build_system = data.get("build-system")
    if isinstance(build_system, dict):
        for spec in _str_items(build_system.get("requires")):
            d = _from_pep508(spec, path, scope="build")
            if d is not None:
                deps.append(d)

    return deps


def _str_items(value: Any) -> list[str]:
    """Return the list when ``value`` is a list, else ``[]`` — never
    iterate a scalar (a string would iterate char-wise)."""
    return value if isinstance(value, list) else []


def extract_project_license(path: Path) -> str | None:
    """License the manifest declares for the PROJECT ITSELF.

    ``[project].license`` / ``[tool.poetry].license`` describe the
    project, not its deps — the value feeds the SBOM metadata/root
    component, never ``Dependency.declared_license`` (dep licenses
    come from registry enrichment, or stay None for the policy's
    ``on_unknown`` path).
    """
    data = _load(path)
    if data is None:
        return None
    return _extract_license(data)


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _load(path: Path) -> dict[str, Any] | None:
    """Read + TOML-parse a pyproject.toml; None on any failure."""
    if _tomllib is None:
        logger.warning(
            "sca.parsers.pyproject: skipping %s — no TOML reader available",
            path,
        )
        return None
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return None

    try:
        return _tomllib.loads(text)
    except _tomllib.TOMLDecodeError as e:
        logger.warning("sca.parsers.pyproject: TOML parse failed for %s: %s", path, e)
        return None


def _extract_license(data: dict[str, Any]) -> str | None:
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
            for key in ("text", "file"):
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
) -> Dependency | None:
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
    # Corridor bounds — same recording the requirements.txt parser does,
    # so harden's ceiling clamp works for pyproject deps too.
    version_floor, version_ceiling = _spec_bounds(req.specifier)
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
        version_floor=version_floor,
        version_ceiling=version_ceiling,
    )


def _from_poetry(
    name: str, spec: Any, path: Path, *, scope: str
) -> Dependency | None:
    if not isinstance(name, str) or not name:
        return None
    if name.lower() == "python":
        # Poetry uses 'python' to declare the project's own interpreter
        # range; not a runtime dep.
        return None

    pin_style: PinStyle
    version: str | None

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
        version_floor, version_ceiling = _poetry_bounds(pin_style, version)
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
            version_floor=version_floor,
            version_ceiling=version_ceiling,
        )
    else:
        return None

    version_floor, version_ceiling = _poetry_bounds(pin_style, version)
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
        version_floor=version_floor,
        version_ceiling=version_ceiling,
    )


def _classify_specifier(req: Requirement) -> tuple[PinStyle, str | None]:
    """Delegate to the requirements.txt parser's specifier logic.

    Shared on purpose: a local copy had drifted — an ``==`` clause
    among multiple specifiers (``foo>=1,==1.5,<2`` pins exactly 1.5)
    was classified RANGE with no version, and a single ``!=`` / ``>``
    / ``<`` clause recorded its operand as the installed version even
    though the spec EXCLUDES it. One implementation for both surfaces
    means they cannot drift again.
    """
    from .requirements import _classify_specifier as _shared
    return _shared(req.specifier, req.url)


def _classify_poetry_string(spec: str) -> tuple[PinStyle, str | None]:
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


def _classify_poetry_dict(spec: dict[str, Any]) -> tuple[PinStyle, str | None]:
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


def _poetry_bounds(
    pin_style: PinStyle, version: str | None,
) -> tuple[str | None, str | None]:
    """Corridor bounds for a Poetry RANGE string (PEP 440 grammar).

    Caret/tilde shapes imply their ceiling through ``pin_style`` and
    are left unbounded here; exact / wildcard / git / path specs carry
    no corridor. Unparseable range strings fail safe to ``(None,
    None)`` — harden then falls back to the rewriter's fail-closed
    backstop.
    """
    if pin_style is not PinStyle.RANGE or not version:
        return None, None
    if not _HAS_PACKAGING:
        return None, None
    from packaging.specifiers import InvalidSpecifier, SpecifierSet
    try:
        spec = SpecifierSet(version)
    except InvalidSpecifier:
        return None, None
    return _spec_bounds(spec)


def _confidence_for_pep508(
    pin_style: PinStyle, version: str | None
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
    pin_style: PinStyle, version: str | None
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


def _build_purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["pyproject.toml"])(parse)

"""``Pipfile`` parser — pipenv's TOML manifest.

Shape:

    [packages]
    requests = "*"
    django = "==4.2.7"
    flask = ">=1.0,<2.0"
    fancy = {version = "~=2.0", extras = ["security"]}
    gitpkg = {git = "https://github.com/o/r.git", ref = "main"}
    localpkg = {path = "."}

    [dev-packages]
    pytest = "*"

``[packages]`` is runtime scope, ``[dev-packages]`` is dev scope.
Version strings are PEP 440 specifier sets (pipenv's grammar), so
classification is shared with the requirements.txt parser — one
``_classify_specifier`` for both surfaces means they can't drift.

Discovery has always classified ``Pipfile`` as a PyPI manifest;
before this parser existed the file was silently dropped at
dispatch (0 deps, no warning). ``Pipfile.lock`` remains the
authoritative resolved view (see :mod:`.pipfile_lock`); this
manifest-side parser exists for lockfile-less projects and for the
direct/transitive join.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any, TYPE_CHECKING

from ..models import Confidence, Dependency, PinStyle
from . import _safe_read, register

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)

ECOSYSTEM = "PyPI"

# tomllib is stdlib on 3.11+; older interpreters need the `tomli` backport.
_tomllib = None
if sys.version_info >= (3, 11):
    import tomllib as _tomllib            # type: ignore[no-redef]
else:                                     # pragma: no cover — env-dependent
    try:
        import tomli as _tomllib          # type: ignore[no-redef]
    except ImportError:
        logger.warning(
            "sca.parsers.pipfile: 'tomli' not installed (required on "
            "Python <3.11) — Pipfile manifests will be skipped. "
            "`pip install tomli` to enable."
        )

# section name → scope value (mirrors pipfile_lock's default/develop).
_SECTIONS: tuple[tuple[str, str], ...] = (
    ("packages", "main"),
    ("dev-packages", "dev"),
)


@register(filenames=["Pipfile"])
def parse(path: Path) -> list[Dependency]:
    if _tomllib is None:
        logger.warning(
            "sca.parsers.pipfile: skipping %s — no TOML reader available",
            path,
        )
        return []
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    try:
        data = _tomllib.loads(text)
    except _tomllib.TOMLDecodeError as e:
        logger.warning(
            "sca.parsers.pipfile: TOML parse failed for %s: %s", path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    deps: list[Dependency] = []
    for section, scope in _SECTIONS:
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            d = _build_dep(name, spec, scope, path)
            if d is not None:
                deps.append(d)
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(
    name: Any, spec: Any, scope: str, path: Path,
) -> Dependency | None:
    if not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()

    pin_style: PinStyle
    version: str | None
    floor: str | None = None
    ceiling: str | None = None

    if isinstance(spec, str):
        pin_style, version, floor, ceiling = _classify_spec_string(spec)
    elif isinstance(spec, dict):
        if "git" in spec:
            ver = (
                spec.get("ref") or spec.get("rev")
                or spec.get("tag") or spec.get("branch")
            )
            pin_style = PinStyle.GIT
            version = ver if isinstance(ver, str) else None
        elif "path" in spec or "file" in spec:
            pin_style, version = PinStyle.PATH, None
        elif isinstance(spec.get("version"), str):
            pin_style, version, floor, ceiling = _classify_spec_string(
                spec["version"],
            )
        else:
            pin_style, version = PinStyle.UNKNOWN, None
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
        parser_confidence=_confidence(pin_style, version),
        version_floor=floor,
        version_ceiling=ceiling,
    )


def _classify_spec_string(
    spec: str,
) -> tuple[PinStyle, str | None, str | None, str | None]:
    """Classify a Pipfile version string.

    ``(pin_style, version, floor, ceiling)`` — classification is
    delegated to the requirements parser's specifier logic so both
    surfaces agree on multi-clause / exclusion semantics.
    """
    s = spec.strip()
    if not s or s == "*":
        return PinStyle.WILDCARD, None, None, None
    try:
        from packaging.specifiers import SpecifierSet
    except ImportError:                   # pragma: no cover — env-dependent
        return _classify_fallback(s)
    try:
        sset = SpecifierSet(s)
    except Exception:                     # noqa: BLE001 — invalid grammar
        return _classify_fallback(s)
    from .requirements import _classify_specifier, _spec_bounds
    pin_style, version = _classify_specifier(sset, None)
    floor, ceiling = _spec_bounds(sset)
    return pin_style, version, floor, ceiling


def _classify_fallback(
    s: str,
) -> tuple[PinStyle, str | None, str | None, str | None]:
    """Best-effort shapes when ``packaging`` is absent or the
    grammar is unrecognised. Bare versions are treated as exact;
    anything else stays UNKNOWN rather than guessing."""
    if s.startswith("=="):
        return PinStyle.EXACT, s[2:].strip() or None, None, None
    if re.fullmatch(r"v?\d+(?:\.\d+)*(?:[-+.][\w.]+)?", s):
        return PinStyle.EXACT, s, None, None
    return PinStyle.UNKNOWN, None, None, None


def _normalise_name(name: str) -> str:
    """PEP 503 normalisation, same as the requirements parser."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _build_purl(name: str, version: str | None) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


def _confidence(pin_style: PinStyle, version: str | None) -> Confidence:
    if pin_style is PinStyle.UNKNOWN:
        return Confidence("low", reason="Pipfile spec unrecognised")
    if pin_style in (PinStyle.GIT, PinStyle.PATH):
        return Confidence(
            "medium", reason="Pipfile git/path source; version best-effort",
        )
    if version is None:
        return Confidence("medium", reason="Pipfile unpinned entry")
    return Confidence("high", reason="Pipfile structured spec")


__all__ = ["parse"]

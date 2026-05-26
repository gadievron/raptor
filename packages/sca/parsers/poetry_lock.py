"""poetry.lock parser — Poetry's lockfile (TOML).

Schema (Poetry 1.x):

    [[package]]
    name        = "django"
    version     = "4.2.7"
    optional    = false
    python-versions = ">=3.8"
    category    = "main"     # present in <1.5; absent in 1.5+

    [package.source]
    type       = "git" | "url" | "directory" | "file" | "legacy"
    url        = "..."
    reference  = "main"
    resolved_reference = "<sha>"

    [metadata]
    lock-version = "2.0"

Scope inference:
- Poetry <1.5: ``category`` is "main" or "dev" — used directly.
- Poetry >=1.5: ``category`` is gone; the lockfile no longer tracks
  groups. We default to "main" with parser_confidence medium and let
  the manifest+lockfile join restore the group later.

Direct vs transitive cannot be derived from poetry.lock alone — every
package is listed flat. We record ``direct=False`` and let the join
pass flip rows that also appear in pyproject.toml.
"""

from __future__ import annotations

import logging
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

_tomllib = None
if sys.version_info >= (3, 11):
    import tomllib as _tomllib            # type: ignore[no-redef]
else:                                     # pragma: no cover — env-dependent
    try:
        import tomli as _tomllib          # type: ignore[no-redef]
    except ImportError:
        logger.warning(
            "sca.parsers.poetry_lock: 'tomli' not installed (required on "
            "Python <3.11) — poetry.lock files will be skipped."
        )

ECOSYSTEM = "PyPI"


def parse(path: Path) -> List[Dependency]:
    if _tomllib is None:
        logger.warning(
            "sca.parsers.poetry_lock: skipping %s — no TOML reader available",
            path,
        )
        return []
    try:
        text = path.read_bytes()
    except OSError as e:
        logger.warning("sca.parsers.poetry_lock: read failed for %s: %s", path, e)
        return []

    try:
        data = _tomllib.loads(text.decode("utf-8", errors="replace"))
    except _tomllib.TOMLDecodeError as e:
        logger.warning(
            "sca.parsers.poetry_lock: TOML parse failed for %s: %s", path, e
        )
        return []

    packages = data.get("package")
    if not isinstance(packages, list):
        return []

    deps: List[Dependency] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        d = _build_dep(pkg, path)
        if d is not None:
            deps.append(d)
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(pkg: Dict[str, Any], path: Path) -> Optional[Dependency]:
    name = pkg.get("name")
    version_text = pkg.get("version")
    if not isinstance(name, str) or not name:
        return None

    source = pkg.get("source") if isinstance(pkg.get("source"), dict) else None
    pin_style: PinStyle
    version: Optional[str]
    confidence_reason: str

    if source and source.get("type") == "git":
        pin_style = PinStyle.GIT
        # Prefer the resolved (post-fetch) commit if Poetry recorded it;
        # fall back to the operator-supplied reference.
        ref = source.get("resolved_reference") or source.get("reference")
        version = ref if isinstance(ref, str) else (
            version_text if isinstance(version_text, str) else None
        )
        confidence_reason = "poetry.lock git source"
    elif source and source.get("type") in ("file", "directory", "url"):
        pin_style = PinStyle.PATH
        version = version_text if isinstance(version_text, str) else None
        confidence_reason = f"poetry.lock {source.get('type')} source"
    else:
        version = version_text if isinstance(version_text, str) else None
        pin_style = PinStyle.EXACT if version else PinStyle.WILDCARD
        confidence_reason = "poetry.lock resolved entry"

    scope = _infer_scope(pkg)

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=_normalise_name(name),
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=True,
        pin_style=pin_style,
        direct=False,
        purl=_build_purl(name, version),
        parser_confidence=_confidence(pin_style, version, scope, confidence_reason),
    )


def _infer_scope(pkg: Dict[str, Any]) -> str:
    """Map Poetry's category (when present) onto our scope buckets."""
    cat = pkg.get("category")
    if isinstance(cat, str):
        if cat == "dev":
            return "dev"
        return "main"
    # Poetry >=1.5 dropped the category field; without it, default to
    # main with reduced confidence — see _confidence().
    return "main"


def _confidence(
    pin_style: PinStyle,
    version: Optional[str],
    scope: str,                           # noqa: ARG001 — kept for symmetry
    base_reason: str,
) -> Confidence:
    if pin_style is PinStyle.GIT:
        return Confidence("medium", reason=base_reason)
    if pin_style is PinStyle.PATH:
        return Confidence("medium", reason=base_reason)
    if version is None:
        return Confidence("low", reason="poetry.lock entry without version")
    return Confidence("high", reason=base_reason)


def _normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


register(filenames=["poetry.lock"])(parse)

"""Pipfile.lock parser — pipenv's lockfile (JSON).

Schema:

    {
      "_meta": { ... },
      "default": {
        "<name>": {
          "version": "==X.Y.Z",
          "hashes": [...],
          "markers": "python_version >= '3.10'",
          "index": "pypi",
          "git": "https://...",      // alternative source
          "ref": "main",
          ...
        }
      },
      "develop": { ... same shape ... }
    }

The ``"default"`` block is runtime deps; ``"develop"`` is dev-only.
All entries are *resolved* — we treat them as exact-pin lockfile rows.
``direct`` is ``False`` unconditionally: Pipfile.lock doesn't flag which
rows came from the manifest vs the resolver. The pipeline pass that
joins manifest + lockfile will flip ``direct=True`` for rows that also
appear in the user's ``Pipfile``.
"""

from __future__ import annotations

import json as _json
import logging
import re
from pathlib import Path
from typing import Any, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "PyPI"

# section name → scope value
_SECTIONS: Tuple[Tuple[str, str], ...] = (
    ("default", "main"),
    ("develop", "dev"),
)


def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.pipfile_lock: read failed for %s: %s", path, e)
        return []

    try:
        data = _json.loads(text)
    except _json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.pipfile_lock: JSON parse failed for %s: %s", path, e
        )
        return []
    if not isinstance(data, dict):
        return []

    deps: List[Dependency] = []
    for section, scope in _SECTIONS:
        block = data.get(section)
        if not isinstance(block, dict):
            continue
        for name, entry in block.items():
            d = _build_dep(name, entry, scope, path)
            if d is not None:
                deps.append(d)
    return deps


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _build_dep(
    name: str, entry: Any, scope: str, path: Path,
) -> Optional[Dependency]:
    if not isinstance(name, str) or not isinstance(entry, dict):
        return None

    pin_style: PinStyle
    version: Optional[str]

    if "git" in entry:
        # Resolved git source: use ref/branch/tag as the version handle.
        pin_style = PinStyle.GIT
        version = (
            entry.get("ref")
            or entry.get("rev")
            or entry.get("tag")
            or entry.get("branch")
        )
        if not isinstance(version, str):
            version = None
    elif "path" in entry or "file" in entry:
        pin_style = PinStyle.PATH
        version = None
    else:
        version = _strip_eq(entry.get("version"))
        # Pipfile.lock always pins via "==X.Y.Z"; bare version → exact.
        pin_style = PinStyle.EXACT if version else PinStyle.WILDCARD

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
        parser_confidence=_confidence(pin_style, version),
    )


def _strip_eq(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    v = value.strip()
    if v.startswith("=="):
        return v[2:].strip() or None
    return v or None


def _normalise_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:pypi/{_normalise_name(name)}"
    if version:
        return f"{base}@{version}"
    return base


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.GIT:
        return Confidence(
            "medium",
            reason="Pipfile.lock git source; ref recorded as version",
        )
    if pin_style is PinStyle.PATH:
        return Confidence(
            "medium",
            reason="Pipfile.lock path/file source; no version",
        )
    if version is None:
        return Confidence(
            "low",
            reason="Pipfile.lock entry without version",
        )
    return Confidence("high", reason="Pipfile.lock resolved entry")


register(filenames=["Pipfile.lock"])(parse)

"""vcpkg manifest parser.

Modern vcpkg uses ``vcpkg.json`` in manifest mode — a JSON file with
a ``dependencies`` array. Entries can be:

  * Simple strings: ``"zlib"``, ``"openssl"`` — name only, no version
    constraint.
  * Objects: ``{"name": "fmt", "version>=": "9.1.0"}`` or
    ``{"name": "fmt", "version-string": "9.1.0", "platform": "linux"}``.

vcpkg's port set is queried via OSV's ``vcpkg`` ecosystem; the package
name is the port name (lowercase, ``-``-separated).

Version model: ports declare ONE version-string per release. Manifest
``version>=`` is a minimum; the actual installed version comes from a
baseline (``builtin-baseline`` field) or from a registry. We don't
resolve to the installed version here — manifest-mode parsers can't,
because vcpkg's resolver doesn't run until ``vcpkg install``. We emit
the declared version constraint and let the operator's CI / lockfile
flow add the resolved versions if they care.

What's NOT covered (yet):

  * ``vcpkg-configuration.json`` overlays — rare in practice.
  * ``vcpkg.lock`` (none exists today; vcpkg has no canonical lockfile).
  * Classic-mode (``CONTROL`` files) — pre-2020, ports-tree-only,
    superseded by manifest mode.
  * Triplet-specific deps (``"platform": "linux & !arm64"``) — emitted
    as if always-active. Over-reports rather than under-reports for
    advisory-matching purposes.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "vcpkg"
_PURL_TYPE = "vcpkg"

# vcpkg port names are lowercase letters / digits / dashes per
# the vcpkg port-naming guidelines. Anything else suggests a
# malformed entry and we skip silently.
_PORT_NAME_RE = __import__("re").compile(r"^[a-z0-9][a-z0-9\-]*$")


@register(filenames=["vcpkg.json"])
def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.vcpkg: read failed for %s: %s", path, e)
        return []

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning(
            "sca.parsers.vcpkg: JSON parse failed for %s: %s", path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    deps: List[Dependency] = []
    deps.extend(_extract_block(
        data.get("dependencies"), scope="main", path=path,
    ))
    # vcpkg also has ``default-features`` and ``features`` — deps
    # only become active when a feature is enabled. Treat them as
    # main-scope (over-report rather than under-report).
    features = data.get("features")
    if isinstance(features, dict):
        for _, feat in features.items():
            if isinstance(feat, dict):
                deps.extend(_extract_block(
                    feat.get("dependencies"), scope="main", path=path,
                ))
    return deps


def _extract_block(
    block: Any, *, scope: str, path: Path,
) -> List[Dependency]:
    if not isinstance(block, list):
        return []
    out: List[Dependency] = []
    for entry in block:
        dep = _build_dep(entry, scope=scope, path=path)
        if dep is not None:
            out.append(dep)
    return out


def _build_dep(
    entry: Any, *, scope: str, path: Path,
) -> Optional[Dependency]:
    if isinstance(entry, str):
        name = entry
        version = None
        pin_style = PinStyle.WILDCARD
    elif isinstance(entry, dict):
        name = entry.get("name")
        if not isinstance(name, str):
            return None
        version, pin_style = _classify(entry)
    else:
        return None

    if not _PORT_NAME_RE.match(name):
        return None

    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=path,
        scope=scope,
        is_lockfile=False,
        pin_style=pin_style,
        direct=True,
        purl=_build_purl(name, version),
        parser_confidence=_confidence(pin_style, version),
    )


def _classify(entry: Dict[str, Any]) -> Tuple[Optional[str], PinStyle]:
    """Pull a (version, pin_style) tuple out of a vcpkg dict entry.

    Field-precedence (vcpkg's documented order):

      * ``version`` — exact version (semver or relaxed-semver).
      * ``version-semver`` — explicitly semver-typed.
      * ``version-date`` — date-shaped version.
      * ``version-string`` — free-form string (legacy).
      * ``version>=`` — minimum constraint.

    Anything else (port name only, version absent) is WILDCARD.
    """
    for field, pin in (
        ("version", PinStyle.EXACT),
        ("version-semver", PinStyle.EXACT),
        ("version-date", PinStyle.EXACT),
        ("version-string", PinStyle.EXACT),
    ):
        v = entry.get(field)
        if isinstance(v, str) and v:
            return v, pin
    v_min = entry.get("version>=")
    if isinstance(v_min, str) and v_min:
        return v_min, PinStyle.RANGE
    return None, PinStyle.WILDCARD


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style == PinStyle.EXACT and version:
        return Confidence("high", reason="vcpkg.json structured field")
    if pin_style == PinStyle.RANGE and version:
        return Confidence(
            "medium",
            reason="vcpkg.json minimum-version constraint",
        )
    return Confidence("medium", reason="vcpkg.json port name only")


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base

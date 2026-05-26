"""Composer (PHP) parser.

Handles ``composer.json`` (manifest) and ``composer.lock`` (resolved
versions).

Both are JSON; both are deterministic. Pin styles map to Composer's
constraint grammar:

  ``"1.2.3"``                 → EXACT
  ``"^1.2.3"``                → CARET
  ``"~1.2.3"``                → TILDE
  ``">=1.0,<2.0"`` / similar  → RANGE
  ``"*"``                     → WILDCARD
  ``"dev-master"`` / branches → GIT (treated as branch-pin)

Names follow the ``vendor/package`` convention; we keep the slash in
the canonical name.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "Packagist"
_PURL_TYPE = "composer"


@register(filenames=["composer.json"])
def parse_manifest(path: Path) -> List[Dependency]:
    """Parse a ``composer.json`` and emit one Dependency per declared dep."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("sca.parsers.composer: %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    # ``replace``: this package CLAIMS to provide the listed
    # packages — consumers seeing ``foo/replacement`` with
    # ``replace: {foo/original: "*"}`` get ``foo/original`` from
    # the replacement, not from the registry. Surface as
    # scope="replaces" so downstream consumers know this isn't
    # a real install-set entry; the dep's CVEs may or may not
    # apply depending on what the replacer actually ships.
    for json_key, scope in (
        ("require", "main"), ("require-dev", "dev"),
        ("replace", "replaces"), ("provide", "provides"),
    ):
        block = data.get(json_key) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if not (isinstance(name, str) and isinstance(spec, str)):
                continue
            # Composer's own platform requirements (``php``, ``ext-*``,
            # ``lib-*``, ``hhvm``) aren't packages on Packagist; skip.
            if _is_platform_req(name):
                continue
            pin_style, version = _classify_version_spec(spec)
            purl = _build_purl(name, version)
            dep = Dependency(
                ecosystem=ECOSYSTEM,
                name=name,
                version=version,
                declared_in=path,
                scope=scope,
                is_lockfile=False,
                pin_style=pin_style,
                direct=True,
                purl=purl,
                parser_confidence=Confidence(
                    "high",
                    reason="composer.json JSON — deterministic structure",
                ),
                source_kind="manifest",
            )
            if dep.key() in seen_keys:
                continue
            seen_keys.add(dep.key())
            out.append(dep)
    return out


@register(filenames=["composer.lock"])
def parse_lockfile(path: Path) -> List[Dependency]:
    """Parse a ``composer.lock`` and emit one Dependency per resolved entry.

    Format (abridged):
        {
          "packages": [
            {"name": "vendor/pkg", "version": "1.2.3", "source": {...}},
            ...
          ],
          "packages-dev": [...]
        }

    Direct vs transitive: Composer's lockfile lists every resolved dep
    flat; the join layer flips ``direct`` based on the manifest.
    """
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("sca.parsers.composer: %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    for json_key, scope in (("packages", "main"), ("packages-dev", "dev")):
        block = data.get(json_key) or []
        if not isinstance(block, list):
            continue
        for entry in block:
            if not isinstance(entry, dict):
                continue
            name = entry.get("name")
            version = entry.get("version")
            if not (isinstance(name, str) and isinstance(version, str)):
                continue
            # Composer leading 'v' on tags (``v1.2.3``) is preserved as-is;
            # OSV's Packagist ecosystem matches whatever shape was published.
            source = entry.get("source")
            pin_style = (PinStyle.GIT
                          if isinstance(source, dict)
                          and source.get("type") == "git"
                          and not _looks_like_release_tag(version)
                          else PinStyle.EXACT)
            purl = _build_purl(name, version)
            dep = Dependency(
                ecosystem=ECOSYSTEM,
                name=name,
                version=version,
                declared_in=path,
                scope=scope,
                is_lockfile=True,
                pin_style=pin_style,
                direct=False,                # join layer flips when matched
                purl=purl,
                parser_confidence=Confidence(
                    "high",
                    reason="composer.lock JSON — deterministic structure",
                ),
                source_kind="lockfile",
            )
            if dep.key() in seen_keys:
                continue
            seen_keys.add(dep.key())
            out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _is_platform_req(name: str) -> bool:
    """``php``, ``ext-*``, ``lib-*``, ``hhvm`` — environment requirements."""
    if name == "php" or name == "hhvm":
        return True
    if name.startswith("ext-") or name.startswith("lib-"):
        return True
    return False


def _classify_version_spec(spec: str) -> Tuple[PinStyle, Optional[str]]:
    s = spec.strip()
    if not s or s == "*":
        return PinStyle.WILDCARD, None
    # ``dev-master``, ``dev-some-branch`` — branch-pin (Git).
    if s.startswith("dev-"):
        return PinStyle.GIT, s
    # OR / multi-constraint — treat as RANGE.
    if "|" in s or "," in s or " " in s.strip():
        return PinStyle.RANGE, None
    if s.startswith("^"):
        return PinStyle.CARET, s[1:]
    if s.startswith("~"):
        return PinStyle.TILDE, s[1:]
    if s.startswith((">=", "<=", ">", "<")):
        # Take the bare version after the operator chars.
        bare = re.sub(r"^[<>=]+", "", s).strip()
        return PinStyle.RANGE, bare or None
    if re.match(r"^v?\d[\w.\-+]*$", s):
        return PinStyle.EXACT, s
    return PinStyle.UNKNOWN, None


_RELEASE_TAG_RE = re.compile(r"^v?\d+(\.\d+)*[\w.\-+]*$")


def _looks_like_release_tag(version: str) -> bool:
    """Heuristic: ``1.2.3`` / ``v1.2.3`` is a release; ``dev-master`` isn't."""
    return bool(_RELEASE_TAG_RE.match(version))


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse_manifest", "parse_lockfile"]

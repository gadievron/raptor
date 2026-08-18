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

from ..models import Confidence, Dependency, PinStyle
from . import _safe_read, register

logger = logging.getLogger(__name__)


ECOSYSTEM = "Packagist"
_PURL_TYPE = "composer"


@register(filenames=["composer.json"])
def parse_manifest(path: Path) -> list[Dependency]:
    """Parse a ``composer.json`` and emit one Dependency per declared dep."""
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("sca.parsers.composer: %s: %s", path, e)
        return []

    if not isinstance(data, dict):
        return []
    out: list[Dependency] = []
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
            scoped_key = f"{scope}:{dep.key()}"
            if scoped_key in seen_keys:
                continue
            seen_keys.add(scoped_key)
            out.append(dep)
    return out


@register(filenames=["composer.lock"])
def parse_lockfile(path: Path) -> list[Dependency]:
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
    # Bounded read — same posture as sibling parsers: a hostile
    # oversized (or symlinked) composer.lock is treated as
    # unparseable rather than fed to the JSON parser.
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        # ``read_bounded`` already logged the underlying reason.
        return []
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        logger.warning("sca.parsers.composer: %s: %s", path, e)
        return []

    out: list[Dependency] = []
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
    return name.startswith(("ext-", "lib-"))


def _classify_version_spec(spec: str) -> tuple[PinStyle, str | None]:
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
    if "*" in s:
        return PinStyle.WILDCARD, None
    if re.match(r"^v?\d[\w.\-+]*$", s):
        return PinStyle.EXACT, s
    return PinStyle.UNKNOWN, None


# Unambiguous grammar: the pre-release/build tail must START with
# ``-`` or ``+`` so it cannot re-consume dot-digit runs already
# matched by ``(\.\d+)*``. The previous ``[\w.\-+]*`` tail overlapped
# with the dotted-segment group, giving O(K^2) backtracking on
# ``1`` + ``.1``*K + ``!`` — quadratic work on attacker-supplied
# lockfile version strings.
_RELEASE_TAG_RE = re.compile(r"^v?\d+(\.\d+)*(?:[-+][\w.\-+]*)?$")

# Length bound applied before the regex runs. Real Composer versions
# are tens of characters; anything longer is hostile or garbage and
# is classified as "not a release tag" without touching the regex.
_MAX_VERSION_LEN = 128


def _looks_like_release_tag(version: str) -> bool:
    """Heuristic: ``1.2.3`` / ``v1.2.3`` is a release; ``dev-master`` isn't.

    Also rejects Composer's numeric dev-branch aliases (``1.0-dev``,
    ``1.2.x-dev``) which satisfy the release regex but represent
    moving branch pins, not immutable tags.
    """
    if len(version) > _MAX_VERSION_LEN:
        return False
    if version.endswith("-dev") or ".x-dev" in version:
        return False
    return bool(_RELEASE_TAG_RE.match(version))


def _build_purl(name: str, version: str | None) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse_lockfile", "parse_manifest"]

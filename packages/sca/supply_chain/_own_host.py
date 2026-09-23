"""Package-own host resolution for tree-walking detectors.

Lifecycle-hook, in-tree-binary, and exfil-destination findings
describe code that ships in the SCANNED PACKAGE ITSELF — the finding
host must carry the package's OWN name, never a dependency it happens
to declare. Anchoring to "the first dep declared in the manifest"
mis-attributes the finding to an innocent third party, keys the
publish-helper worm-shape suppression on the wrong package name (a
project whose first dep is ``np`` would silently suppress its own
credential-read+publish hook finding), and fragments the composite
chokepoint's per-dep grouping so HOOK+BINARY / HOOK+EGRESS hard
pairs can never co-fire.

One resolver here, shared by every adapter, so both sides of any
composite pair produce byte-identical host keys for the same
manifest.  The dependency-row reuse the npm adapter used to attempt
(returning the parser's row when a dep matches the package's own
name) is deliberately NOT performed: a package is never a dep of its
own manifest in parser output, and a synthesised host that is a pure
function of the manifest file guarantees key equality across
detectors regardless of which deps slice each one received.
"""

from __future__ import annotations

import json
import logging
import re
from typing import TYPE_CHECKING

from ..models import Confidence, Dependency, PinStyle
from ..parsers import _safe_read
from ..parsers._base import PARSE_ESCAPE_ERRORS

if TYPE_CHECKING:
    from pathlib import Path

    from ..models import Manifest

try:
    import tomllib                # Python 3.11+
except ImportError:               # pragma: no cover — legacy envs
    import tomli as tomllib       # type: ignore[no-redef]

logger = logging.getLogger(__name__)

# The canonical placeholder host name when the manifest carries no
# usable own name (Gemfile-only gems, requirements-only Python
# trees).  ``<``-prefixed names cannot collide with real package
# names in any supported ecosystem grammar; the composite chokepoint
# relies on that to key placeholder-hosted findings by their
# anchoring manifest instead.
PLACEHOLDER_NAME = "<project>"

# ``spec.name = "x"`` / ``s.name = 'x'`` in a gemspec.  Deliberately
# narrow: interpolated or computed names stay unresolved (placeholder
# host) rather than guessed.
_GEMSPEC_NAME_RE = re.compile(
    r"""\.\s*name\s*=\s*(["'])([A-Za-z0-9_.\-]+)\1""")
_GEMSPEC_VERSION_RE = re.compile(
    r"""\.\s*version\s*=\s*(["'])([A-Za-z0-9_.\-]+)\1""")


def _load_json(path: Path) -> dict | None:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        return None
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, *PARSE_ESCAPE_ERRORS):  # hostile-input escape classes
        return None
    return data if isinstance(data, dict) else None


def _load_toml(path: Path) -> dict | None:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        return None
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, *PARSE_ESCAPE_ERRORS):  # hostile-input escape classes
        return None
    return data if isinstance(data, dict) else None


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) and value else None


def _from_json_manifest(path: Path) -> tuple[str | None, str | None]:
    data = _load_json(path)
    if data is None:
        return None, None
    return _str_or_none(data.get("name")), _str_or_none(data.get("version"))


def _from_pyproject(path: Path) -> tuple[str | None, str | None]:
    data = _load_toml(path)
    if data is None:
        return None, None
    project = data.get("project")
    if isinstance(project, dict) and _str_or_none(project.get("name")):
        return (_str_or_none(project.get("name")),
                _str_or_none(project.get("version")))
    poetry = data.get("tool", {})
    poetry = poetry.get("poetry") if isinstance(poetry, dict) else None
    if isinstance(poetry, dict):
        return (_str_or_none(poetry.get("name")),
                _str_or_none(poetry.get("version")))
    return None, None


def _from_cargo_toml(path: Path) -> tuple[str | None, str | None]:
    data = _load_toml(path)
    if data is None:
        return None, None
    package = data.get("package")
    if not isinstance(package, dict):
        return None, None
    version = package.get("version")
    # ``version.workspace = true`` inheritance — not a string.
    return (_str_or_none(package.get("name")), _str_or_none(version))


def _from_gemspec(path: Path) -> tuple[str | None, str | None]:
    text = _safe_read.read_bounded(path, follow_symlinks=False)
    if text is None:
        return None, None
    name_m = _GEMSPEC_NAME_RE.search(text)
    if name_m is None:
        return None, None
    version_m = _GEMSPEC_VERSION_RE.search(text)
    return name_m.group(2), (version_m.group(2) if version_m else None)


def own_name_version(manifest: Manifest) -> tuple[str | None, str | None]:
    """The package's OWN declared ``(name, version)`` for ``manifest``,
    ``(None, None)`` when the manifest kind doesn't carry one or it
    is unreadable / malformed.

    Resolution is a pure function of files in the manifest's own
    directory, so every detector anchoring at the same manifest gets
    the identical answer.
    """
    path = manifest.path
    fname = path.name
    if fname in ("package.json", "composer.json"):
        return _from_json_manifest(path)
    if fname == "pyproject.toml":
        return _from_pyproject(path)
    if fname == "Cargo.toml":
        return _from_cargo_toml(path)
    if fname.endswith(".gemspec"):
        return _from_gemspec(path)
    # Manifests that don't carry the project's name themselves:
    # consult the canonical sibling for the ecosystem.
    eco = manifest.ecosystem
    if eco == "PyPI":
        sibling = path.parent / "pyproject.toml"
        if sibling.is_file():
            return _from_pyproject(sibling)
        return None, None
    if eco == "RubyGems":
        try:
            specs = sorted(path.parent.glob("*.gemspec"))
        except OSError:
            return None, None
        if specs:
            return _from_gemspec(specs[0])
        return None, None
    if eco == "npm" and fname != "package.json":
        sibling = path.parent / "package.json"
        if sibling.is_file():
            return _from_json_manifest(sibling)
    return None, None


def resolve_own_host(
    manifest: Manifest,
    *,
    reason: str,
    placeholder_name: str = PLACEHOLDER_NAME,
    scope: str = "main",
) -> Dependency:
    """Synthesise the host ``Dependency`` for a package-own finding
    anchored at ``manifest``.

    Carries the package's own name/version when the manifest declares
    one (high confidence); otherwise a placeholder (low confidence) —
    callers may keep their established per-detector placeholder name,
    which MUST stay ``<``-prefixed.  Either way ``declared_in`` is
    the manifest path — the composite chokepoint keys placeholder-
    hosted findings on it, so placeholder names don't need to agree
    across detectors.
    """
    name, version = own_name_version(manifest)
    if name is None:
        return Dependency(
            ecosystem=manifest.ecosystem,
            name=placeholder_name,
            version=None,
            declared_in=manifest.path,
            scope=scope,
            is_lockfile=False,
            pin_style=PinStyle.UNKNOWN,
            direct=True,
            purl="",
            parser_confidence=Confidence("low", reason=reason),
        )
    return Dependency(
        ecosystem=manifest.ecosystem,
        name=name,
        version=version,
        declared_in=manifest.path,
        scope=scope,
        is_lockfile=False,
        pin_style=PinStyle.UNKNOWN,
        direct=True,
        purl=f"pkg:{manifest.ecosystem.lower()}/{name}",
        parser_confidence=Confidence(
            "high",
            reason="package's own name from its manifest",
        ),
    )


__all__ = ["PLACEHOLDER_NAME", "own_name_version", "resolve_own_host"]

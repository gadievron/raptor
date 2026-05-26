"""Go module parser.

Handles ``go.mod`` (manifest) and ``go.sum`` (resolved versions +
hashes).

Go's grammar is custom plain-text. The relevant sections in ``go.mod``:

  module github.com/me/myapp

  go 1.22

  require (
      github.com/foo/bar v1.2.3
      github.com/baz/qux v0.0.0-20231201120000-abcdef123456 // indirect
  )

  require github.com/single/dep v1.0.0    // single-line require also valid

  replace github.com/foo/bar => github.com/me/forked v1.2.3-mine

  exclude github.com/bad/dep v0.5.0

  retract v1.0.0    // own-module retraction; ignore

We surface ``require`` entries as Dependency rows; ``// indirect``
comments mark transitive deps. ``replace`` directives override the
target — we record those as RANGE pin_style with the replacement spec
in ``parser_confidence.reason``. ``exclude`` is informational; not
emitted as a dep.

``go.sum`` is the lockfile equivalent — a list of
``<module> <version> h1:<hash>`` triples (and a ``/go.mod`` line for
module-graph entries). We dedupe on ``(name, version)``.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)


ECOSYSTEM = "Go"
_PURL_TYPE = "golang"

# A Go pseudo-version: ``v0.0.0-20210101120000-abcdef123456`` or
# ``v1.2.3-0.20210101120000-abcdef123456`` (vX.Y.Z-pre.0.<ts>-<sha>).
_PSEUDO_VERSION_RE = re.compile(
    r"^v\d+\.\d+\.\d+(?:-[\w.]+)?-\d{14}-[0-9a-f]{12}$"
)


@register(filenames=["go.mod"])
def parse_manifest(path: Path) -> List[Dependency]:
    """Parse a ``go.mod`` and emit one Dependency per ``require`` entry.

    ``// indirect`` comments mark transitive deps (set ``direct=False``).
    ``replace`` directives produce an additional Dependency row when
    they redirect to a different module name; the original module is
    excluded.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.gomod: cannot read %s: %s", path, e)
        return []

    requires = _parse_require_block(text)
    replaces = _parse_replace_block(text)

    out: List[Dependency] = []
    seen_keys: set = set()
    for name, version, indirect in requires:
        # Apply replace directives: if the original module is being
        # replaced, emit only the replacement.
        replacement = replaces.get(name)
        if replacement is not None:
            new_name, new_version = replacement
            dep = _build_dep(
                name=new_name, version=new_version,
                direct=not indirect, declared_in=path,
                replaced_from=name,
            )
        else:
            dep = _build_dep(
                name=name, version=version,
                direct=not indirect, declared_in=path,
                replaced_from=None,
            )
        if dep is None or dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


@register(filenames=["go.sum"])
def parse_lockfile(path: Path) -> List[Dependency]:
    """Parse a ``go.sum`` and emit one Dependency per (module, version).

    Each line is ``<module> <version>[/go.mod] h1:<base64-hash>``. The
    ``/go.mod`` lines duplicate module entries with the same version;
    we dedupe.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        logger.warning("sca.parsers.gomod: cannot read %s: %s", path, e)
        return []

    out: List[Dependency] = []
    seen_keys: set = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        # ``module version[/go.mod] h1:hash``
        parts = line.split()
        if len(parts) < 3:
            continue
        name = parts[0]
        version = parts[1]
        # Strip ``/go.mod`` suffix on the version when present.
        if version.endswith("/go.mod"):
            version = version[: -len("/go.mod")]
        dep = _build_dep(
            name=name, version=version,
            direct=False, declared_in=path,
            replaced_from=None, is_lockfile=True,
        )
        if dep is None or dep.key() in seen_keys:
            continue
        seen_keys.add(dep.key())
        out.append(dep)
    return out


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

def _parse_require_block(text: str) -> List[Tuple[str, str, bool]]:
    """Yield ``(name, version, indirect)`` for every ``require`` entry.

    Handles both block form (``require ( ... )``) and single-line form
    (``require <mod> <ver>``).
    """
    out: List[Tuple[str, str, bool]] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.lstrip()
        # Single-line require.
        m = re.match(r"^require\s+(\S+)\s+(\S+)\s*(//.*)?$", stripped)
        if m:
            name, version, comment = m.group(1), m.group(2), m.group(3) or ""
            out.append((name, version, _is_indirect(comment)))
            i += 1
            continue
        # Block-form require.
        if re.match(r"^require\s*\(\s*$", stripped):
            i += 1
            while i < len(lines):
                inner = lines[i].rstrip()
                inner_stripped = inner.lstrip()
                if inner_stripped.startswith(")"):
                    i += 1
                    break
                # Skip pure comments / blank lines.
                if not inner_stripped or inner_stripped.startswith("//"):
                    i += 1
                    continue
                im = re.match(r"^(\S+)\s+(\S+)\s*(//.*)?$", inner_stripped)
                if im:
                    name = im.group(1)
                    version = im.group(2)
                    comment = im.group(3) or ""
                    out.append((name, version, _is_indirect(comment)))
                i += 1
            continue
        i += 1
    return out


def _parse_replace_block(text: str) -> Dict[str, Tuple[str, Optional[str]]]:
    """Yield ``orig → (new_name, new_version)`` for every ``replace`` line.

    Both single and block form. ``replace foo => ../local`` (path-only,
    no version) is recorded with ``new_version=None`` so the dep flows
    through as PATH pin_style.
    """
    out: Dict[str, Tuple[str, Optional[str]]] = {}
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.lstrip()
        m = re.match(
            r"^replace\s+(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?\s*$",
            stripped,
        )
        if m:
            orig = m.group(1)
            new_name = m.group(2)
            new_version = m.group(3)
            out[orig] = (new_name, new_version)
            i += 1
            continue
        if re.match(r"^replace\s*\(\s*$", stripped):
            i += 1
            while i < len(lines):
                inner = lines[i].rstrip()
                inner_stripped = inner.lstrip()
                if inner_stripped.startswith(")"):
                    i += 1
                    break
                if not inner_stripped or inner_stripped.startswith("//"):
                    i += 1
                    continue
                im = re.match(
                    r"^(\S+)(?:\s+\S+)?\s*=>\s*(\S+)(?:\s+(\S+))?\s*$",
                    inner_stripped,
                )
                if im:
                    out[im.group(1)] = (im.group(2), im.group(3))
                i += 1
            continue
        i += 1
    return out


def _is_indirect(comment: str) -> bool:
    return "indirect" in comment


def _build_dep(
    *,
    name: str,
    version: Optional[str],
    direct: bool,
    declared_in: Path,
    replaced_from: Optional[str],
    is_lockfile: bool = False,
) -> Optional[Dependency]:
    if not name:
        return None
    pin_style = _classify_pin_style(version)
    purl = _build_purl(name, version)
    reason = "go.mod plain-text grammar"
    if is_lockfile:
        reason = "go.sum plain-text — deterministic"
    if replaced_from:
        reason = f"replace directive: {replaced_from} → {name}"
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=declared_in,
        scope="main",
        is_lockfile=is_lockfile,
        pin_style=pin_style,
        direct=direct,
        purl=purl,
        parser_confidence=Confidence("high", reason=reason),
        source_kind="lockfile" if is_lockfile else "manifest",
    )


def _classify_pin_style(version: Optional[str]) -> PinStyle:
    if version is None:
        # Path replacement (no version) — treat as PATH.
        return PinStyle.PATH
    if _PSEUDO_VERSION_RE.match(version):
        # Pseudo-versions ARE exact (they encode commit + timestamp).
        return PinStyle.GIT
    if version.startswith("v") and re.match(r"^v\d+(\.\d+){0,2}$", version):
        return PinStyle.EXACT
    if re.match(r"^v\d+(\.\d+){0,2}(?:-[\w.]+)?$", version):
        return PinStyle.EXACT
    return PinStyle.UNKNOWN


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:{_PURL_TYPE}/{name}"
    if version:
        return f"{base}@{version}"
    return base


__all__ = ["parse_manifest", "parse_lockfile"]

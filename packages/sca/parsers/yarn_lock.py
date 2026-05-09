"""yarn.lock parser — Yarn classic v1 and Berry v2+.

Two on-disk shapes share one filename:

- **Classic (v1)**: a custom indented format that's *not* valid YAML
  (string values are bare-quoted with embedded special chars). The
  ``# yarn lockfile v1`` banner is the only fingerprint we can rely on.
  Each block starts with one or more comma-separated descriptors
  (``"@types/node@^20.5.0", "@types/node@^20.10.0":``) followed by
  indented ``key value`` properties; the resolved version sits under
  ``version "X.Y.Z"``.

- **Berry (v2+)**: the file *is* YAML and starts with a ``__metadata``
  block. Top-level keys are full descriptors
  (``"lodash@npm:^4.17.21"``); each maps to a record with ``version``,
  ``resolution``, ``linkType`` and friends.

Detection: if PyYAML is available and the file parses as YAML *with*
a ``__metadata`` key, dispatch to the Berry path; otherwise treat it as
classic. The classic path needs no extra dependencies.

Direct vs transitive: yarn.lock alone doesn't flag direct deps; that
information lives in ``package.json``. We record ``direct=False`` and
let the manifest+lockfile join flip the bit.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import Confidence, Dependency, PinStyle
from . import register

logger = logging.getLogger(__name__)

ECOSYSTEM = "npm"

try:
    import yaml as _yaml                  # type: ignore[import-untyped]
    from .._yaml_fast import safe_load as _safe_load
    _HAS_YAML = True
except ImportError:                       # pragma: no cover — env-dependent
    _yaml = None                          # type: ignore[assignment]
    _safe_load = None                     # type: ignore[assignment]
    _HAS_YAML = False
    logger.warning(
        "sca.parsers.yarn_lock: 'PyYAML' not installed — Yarn Berry "
        "lockfiles will be skipped (Yarn classic still works). "
        "`pip install PyYAML` to enable."
    )


def parse(path: Path) -> List[Dependency]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        logger.warning("sca.parsers.yarn_lock: read failed for %s: %s", path, e)
        return []

    if _looks_like_berry(text):
        if not _HAS_YAML:
            logger.warning(
                "sca.parsers.yarn_lock: skipping Berry-format %s — "
                "'PyYAML' not installed", path,
            )
            return []
        return _parse_berry(text, path)
    return _parse_classic(text, path)


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _looks_like_berry(text: str) -> bool:
    """Berry lockfiles start with a ``__metadata`` block before the first
    descriptor. Classic v1 files start with the ``# yarn lockfile v1`` banner.
    """
    head = "\n".join(text.splitlines()[:30])
    if "__metadata:" in head:
        return True
    if "# yarn lockfile v1" in head:
        return False
    # Ambiguous: try YAML; if it parses to a dict containing __metadata,
    # call it Berry. Otherwise default to classic.
    if _HAS_YAML:
        try:
            data = _safe_load(text)       # type: ignore[misc]
            if isinstance(data, dict) and "__metadata" in data:
                return True
        except Exception:                 # noqa: BLE001 — best-effort sniff
            pass
    return False


# ---------------------------------------------------------------------------
# Classic v1 parser (line-oriented)
# ---------------------------------------------------------------------------

def _parse_classic(text: str, path: Path) -> List[Dependency]:
    deps: List[Dependency] = []
    current_specs: List[str] = []
    current_props: Dict[str, str] = {}

    def _flush() -> None:
        if not current_specs:
            return
        d = _from_classic_block(current_specs, current_props, path)
        if d is not None:
            deps.append(d)

    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            # Comment or blank → if we just finished a block, flush now.
            if current_specs and not raw.strip():
                _flush()
                current_specs = []
                current_props = {}
            continue
        if raw[0] not in (" ", "\t"):
            # New block header.
            _flush()
            current_specs = _split_classic_specs(raw.rstrip(":").rstrip())
            current_props = {}
        else:
            # Property line.
            key, value = _parse_classic_prop(raw.strip())
            if key is not None:
                current_props[key] = value
    _flush()
    return deps


_CLASSIC_SPEC_QUOTED = re.compile(r'"([^"]*)"')


def _split_classic_specs(line: str) -> List[str]:
    """Split a comma-separated spec header into individual descriptors.

    Each spec may be quoted (when it contains commas/spaces/colons in the
    range) or bare. We extract quoted runs first, then handle anything
    left as bare comma-split tokens.
    """
    if '"' in line:
        # All meaningful tokens are inside quotes when any quoting is used.
        return _CLASSIC_SPEC_QUOTED.findall(line)
    return [t.strip() for t in line.split(",") if t.strip()]


_PROP_RE = re.compile(r'^([A-Za-z_][\w-]*)\s+(?:"([^"]*)"|([^\s].*))$')


def _parse_classic_prop(line: str) -> Tuple[Optional[str], str]:
    """Parse one ``key value`` property line; ``value`` may be quoted."""
    m = _PROP_RE.match(line)
    if not m:
        return None, ""
    key = m.group(1)
    value = m.group(2) if m.group(2) is not None else (m.group(3) or "")
    return key, value.strip()


def _from_classic_block(
    specs: List[str], props: Dict[str, str], path: Path,
) -> Optional[Dependency]:
    name = _name_from_descriptor(specs[0]) if specs else None
    if not name:
        return None
    version = props.get("version") or None
    resolved = props.get("resolved", "")
    pin_style = _pin_from_resolved(resolved, version)
    return Dependency(
        ecosystem=ECOSYSTEM,
        name=name,
        version=version,
        declared_in=path,
        scope="main",   # yarn.lock doesn't carry dev/peer info — joiner sets it
        is_lockfile=True,
        pin_style=pin_style,
        direct=False,
        purl=_build_purl(name, version),
        parser_confidence=_confidence(pin_style, version),
    )


# ---------------------------------------------------------------------------
# Berry parser (YAML)
# ---------------------------------------------------------------------------

def _parse_berry(text: str, path: Path) -> List[Dependency]:
    try:
        data = _safe_load(text)           # type: ignore[misc]
    except _yaml.YAMLError as e:          # type: ignore[union-attr]
        logger.warning(
            "sca.parsers.yarn_lock: Berry YAML parse failed for %s: %s",
            path, e,
        )
        return []
    if not isinstance(data, dict):
        return []

    deps: List[Dependency] = []
    for descriptor, entry in data.items():
        if descriptor == "__metadata":
            continue
        if not isinstance(descriptor, str) or not isinstance(entry, dict):
            continue
        # Berry lets one record cover multiple comma-separated descriptors;
        # any one of them resolves to the same version.
        first_descriptor = descriptor.split(",")[0].strip()
        name = _name_from_descriptor(first_descriptor)
        if not name:
            continue
        version = entry.get("version") if isinstance(entry.get("version"), str) else None
        resolution = entry.get("resolution")
        pin_style = _pin_from_berry_resolution(resolution, version)

        deps.append(Dependency(
            ecosystem=ECOSYSTEM,
            name=name,
            version=version,
            declared_in=path,
            scope="main",
            is_lockfile=True,
            pin_style=pin_style,
            direct=False,
            purl=_build_purl(name, version),
            parser_confidence=_confidence(pin_style, version),
        ))
    return deps


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _name_from_descriptor(descriptor: str) -> Optional[str]:
    """Extract the package name from a yarn descriptor.

    Examples (input → output):
      ``lodash@^4.17.21``                 → ``lodash``
      ``"@types/node@^20.10.0"``          → ``@types/node``
      ``lodash@npm:^4.17.21``             → ``lodash``        (Berry)
      ``@scope/pkg@workspace:./pkgs/x``   → ``@scope/pkg``    (Berry)
    """
    s = descriptor.strip().strip('"')
    if not s:
        return None
    if s.startswith("@"):
        # Scoped: skip the leading '@' so the first split occurs after
        # the scope's '/'.
        slash = s.find("/")
        if slash == -1:
            return None
        sep = s.find("@", slash)
        if sep == -1:
            return s   # no version qualifier (rare)
        return s[:sep]
    sep = s.find("@")
    if sep == -1:
        return s
    return s[:sep]


def _pin_from_resolved(resolved: str, version: Optional[str]) -> PinStyle:
    """Classify pin style from a v1 ``resolved "..."`` URL."""
    if resolved.startswith(("git+", "git:", "git@")):
        return PinStyle.GIT
    if resolved.startswith("file:"):
        return PinStyle.PATH
    if version:
        return PinStyle.EXACT
    return PinStyle.WILDCARD


def _pin_from_berry_resolution(
    resolution: Any, version: Optional[str],
) -> PinStyle:
    """Classify pin style from a Berry ``resolution: "..."`` field."""
    if isinstance(resolution, str):
        # Format: ``name@protocol:specifier`` — ``git`` / ``patch`` /
        # ``workspace`` / ``portal`` are non-version sources.
        if "@git+" in resolution or resolution.endswith("@git"):
            return PinStyle.GIT
        if "@workspace:" in resolution or "@portal:" in resolution:
            return PinStyle.PATH
        if "@file:" in resolution:
            return PinStyle.PATH
    if version:
        return PinStyle.EXACT
    return PinStyle.WILDCARD


def _build_purl(name: str, version: Optional[str]) -> str:
    base = f"pkg:npm/{name}"
    if version:
        return f"{base}@{version}"
    return base


def _confidence(pin_style: PinStyle, version: Optional[str]) -> Confidence:
    if pin_style is PinStyle.GIT:
        return Confidence("medium", reason="yarn.lock git source")
    if pin_style is PinStyle.PATH:
        return Confidence("medium", reason="yarn.lock workspace/file source")
    if version is None:
        return Confidence("low", reason="yarn.lock entry without version")
    return Confidence("high", reason="yarn.lock resolved entry")


register(filenames=["yarn.lock"])(parse)

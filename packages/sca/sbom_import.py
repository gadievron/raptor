"""Import a CycloneDX SBOM as scan input.

Operators with an existing SBOM (from Trivy, Snyk, Anchore, etc.)
can feed it directly to raptor-sca instead of relying on manifest
discovery. Useful when:

  * The build system produces an SBOM during the build (cargo
    auditable, Maven cyclonedx-plugin, etc.) and we want to scan
    the exact deps the build resolved rather than re-parsing the
    manifests.
  * The deps live in a build that raptor-sca's parsers can't fully
    decode (Bazel, custom toolchains).
  * Cross-tool comparison — give raptor-sca + Snyk the same SBOM
    and compare findings.

The importer maps CycloneDX 1.5 ``components`` → SCA
``Dependency`` rows. Each component must have a ``purl`` (the
canonical identifier we key on); components without one are
skipped with a warning. The ``purl`` carries the ecosystem
(``pkg:pypi/...``, ``pkg:npm/...``, etc.) and authoritative
name + version.

The output ``Dependency`` rows feed the pipeline at the same
seam ``parse_manifest`` does — join → OSV → KEV → EPSS →
hygiene → supply-chain → report. The discovery + parser-
dispatch phases are SKIPPED when ``--sbom`` is set.

Limitations (documented):

  * SPDX SBOMs not supported — different schema. Convert via
    ``cyclonedx-cli`` first if needed.
  * Component ``properties`` extension fields are NOT preserved
    in the Dependency row. The find-and-route code only needs
    purl + version + scope.
  * Transitive expansion is skipped when an SBOM provides
    transitives — the SBOM's component list is authoritative.
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import List, Optional, Tuple

from .models import Confidence, Dependency, PinStyle

logger = logging.getLogger(__name__)


# Map ``pkg:<eco>/...`` purl prefix → SCA's canonical ecosystem
# label. SCA uses the OSV ecosystem names so this also dispatches
# correctly into the vuln-matcher.
_PURL_ECO_MAP = {
    "pypi": "PyPI",
    "npm": "npm",
    "maven": "Maven",
    "cargo": "Cargo",
    "gem": "RubyGems",
    "rubygems": "RubyGems",
    "golang": "Go",
    "go": "Go",
    "nuget": "NuGet",
    "composer": "Packagist",
    "github": "GitHub",
    "deb": "Debian",
    "rpm": "RPM",
    "apk": "Alpine",
    "oci": "Container",
}

# CycloneDX ``scope`` enum → SCA scope. CycloneDX has fewer
# values; map conservatively.
_SCOPE_MAP = {
    "required": "main",
    "optional": "optional",
    "excluded": "excluded",
}


def parse_cyclonedx(path: Path) -> Tuple[List[Dependency], List[str]]:
    """Parse a CycloneDX 1.5 JSON file at ``path``.

    Returns ``(deps, warnings)`` — the parsed dep list and a list
    of human-readable diagnostics (skipped-component reasons).
    Errors that prevent the entire SBOM from being read (bad
    JSON, wrong shape) raise ``ValueError``.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise ValueError(f"failed to read SBOM file {path}: {e}") from e

    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise ValueError(f"invalid JSON in SBOM {path}: {e}") from e

    if not isinstance(data, dict):
        raise ValueError(
            f"SBOM root must be a JSON object, got {type(data).__name__}"
        )

    # Sanity: bomFormat must be "CycloneDX". Operators who pass
    # an SPDX SBOM see a clear error rather than a silent miss.
    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        raise ValueError(
            f"SBOM at {path} is not CycloneDX (bomFormat={bom_format!r}); "
            f"SPDX or other formats are not supported. Convert with "
            f"`cyclonedx-cli convert` first if needed."
        )

    components = data.get("components")
    if not isinstance(components, list):
        # No components is technically valid CycloneDX (empty SBOM),
        # but it produces zero deps; emit empty + warning.
        return [], [f"SBOM at {path} has no components array"]

    deps: List[Dependency] = []
    warnings: List[str] = []
    for i, comp in enumerate(components):
        if not isinstance(comp, dict):
            warnings.append(f"component #{i}: not a dict, skipping")
            continue
        dep = _component_to_dep(comp, sbom_path=path)
        if dep is None:
            name = comp.get("name", f"component #{i}")
            warnings.append(
                f"component {name}: no usable purl, skipped"
            )
            continue
        deps.append(dep)
    return deps, warnings


def _component_to_dep(
    comp: dict, *, sbom_path: Path,
) -> Optional[Dependency]:
    """Convert one CycloneDX component → SCA ``Dependency``.

    Returns ``None`` when the component lacks the minimum
    information we need (purl OR name+version+ecosystem-hint).
    """
    purl = comp.get("purl")
    if purl:
        parsed = _parse_purl(purl)
        if parsed is None:
            return None
        ecosystem, name, version = parsed
    else:
        # Fallback: use ``name`` + ``version`` directly; ecosystem
        # is unguessable without purl, so skip.
        return None

    scope_raw = comp.get("scope", "required")
    scope = _SCOPE_MAP.get(scope_raw, "main")

    # ``licenses`` → first SPDX expression / id we find.
    declared_license = _extract_license(comp.get("licenses"))

    # Type → pin_style + direct heuristic.
    # CycloneDX ``type`` is library/application/framework/etc.; we
    # default to ``exact`` (the version we got was resolved by the
    # SBOM producer) and ``direct=True`` (CycloneDX doesn't tag
    # direct vs transitive uniformly).
    pin_style = PinStyle.EXACT if version else PinStyle.UNKNOWN

    return Dependency(
        ecosystem=ecosystem,
        name=name,
        version=version,
        declared_in=sbom_path,
        scope=scope,
        is_lockfile=True,           # SBOM = resolved snapshot
        pin_style=pin_style,
        direct=True,
        purl=purl,
        parser_confidence=Confidence(
            level="high", numeric=0.95,
            reason="imported from CycloneDX SBOM",
        ),
        declared_license=declared_license,
        source_kind="sbom_import",
    )


# Compact purl parser. Spec is at https://github.com/package-url/purl-spec
# Format: ``pkg:type/namespace/name@version?qualifiers#subpath``
# We extract: type, name (with namespace prefix where applicable),
# version. Subpath + qualifiers are dropped — SCA's matcher keys
# on the (eco, name, version) triple.
_PURL_RE = re.compile(
    r"^pkg:(?P<type>[A-Za-z0-9.+-]+)"
    r"/(?P<path>[^@?#]+)"
    r"(?:@(?P<version>[^?#]+))?"
    r"(?:[?#].*)?$"
)


def _parse_purl(purl: str) -> Optional[Tuple[str, str, Optional[str]]]:
    """Return ``(ecosystem, name, version)`` parsed from a purl,
    or ``None`` for malformed / unsupported ecosystems."""
    if not isinstance(purl, str):
        return None
    m = _PURL_RE.match(purl)
    if m is None:
        logger.debug("sbom_import: unparseable purl: %r", purl)
        return None
    type_lc = m.group("type").lower()
    ecosystem = _PURL_ECO_MAP.get(type_lc)
    if ecosystem is None:
        logger.debug(
            "sbom_import: unsupported purl type %r in %r",
            type_lc, purl,
        )
        return None
    path = m.group("path")
    version = m.group("version")

    # Maven uses ``pkg:maven/<group>/<artifact>@<version>`` — recombine
    # group + artifact with ``:`` (SCA's canonical Maven name).
    if ecosystem == "Maven" and "/" in path:
        group, artifact = path.rsplit("/", 1)
        name = f"{group}:{artifact}"
    elif ecosystem == "Go" and "/" in path:
        # Go modules: ``pkg:golang/<host>/<owner>/<repo>@<version>``
        # → the FULL path is the import path; keep it intact.
        name = path
    elif ecosystem == "npm" and path.startswith("%40"):
        # URL-encoded ``@scope/name`` — decode the leading ``@``.
        name = "@" + path[3:]
    else:
        # Single-segment ecosystems (PyPI, Cargo, RubyGems, NuGet,
        # Packagist) — name is the trailing path component.
        name = path.rsplit("/", 1)[-1]

    return (ecosystem, name, version)


def _extract_license(licenses_block) -> Optional[str]:
    """Pull the first license expression / SPDX id from a CycloneDX
    licenses array.

    CycloneDX license shape is one of:
      ``[{"license": {"id": "Apache-2.0"}}]``
      ``[{"license": {"name": "Custom"}}]``
      ``[{"expression": "Apache-2.0 OR MIT"}]``

    Returns the first non-empty value or ``None``."""
    if not isinstance(licenses_block, list):
        return None
    for entry in licenses_block:
        if not isinstance(entry, dict):
            continue
        # Expression form
        expr = entry.get("expression")
        if expr:
            return str(expr).strip()
        # License-object form
        lic = entry.get("license")
        if isinstance(lic, dict):
            for key in ("id", "name"):
                val = lic.get(key)
                if val:
                    return str(val).strip()
    return None


__all__ = [
    "parse_cyclonedx",
]

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
``Dependency`` rows. Components need a supported ``purl`` to enter vulnerability matching;
other components stay in the retained inventory and licence-policy view,
with a diagnostic explaining the matching gap. The ``purl`` carries the ecosystem
(``pkg:pypi/...``, ``pkg:npm/...``, etc.) and authoritative
name + version.

The output ``Dependency`` rows feed the pipeline at the same
seam ``parse_manifest`` does — join → OSV → KEV → EPSS →
hygiene → supply-chain → report. The discovery + parser-
dispatch phases are SKIPPED when ``--sbom`` is set.

The full document is retained separately from the scannable Dependency view.
Non-package inventory and provenance therefore survive CycloneDX enrichment.
Only CycloneDX 1.5 is supported; unsupported versions fail explicitly.
"""

from __future__ import annotations

import json
import math
from collections import deque
from dataclasses import dataclass, replace
import logging
import re
import urllib.parse

from .models import Confidence, Dependency, PinStyle
from .parsers import _safe_read
from .parsers._base import PARSE_ESCAPE_ERRORS
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

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
    # OSV's "Red Hat" ecosystem covers RHEL / Rocky / Alma and keys by
    # source package name — the same mapping the image-scan path
    # (core/oci/sbom) applies to every RPM database. The literal "RPM"
    # label binds to NO advisory surface: components carrying it
    # imported cleanly and silently got zero advisories.
    "rpm": "Red Hat",
    "apk": "Alpine",
    "oci": "Container",
}
# Closure invariant (pinned by test_purl_eco_map_values_all_bind_to_
# an_advisory_surface): every VALUE above must be OSV-queryable or an
# explicitly documented visibility-only label ("GitHub" → OSS-Fuzz
# fallback; "Container" → image-scan path).

# CycloneDX ``scope`` enum → SCA scope. CycloneDX has fewer
# values; map conservatively.
_SCOPE_MAP = {
    "required": "main",
    "optional": "optional",
    "excluded": "excluded",
}


def read_cyclonedx(path: Path) -> ImportedBom:
    """Parse a CycloneDX 1.5 JSON file at ``path``.

    Return the retained document, scan projection, and coverage diagnostics.
    Errors that prevent the entire SBOM from being read (bad
    JSON, wrong shape) raise ``ValueError``.
    """
    # Bounded read: an SBOM is target/operator-supplied input, and an
    # unbounded read_text is a memory-exhaustion primitive. The 50 MB
    # package cap comfortably covers legitimate monorepo SBOMs.
    # follow_symlinks=True is deliberate: this path is OPERATOR-NAMED
    # (--sbom-input on the CLI), not discovered in the scanned tree,
    # and build-emitted SBOMs legitimately sit behind build-dir
    # symlinks. Tree-discovered manifests keep the hardened default.
    try:
        text = _safe_read.read_bounded(path, follow_symlinks=True, strict_utf8=True)
    except UnicodeDecodeError as exc:
        raise ValueError("SBOM must contain valid UTF-8") from exc
    if text is None:
        cap = _safe_read._MAX_PARSER_BYTES
        try:
            size = path.stat().st_size
        except OSError as e:
            msg = f"failed to read SBOM file {path}: {e}"
            raise ValueError(msg) from e
        if size > cap:
            msg = (
                f"SBOM file {path} is {size} bytes — exceeds the "
                f"{cap}-byte read cap; refusing to parse"
            )
        else:
            msg = f"failed to read SBOM file {path}"
        raise ValueError(msg)

    try:
        data = json.loads(text, object_pairs_hook=_unique_object)
    except (json.JSONDecodeError, *PARSE_ESCAPE_ERRORS) as e:  # type: ignore[misc]  # hostile-input escape classes
        msg = f"invalid JSON in SBOM {path}: {e}"
        raise ValueError(msg) from e

    if not isinstance(data, dict):
        msg = f"SBOM root must be a JSON object, got {type(data).__name__}"
        raise ValueError(msg)

    # Sanity: bomFormat must be "CycloneDX". Operators who pass
    # an SPDX SBOM see a clear error rather than a silent miss.
    bom_format = data.get("bomFormat")
    if bom_format != "CycloneDX":
        msg = (
            f"SBOM at {path} is not CycloneDX (bomFormat={bom_format!r}); "
            f"SPDX or other formats are not supported. Convert with "
            f"`cyclonedx-cli convert` first if needed."
        )
        raise ValueError(msg)

    if data.get("specVersion") != "1.5":
        raise ValueError("unsupported CycloneDX specVersion; expected 1.5")
    if "version" in data and (type(data["version"]) is not int or data["version"] < 1):
        raise ValueError("CycloneDX document version must be a positive integer")
    _check_document(data)
    metadata = data.get("metadata", {})
    if not isinstance(metadata, dict) or not isinstance(metadata.get("component", {}), dict):
        raise ValueError("CycloneDX metadata/component must be objects")
    tools = metadata.get("tools", [])
    if not isinstance(tools, (list, dict)) or (isinstance(tools, dict) and not isinstance(tools.get("components", []), list)):
        raise ValueError("invalid CycloneDX metadata tools")
    if not isinstance(data.get("vulnerabilities", []), list):
        raise ValueError("CycloneDX vulnerabilities must be an array")
    components = _components(data)
    known_refs = _references(data)
    external_refs: set[str] = set()
    depths = _graph_depths(data, known_refs, external_refs)
    component_refs: list[str] = []
    for i, comp in enumerate(components):
        ref = comp.get("bom-ref")
        if ref is None:
            ref = f"urn:sca:component:{i}"
            while ref in known_refs:
                ref += ":imported"
            known_refs.add(ref)
        component_refs.append(ref)
    deps: list[Dependency] = []
    diagnostics: list[str] = []
    if external_refs:
        diagnostics.append("external BOM references are retained; their components were not loaded for vulnerability matching")
    refs: dict[str, list[str]] = {}
    license_deps: list[Dependency] = []
    for comp, component_ref in zip(components, component_refs):
        dep = _component_to_dep(comp, sbom_path=path)
        if dep is None:
            diagnostics.append(
                f"component {comp.get('name', component_ref)}: no usable purl; "
                "retained in inventory, not vulnerability-matched"
            )
            declarations = _license_declarations(comp.get("licenses"))
            license_deps.append(Dependency(
                ecosystem="SBOM", name=comp["name"], version=comp.get("version"),
                declared_in=path, scope=_SCOPE_MAP[comp.get("scope", "required")],
                is_lockfile=True, pin_style=PinStyle.UNKNOWN, direct=True,
                purl=comp.get("purl", ""), parser_confidence=Confidence("high", reason="SBOM inventory declaration"),
                declared_license=declarations[0] if len(declarations) == 1 else None,
                license_declarations=declarations, source_kind="sbom_import",
                source_extra={"sbom_ref": component_ref},
            ))
            continue
        if not dep.version:
            diagnostics.append(f"component {comp['name']}: no resolved version; vulnerability coverage is incomplete")
        depth = depths.get(component_ref)
        direct_claims = [p.get("value") for p in comp.get("properties", [])
                         if p.get("name") == "raptor:direct"]
        if any(value not in {"true", "false"} for value in direct_claims) or len(set(direct_claims)) > 1:
            raise ValueError("invalid or contradictory SBOM directness property")
        if depth is not None:
            dep.direct = depth == 1
            dep.transitive_depth = max(0, depth - 1)
            if direct_claims and (direct_claims[0] == "true") != dep.direct:
                raise ValueError("SBOM directness property conflicts with its dependency graph")
        elif direct_claims:
            dep.direct = direct_claims[0] == "true"
        dep.source_extra = {"sbom_ref": component_ref,
                            "sbom_directness": "graph" if depth is not None else "property" if direct_claims else "unknown"}
        if depth is None and not direct_claims:
            dep.parser_confidence = replace(dep.parser_confidence, reason=(
                dep.parser_confidence.reason + "; directness unknown, conservatively treated as direct"))
        refs.setdefault(dep.key(), []).append(component_ref)
        deps.append(dep)
    notices: list[str] = []
    if "signature" in data:
        notices.append("document signature is retained on input but removed from modified output")
    changed = _reference_changes(components, metadata.get("component", {}))
    if any("signature" in c and id(c) in changed for c in components + [metadata.get("component", {})]):
        notices.append("component signatures are retained on input but removed where output adds component references")
    return ImportedBom(data, deps, diagnostics, refs, component_refs, license_deps, notices)


@dataclass
class ImportedBom:
    """A complete inventory plus its explicitly separate vulnerability-scan view."""

    document: dict
    dependencies: list[Dependency]
    coverage_gaps: list[str]
    refs_by_key: dict[str, list[str]]
    component_refs: list[str]
    license_dependencies: list[Dependency]
    notices: list[str]

    @property
    def warnings(self) -> list[str]:
        return self.coverage_gaps + self.notices


def parse_cyclonedx(path: Path) -> tuple[list[Dependency], list[str]]:
    """Compatibility API returning the scan projection and its diagnostics."""
    imported = read_cyclonedx(path)
    return imported.dependencies, imported.warnings


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        try:
            key.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("invalid Unicode scalar in SBOM object key") from exc
        if key in result:
            raise ValueError(f"duplicate SBOM object key {key[:80]!r}")
        result[key] = value
    return result


def _check_document(data: dict) -> None:
    # Structural validation, not a claim of complete JSON-schema validation.
    # Traverse iteratively and bound nesting before copy/export touches input.
    stack = [(data, 0)]
    while stack:
        value, depth = stack.pop()
        if depth > 64:
            raise ValueError("CycloneDX document exceeds supported nesting depth")
        if isinstance(value, dict):
            stack.extend((v, depth + 1) for v in value.values())
        elif isinstance(value, list):
            stack.extend((v, depth + 1) for v in value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ValueError("non-finite number in CycloneDX document")
        elif isinstance(value, str):
            try:
                value.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("invalid Unicode scalar in SBOM document") from exc


def _components(data: dict) -> list[dict]:
    values = data.get("components", [])
    if not isinstance(values, list):
        raise ValueError("CycloneDX components must be an array")
    root_children = data.get("metadata", {}).get("component", {}).get("components", [])
    if not isinstance(root_children, list):
        raise ValueError("CycloneDX nested components must be arrays")
    stack = list(reversed(values + root_children))
    result = []
    while stack:
        comp = stack.pop()
        if not isinstance(comp, dict):
            raise ValueError("CycloneDX component must be an object")
        if not isinstance(comp.get("name"), str) or not comp["name"]:
            raise ValueError("CycloneDX component must have a nonempty name")
        if not isinstance(comp.get("scope", "required"), str) or comp.get("scope", "required") not in _SCOPE_MAP:
            raise ValueError("unsupported CycloneDX component scope")
        for field in ("purl", "version"):
            if field in comp and not isinstance(comp[field], str):
                raise ValueError(f"CycloneDX component {field} must be a string")
        properties = comp.get("properties", [])
        if not isinstance(properties, list) or any(not isinstance(p, dict) or not isinstance(p.get("name"), str)
                                                 or not isinstance(p.get("value"), str) for p in properties):
            raise ValueError("invalid CycloneDX component properties")
        _license_declarations(comp.get("licenses"))
        children = comp.get("components", [])
        if not isinstance(children, list):
            raise ValueError("CycloneDX nested components must be arrays")
        if len(result) >= 100_000:
            raise ValueError("CycloneDX component count exceeds 100000")
        result.append(comp)
        stack.extend(reversed(children))
    return result


def _reference_changes(components: list[dict], root: dict) -> set[int]:
    """Objects whose signed content changes when missing refs are assigned."""
    changed: set[int] = set()
    for component in reversed(components):
        if "bom-ref" not in component or any(id(c) in changed for c in component.get("components", [])):
            changed.add(id(component))
    if any(id(c) in changed for c in root.get("components", [])):
        changed.add(id(root))
    return changed


def _references(data: dict) -> set[str]:
    refs: set[str] = set()
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            if "bom-ref" in item:
                ref = item["bom-ref"]
                if not isinstance(ref, str) or not ref or ref in refs:
                    raise ValueError("empty, invalid, or duplicate CycloneDX bom-ref")
                refs.add(ref)
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
    return refs


def _graph_depths(data: dict, known_refs: set[str], external_refs: set[str]) -> dict[str, int]:
    graph = data.get("dependencies", [])
    if not isinstance(graph, list):
        raise ValueError("CycloneDX dependencies must be an array")
    edges: dict[str, list[str]] = {}
    for entry in graph:
        if not isinstance(entry, dict) or not isinstance(entry.get("ref"), str):
            raise ValueError("invalid CycloneDX dependency graph entry")
        ref, children = entry["ref"], entry.get("dependsOn", [])
        if not isinstance(children, list) or any(not isinstance(c, str) for c in children):
            raise ValueError("invalid CycloneDX dependsOn array")
        if ref in edges:
            raise ValueError("duplicate CycloneDX dependency graph entry")
        for target in [ref, *children]:
            if target not in known_refs:
                if not re.fullmatch(r"urn:cdx:[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}/[1-9][0-9]*(?:#.+)?", target):
                    raise ValueError("dangling CycloneDX dependency reference")
                external_refs.add(target)
        edges[ref] = children
    root = data.get("metadata", {}).get("component", {}).get("bom-ref")
    if root not in edges:
        return {}
    depths = {root: 0}
    pending = deque([root])
    while pending:
        current = pending.popleft()
        for child in edges.get(current, []):
            if child not in depths:
                depths[child] = depths[current] + 1
                pending.append(child)
    return depths


def _component_to_dep(
    comp: dict, *, sbom_path: Path,
) -> Dependency | None:
    """Convert one CycloneDX component → SCA ``Dependency``.

    Returns ``None`` when the PURL cannot identify a supported matching
    ecosystem. The original component remains in the inventory.
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

    if version is None:
        version = comp.get("version")
    elif comp.get("version") is not None and comp["version"] != version:
        raise ValueError("CycloneDX component version conflicts with its purl")

    scope_raw = comp.get("scope", "required")
    scope = _SCOPE_MAP.get(scope_raw, "main")

    # Keep every declaration; the compatibility field represents only a single choice.
    declarations = _license_declarations(comp.get("licenses"))
    declared_license = declarations[0] if len(declarations) == 1 else None

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
        license_declarations=declarations,
        source_kind="sbom_import",
    )


# Compact purl parser. Spec is at https://github.com/package-url/purl-spec
# Format: ``pkg:type/namespace/name@version?qualifiers#subpath``
# Extract matching coordinates and the distro context used by advisory feeds.
# The complete PURL, including qualifiers/subpath, remains on the Dependency.
_PURL_RE = re.compile(
    r"^pkg:(?P<type>[A-Za-z0-9.+-]+)"
    r"/(?P<path_and_version>[^?#]+)"
    r"(?:[?#].*)?$"
)


def _parse_purl(purl: str) -> tuple[str, str, str | None] | None:
    """Return ``(ecosystem, name, version)`` parsed from a purl,
    or ``None`` for malformed / unsupported ecosystems."""
    if not isinstance(purl, str):
        return None
    if re.search(r"%(?![0-9A-Fa-f]{2})", purl):
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
    path_and_version = m.group("path_and_version")
    package_path = path_and_version.rsplit("@", 1)[0] if "@" in path_and_version else path_and_version
    try:
        namespace = urllib.parse.unquote(package_path.split("/", 1)[0], errors="strict").lower() if "/" in package_path else ""
    except UnicodeDecodeError:
        return None
    query = purl.partition("?")[2].partition("#")[0]
    try:
        qualifiers = urllib.parse.parse_qs(query, keep_blank_values=True,
                                         strict_parsing=True, max_num_fields=64,
                                         errors="strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if any(len(values) != 1 for values in qualifiers.values()):
        return None
    distro = qualifiers.get("distro", [""])[0].lower()
    if type_lc == "deb":
        if (namespace == "debian" and distro.startswith("ubuntu-")) or (namespace == "ubuntu" and distro.startswith("debian-")):
            return None
        if namespace == "ubuntu" or distro.startswith("ubuntu-"):
            ecosystem = "Ubuntu"
        elif namespace not in {"", "debian"}:
            return None
    elif type_lc == "apk":
        release = re.fullmatch(r"alpine-([0-9]+)\.([0-9]+)(?:\.[0-9]+)?", distro)
        if release:
            ecosystem = f"Alpine:v{release[1]}.{release[2]}"
        else:
            return None
    elif type_lc == "rpm" and namespace not in {"", "redhat", "rhel", "centos", "rocky", "almalinux"}:
        return None
    last_at = path_and_version.rfind("@")
    if last_at > 0:
        path = path_and_version[:last_at]
        # purl components are percent-encoded (spec: a literal ``%``
        # is ``%25``) — rpm versions carry the epoch as ``1%3A...``,
        # and a literal ``%3A`` never matches any advisory range.
        try:
            version: str | None = urllib.parse.unquote(
                path_and_version[last_at + 1:], errors="strict")
        except UnicodeDecodeError:
            return None
        if not version:
            return None
    else:
        path = path_and_version
        version = None

    try:
        path = urllib.parse.unquote(path, errors="strict")
    except UnicodeDecodeError:
        return None

    # Maven uses ``pkg:maven/<group>/<artifact>@<version>`` — recombine
    # group + artifact with ``:`` (SCA's canonical Maven name).
    if ecosystem == "Maven" and "/" in path:
        group, artifact = path.rsplit("/", 1)
        name = f"{group}:{artifact}"
    elif ecosystem == "GitHub" and "/" in path:
        name = path  # repository identity includes its owner
    elif ecosystem == "Go" and "/" in path:
        # Go modules: ``pkg:golang/<host>/<owner>/<repo>@<version>``
        # → the FULL path is the import path; keep it intact.
        name = path
    elif ecosystem == "npm" and (path.startswith(("%40", "@"))):
        name = "@" + path[3:] if path.startswith("%40") else path
    elif ecosystem == "Packagist" and "/" in path:
        # Composer/Packagist names are ``vendor/package`` (two-segment).
        name = path
    else:
        # Single-segment ecosystems (PyPI, Cargo, RubyGems, NuGet)
        # — name is the trailing path component.
        name = path.rsplit("/", 1)[-1]

    return (ecosystem, name, version)


def _license_declarations(block) -> tuple[str, ...]:
    """Keep each declaration; a list does not invent an AND/OR expression."""
    if block is None:
        return ()
    if not isinstance(block, list):
        raise ValueError("CycloneDX licenses must be an array")
    result = []
    expression = False
    for entry in block:
        if not isinstance(entry, dict):
            raise ValueError("CycloneDX license choice must be an object")
        if "expression" in entry:
            value = entry["expression"]
            expression = True
            if "license" in entry:
                raise ValueError("ambiguous CycloneDX license choice")
        else:
            license_object = entry.get("license")
            if not isinstance(license_object, dict) or ("id" in license_object) == ("name" in license_object):
                raise ValueError("CycloneDX license requires either id or name")
            value = license_object.get("id", license_object.get("name"))
        if not isinstance(value, str) or not value.strip():
            raise ValueError("CycloneDX license must be a nonempty string")
        result.append(value.strip())
    if expression and len(result) != 1:
        raise ValueError("CycloneDX license expression must be the only choice")
    return tuple(result)


__all__ = ["parse_cyclonedx", "read_cyclonedx", "ImportedBom"]

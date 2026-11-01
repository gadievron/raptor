"""CycloneDX 1.5 SBOM emitter — VEX-enriched.

Two top-level arrays:

- ``components``      — one per resolved/declared dep, with purl, scope,
                        license, and supplier metadata when known.
- ``vulnerabilities`` — one per emitted ``VulnFinding``, cross-referenced
                        to its ``components`` entry by ``bom-ref``. This
                        gives consumers a single artefact that doubles
                        as an SBOM and a VEX (Vulnerability Exploitability
                        eXchange) document.

Layout follows CycloneDX 1.5 — see
https://cyclonedx.org/docs/1.5/json/ — with only the fields we can
populate from the mechanical pipeline. Imported documents retain their
original components, evidence, references, relationships, and root identity;
only scan metadata and VEX assertions are enriched.

Why one combined SBOM+VEX file rather than two: most downstream tooling
(Dependency-Track, OWASP CycloneDX CLI) accepts the merged shape, and
emitting twice doubles operator confusion about which is canonical.
"""

from __future__ import annotations

import logging
from copy import deepcopy
import uuid
from collections import OrderedDict
from datetime import datetime, timezone
from typing import Any, TYPE_CHECKING

from core.json import save_json
from core.security.prompt_output_sanitise import sanitise_string


if TYPE_CHECKING:
    from .models import Advisory, Dependency, VulnFinding
    from .sbom_import import ImportedBom
    from collections.abc import Iterable, Mapping, Sequence
    from pathlib import Path

# Cap on advisory text in CycloneDX vulnerability.description. Larger
# than the sanitiser default (500) because Dependency-Track and other
# consumers render the full description; matches the SARIF cap so the
# two emitters stay in sync.
_SBOM_DESCRIPTION_MAX_CHARS = 2000

logger = logging.getLogger(__name__)

_BOM_FORMAT = "CycloneDX"
_SPEC_VERSION = "1.5"

# CycloneDX scope vocabulary: required | optional | excluded.
# Our internal scope strings collapse onto these.
_SCOPE_MAP = {
    "main": "required",
    "build": "optional",
    "dev": "optional",
    "test": "optional",
    "peer": "required",
    "optional": "optional",
    "excluded": "excluded",
}


def write_sbom_json(
    path: Path,
    *,
    deps: Sequence[Dependency],
    vuln_findings: Sequence[VulnFinding] = (),
    target_name: str | None = None,
    serial_number: str | None = None,
    image_fingerprints: dict[str, Any] | None = None,
    project_license: str | None = None,
    source_bom: ImportedBom | None = None,
) -> int:
    """Atomically write the merged SBOM+VEX document; return component count."""
    bom = build_bom(deps=deps, vuln_findings=vuln_findings,
                    target_name=target_name,
                    serial_number=serial_number,
                    image_fingerprints=image_fingerprints,
                    project_license=project_license, source_bom=source_bom)
    save_json(path, bom)
    return len(bom.get("components", []))


def build_bom(
    *,
    deps: Sequence[Dependency],
    vuln_findings: Sequence[VulnFinding] = (),
    target_name: str | None = None,
    generated_at: datetime | None = None,
    serial_number: str | None = None,
    image_fingerprints: dict[str, Any] | None = None,
    project_license: str | None = None,
    source_bom: ImportedBom | None = None,
) -> dict[str, Any]:
    """Return the CycloneDX 1.5 BOM dict (in serialisation order).

    ``serial_number`` — a ``urn:uuid:`` identifier for this
    specific BOM instance. CycloneDX-OPTIONAL but preferred by
    consumers (Dependency-Track keys on it to detect BOM
    re-uploads vs new BOMs). Defaults to a freshly-generated
    UUID per call. Tests inject a fixed UUID for determinism.

    ``project_license`` — the scanned project's own manifest-declared
    license. Attached to ``metadata.component`` (the thing this BOM
    describes), never to any dep's ``components[]`` entry — a dep's
    license only ever comes from data that describes that dep.
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    if source_bom is not None:
        if source_bom.format != "CycloneDX":
            raise ValueError("CycloneDX preservation requires a CycloneDX source document")
        return _enrich_imported_bom(source_bom, vuln_findings, generated_at)
    if serial_number is None:
        serial_number = f"urn:uuid:{uuid.uuid4()}"
    components, by_key = _build_components(
        deps, image_fingerprints=image_fingerprints,
    )
    vulnerabilities = _build_vulnerabilities(vuln_findings, by_key)

    bom: dict[str, Any] = OrderedDict()
    bom["bomFormat"] = _BOM_FORMAT
    bom["specVersion"] = _SPEC_VERSION
    bom["serialNumber"] = serial_number
    bom["version"] = 1
    bom["metadata"] = {
        "timestamp": generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tools": [{
            "vendor": "raptor",
            "name": "sca",
            "version": "0.1",
        }],
    }
    if target_name:
        component: dict[str, Any] = {
            "type": "application",
            "name": target_name,
        }
        if project_license:
            component["licenses"] = _license_block(project_license)
        bom["metadata"]["component"] = component
    bom["components"] = components
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

def _build_components(
    deps: Sequence[Dependency],
    *,
    image_fingerprints: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Return (component list, ``Dependency.key()`` → ``bom-ref`` map).

    ``image_fingerprints`` — optional ref → :class:`core.binary.
    CapabilityFingerprint` mapping. When a dep is a container image
    (ecosystem ``"Container"`` or purl starting ``pkg:container/``)
    AND we have a fingerprint for its ref, attach the fingerprint's
    bucket-set + binary SHA + arch/bits/format as ``raptor:cap_fp:*``
    properties. Lets SBOM consumers (Dependency-Track / custom
    dashboards) compare image-binary capability surface across
    successive uploads without re-extracting the binary themselves.
    """
    seen: dict[str, dict[str, Any]] = OrderedDict()
    by_key: dict[str, str] = {}
    for d in deps:
        bom_ref = d.purl or d.key()
        if bom_ref in seen:
            # Merge: prefer rows with version present + license declared.
            existing = seen[bom_ref]
            scopes = [existing.get("scope", "optional"), _SCOPE_MAP.get(d.scope, "optional")]
            existing["scope"] = min(scopes, key={"required": 0, "optional": 1, "excluded": 2}.__getitem__)
            if not existing.get("version") and d.version:
                existing["version"] = d.version
            if not existing.get("licenses") and (d.declared_license or d.license_declarations):
                existing["licenses"] = _dependency_licenses(d)
            by_key[d.key()] = bom_ref
            continue
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": d.name,
        }
        if d.version:
            comp["version"] = d.version
        if d.purl:
            comp["purl"] = d.purl
        comp["scope"] = _SCOPE_MAP.get(d.scope, "optional")
        if d.declared_license or d.license_declarations:
            comp["licenses"] = _dependency_licenses(d)
        comp["properties"] = [
            {"name": "raptor:ecosystem", "value": d.ecosystem},
            {"name": "raptor:direct", "value": "true" if d.direct else "false"},
            {"name": "raptor:is_lockfile",
             "value": "true" if d.is_lockfile else "false"},
            {"name": "raptor:pin_style", "value": d.pin_style.value},
            # Provenance: where this dep was declared and what kind of
            # file declared it. Lets SBOM consumers triage by source
            # ("which deps came from a Dockerfile vs a manifest?") and
            # gives operators a one-step jump back to the source line.
            {"name": "raptor:source_kind", "value": d.source_kind},
            {"name": "raptor:declared_in",
             "value": str(d.declared_in)},
        ]
        if d.commented_out:
            comp["properties"].append({
                "name": "raptor:commented_out", "value": "true"
            })
        # source_extra fields surfaced as raptor:<key> properties.
        # Used today by ``dockerfile_from`` rows to expose
        # ``image`` / ``digest`` / ``stage_name`` so SBOM consumers
        # can group findings by base image and filter intermediate
        # build stages from the final-image view.
        if d.source_extra:
            for k, v in d.source_extra.items():
                if v is None:
                    continue
                comp["properties"].append({
                    "name": f"raptor:{k}",
                    "value": str(v),
                })
        # Capability-fingerprint enrichment for container components.
        fp_props = _fingerprint_properties(d, image_fingerprints)
        if fp_props:
            comp["properties"].extend(fp_props)
        seen[bom_ref] = comp
        by_key[d.key()] = bom_ref
    return list(seen.values()), by_key


def _enrich_imported_bom(
    source: ImportedBom, findings: Iterable[VulnFinding], generated_at: datetime,
) -> dict[str, Any]:
    """Preserve inventory/evidence; add this scan's VEX using original refs."""
    # read_cyclonedx bounds document depth before deepcopy is reached.
    bom = deepcopy(source.document)
    bom.pop("signature", None)  # modifying the document invalidates its signature
    bom["version"] = bom.get("version", 1) + 1
    metadata = bom.setdefault("metadata", {})
    metadata["timestamp"] = generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    tool = {"vendor": "raptor", "name": "sca", "version": "0.1"}
    tools = metadata.setdefault("tools", [])
    if isinstance(tools, list):
        if tool not in tools:
            tools.append(tool)
    elif isinstance(tools, dict):
        components = tools.setdefault("components", [])
        component = {"type": "application", "name": "raptor-sca", "version": "0.1"}
        if component not in components:
            components.append(component)
    from .sbom_import import _components, _reference_changes, _references
    components = _components(bom)
    if len(components) != len(source.component_refs):
        raise ValueError("SBOM component inventory changed after import")
    changed = _reference_changes(components, metadata.get("component", {}))
    for comp, ref in zip(components, source.component_refs):
        comp.setdefault("bom-ref", ref)
        if id(comp) in changed:
            comp.pop("signature", None)
    if id(metadata.get("component")) in changed:
        metadata["component"].pop("signature", None)
    used = _references(bom)
    new_findings = _build_vulnerabilities(findings, source.refs_by_key)
    for entry in new_findings:
        original_ref = entry["bom-ref"]
        ref = original_ref
        collision = 0
        while ref in used:
            collision += 1
            ref = f"{original_ref}:sca:{collision}"
        entry["bom-ref"] = ref
        used.add(ref)
    if new_findings:
        bom.setdefault("vulnerabilities", []).extend(new_findings)
    return bom


def _dependency_licenses(dep: Dependency) -> list[dict[str, Any]]:
    declarations = dep.license_declarations or (dep.declared_license,)
    result = []
    for declaration in declarations:
        if not declaration:
            continue
        block = _license_block(declaration)
        if len(declarations) > 1 and "expression" in block[0]:
            raise ValueError("multiple licence declarations cannot mix with SPDX expressions")
        result.extend(block)
    return result


def _fingerprint_properties(
    d: Dependency,
    image_fingerprints: dict[str, Any] | None,
) -> list[dict[str, str]]:
    """Build the ``raptor:cap_fp:*`` properties for one dep, or
    ``[]`` when:
      * ``image_fingerprints`` is unset / empty
      * the dep is not a container component
      * no fingerprint was computed for the resolved ref

    Resolution: try ``source_extra['image']`` first (the canonical
    ref the bumper recorded), then fall back to ``d.name`` (which
    is also the ref for container ecosystem deps)."""
    if not image_fingerprints:
        return []
    is_container = (
        (d.ecosystem == "Container")
        or (d.purl is not None and d.purl.startswith("pkg:container/"))
    )
    if not is_container:
        return []
    ref = (d.source_extra or {}).get("image") if d.source_extra else None
    fp = image_fingerprints.get(ref) if ref else None
    if fp is None:
        fp = image_fingerprints.get(d.name)
    if fp is None:
        return []

    buckets = sorted((getattr(fp, "capability_buckets", {}) or {}).keys())
    props: list[dict[str, str]] = [
        {"name": "raptor:cap_fp:schema_version",
         "value": str(getattr(fp, "schema_version", 1))},
        {"name": "raptor:cap_fp:buckets",
         "value": ",".join(buckets)},
    ]
    sha = getattr(fp, "binary_sha256", None)
    if sha:
        props.append(
            {"name": "raptor:cap_fp:binary_sha256", "value": str(sha)},
        )
    arch = getattr(fp, "arch", None)
    if arch:
        props.append({"name": "raptor:cap_fp:arch", "value": str(arch)})
    bits = getattr(fp, "bits", None)
    if bits:
        props.append(
            {"name": "raptor:cap_fp:bits", "value": str(bits)},
        )
    fmt = getattr(fp, "binary_format", None)
    if fmt:
        props.append(
            {"name": "raptor:cap_fp:format", "value": str(fmt)},
        )
    return props


def _license_block(spdx_or_name: str) -> list[dict[str, Any]]:
    """Wrap a license string in CycloneDX's list-of-licenses shape.

    A SPDX expression (contains ``OR``/``AND``/parens) goes into the
    ``expression`` field; a single license id/name goes into
    ``license.id`` (best-effort) or ``license.name``.
    """
    text = spdx_or_name.strip()
    if any(op in text for op in (" OR ", " AND ", "(", ")")):
        return [{"expression": text}]
    if _looks_like_spdx_id(text):
        return [{"license": {"id": text}}]
    return [{"license": {"name": text}}]


_SPDX_LIKE = (
    "MIT", "ISC", "BSD-2-Clause", "BSD-3-Clause",
    "Apache-2.0", "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0",
    "MPL-2.0", "AGPL-3.0", "EPL-1.0", "EPL-2.0",
    "Unlicense", "CC0-1.0", "WTFPL", "BSL-1.0", "0BSD",
)


def _looks_like_spdx_id(text: str) -> bool:
    if not text:
        return False
    if text in _SPDX_LIKE:
        return True
    if " " in text:
        return False
    return all(c.isalnum() or c in ".-+" for c in text)


# ---------------------------------------------------------------------------
# Vulnerabilities (VEX block)
# ---------------------------------------------------------------------------

def _build_vulnerabilities(
    vuln_findings: Iterable[VulnFinding],
    by_key: Mapping[str, str | list[str]],
) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in vuln_findings:
        bom_ref = by_key.get(f.dependency.key())
        primary: Advisory | None = f.advisories[0] if f.advisories else None
        if primary is None:
            continue
        entry: dict[str, Any] = {
            "bom-ref": f.finding_id,
            "id": primary.osv_id,
            "source": {"name": "OSV", "url": "https://osv.dev"},
        }
        if primary.aliases:
            entry["references"] = [
                {"id": alias, "source": {"name": "alias"}}
                for alias in primary.aliases[:5]
            ]
        if primary.summary:
            # CycloneDX consumers (Dependency-Track, OWASP CDX CLI)
            # render ``description`` as markdown / rich text — raw
            # OSV summaries are untrusted third-party content that
            # could carry autofetch markup or terminal-injection
            # bytes. sanitise_string defangs both before emission.
            entry["description"] = sanitise_string(
                primary.summary, max_chars=_SBOM_DESCRIPTION_MAX_CHARS,
            )
        if primary.severity:
            entry["ratings"] = [{
                "source": {"name": "OSV"},
                "score": primary.severity.score,
                "severity": primary.severity.severity,
                "method": "CVSSv31",
                "vector": primary.severity.vector,
            }]
        if bom_ref:
            refs = bom_ref if isinstance(bom_ref, list) else [bom_ref]
            entry["affects"] = [{"ref": ref} for ref in refs]
        analysis: dict[str, Any] = {}
        if f.reachability.verdict == "likely_called":
            analysis["state"] = "exploitable"
            # No "justification": the CycloneDX impact-analysis
            # justification enum only has not-affected reasons
            # (code_not_reachable, requires_configuration, ...) —
            # "in_triage" is a STATE, and emitting it as a
            # justification made strict consumers (Dependency-Track,
            # cyclonedx-cli validate) reject the whole BOM.
            analysis["detail"] = (
                "function-level reachability: vulnerable symbol called "
                "on a live execution path"
            )
        elif f.reachability.verdict == "imported":
            analysis["state"] = "exploitable"
            analysis["detail"] = (
                "module-level reachability: imported in non-test source"
            )
        elif f.reachability.verdict in (
            "not_reachable", "not_function_reachable",
        ):
            # ``not_function_reachable`` is "the dep is imported but
            # the specific affected function isn't called" — same
            # CycloneDX/VEX state as not_reachable (the vulnerable
            # code isn't reached), with a more specific detail.
            analysis["state"] = "not_affected"
            analysis["justification"] = "code_not_reachable"
            analysis["detail"] = f.reachability.confidence.reason
        elif f.reachability.verdict == "called_in_dead_code":
            # The vulnerable function IS called from project code,
            # but the call sites all live in private-named hosts
            # with no callers — likely dead code, but the host
            # could still be an unseen entry point. Medium
            # confidence on the dead-code claim doesn't justify a
            # ``not_affected`` VEX state (which would silently hide
            # the finding from SBOM consumers); ``in_triage``
            # surfaces it for human review with the supporting
            # reason.
            analysis["state"] = "in_triage"
            # No "justification": the enum semantically pairs with
            # not_affected only (the likely_called branch above
            # documents the same rule) — the dead-code reasoning
            # belongs in detail.
            analysis["detail"] = f.reachability.confidence.reason
        elif f.in_kev:
            analysis["state"] = "exploitable"
            # No justification — see the reachability arms above.
            analysis["detail"] = "CVE listed in CISA KEV catalog"
        if f.epss is not None:
            entry.setdefault("properties", []).append({
                "name": "raptor:epss", "value": f"{f.epss:.5f}",
            })
        if f.in_kev:
            entry.setdefault("properties", []).append({
                "name": "raptor:in_kev", "value": "true",
            })
        if analysis:
            entry["analysis"] = analysis
        if f.fixed_version:
            entry.setdefault("properties", []).append({
                "name": "raptor:fixed_version", "value": f.fixed_version,
            })
        out.append(entry)
    return out


__all__ = ["build_bom", "write_sbom_json"]

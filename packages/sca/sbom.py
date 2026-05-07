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
populate from the mechanical pipeline. Optional fields we leave out
(hashes, externalReferences, evidence) can land in a follow-up.

Why one combined SBOM+VEX file rather than two: most downstream tooling
(Dependency-Track, OWASP CycloneDX CLI) accepts the merged shape, and
emitting twice doubles operator confusion about which is canonical.
"""

from __future__ import annotations

import json as _json
import logging
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .models import Advisory, Dependency, VulnFinding

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
}


def write_sbom_json(
    path: Path,
    *,
    deps: Sequence[Dependency],
    vuln_findings: Sequence[VulnFinding] = (),
    target_name: Optional[str] = None,
) -> int:
    """Atomically write the merged SBOM+VEX document; return component count."""
    bom = build_bom(deps=deps, vuln_findings=vuln_findings,
                    target_name=target_name)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as fh:
        _json.dump(bom, fh, indent=2)
    tmp.replace(path)
    return len(bom.get("components", []))


def build_bom(
    *,
    deps: Sequence[Dependency],
    vuln_findings: Sequence[VulnFinding] = (),
    target_name: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Return the CycloneDX 1.5 BOM dict (in serialisation order)."""
    generated_at = generated_at or datetime.now(timezone.utc)
    components, by_key = _build_components(deps)
    vulnerabilities = _build_vulnerabilities(vuln_findings, by_key)

    bom: Dict[str, Any] = OrderedDict()
    bom["bomFormat"] = _BOM_FORMAT
    bom["specVersion"] = _SPEC_VERSION
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
        bom["metadata"]["component"] = {
            "type": "application",
            "name": target_name,
        }
    bom["components"] = components
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


# ---------------------------------------------------------------------------
# Components
# ---------------------------------------------------------------------------

def _build_components(
    deps: Sequence[Dependency],
) -> Tuple[List[Dict[str, Any]], Dict[str, str]]:
    """Return (component list, ``Dependency.key()`` → ``bom-ref`` map)."""
    seen: Dict[str, Dict[str, Any]] = OrderedDict()
    by_key: Dict[str, str] = {}
    for d in deps:
        bom_ref = d.purl or d.key()
        if bom_ref in seen:
            # Merge: prefer rows with version present + license declared.
            existing = seen[bom_ref]
            if not existing.get("version") and d.version:
                existing["version"] = d.version
            if not existing.get("licenses") and d.declared_license:
                existing["licenses"] = _license_block(d.declared_license)
            by_key[d.key()] = bom_ref
            continue
        comp: Dict[str, Any] = {
            "type": "library",
            "bom-ref": bom_ref,
            "name": d.name,
        }
        if d.version:
            comp["version"] = d.version
        if d.purl:
            comp["purl"] = d.purl
        comp["scope"] = _SCOPE_MAP.get(d.scope, "optional")
        if d.declared_license:
            comp["licenses"] = _license_block(d.declared_license)
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
        seen[bom_ref] = comp
        by_key[d.key()] = bom_ref
    return list(seen.values()), by_key


def _license_block(spdx_or_name: str) -> List[Dict[str, Any]]:
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
    if text in _SPDX_LIKE:
        return True
    # Heuristic: SPDX IDs are short, no spaces, only letters/digits/dot/-/+ .
    if " " in text:
        return False
    return all(c.isalnum() or c in ".-+" for c in text)


# ---------------------------------------------------------------------------
# Vulnerabilities (VEX block)
# ---------------------------------------------------------------------------

def _build_vulnerabilities(
    vuln_findings: Iterable[VulnFinding],
    by_key: Dict[str, str],
) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in vuln_findings:
        bom_ref = by_key.get(f.dependency.key())
        primary: Optional[Advisory] = f.advisories[0] if f.advisories else None
        if primary is None:
            continue
        entry: Dict[str, Any] = {
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
            entry["description"] = primary.summary
        if primary.severity:
            entry["ratings"] = [{
                "source": {"name": "OSV"},
                "score": primary.severity.score,
                "severity": primary.severity.severity,
                "method": "CVSSv3",
                "vector": primary.severity.vector,
            }]
        if bom_ref:
            entry["affects"] = [{"ref": bom_ref}]
        analysis: Dict[str, Any] = {}
        if f.reachability.verdict == "imported":
            analysis["state"] = "exploitable"
            analysis["justification"] = "in_triage"
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
        elif f.in_kev:
            analysis["state"] = "exploitable"
            analysis["justification"] = "in_triage"
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

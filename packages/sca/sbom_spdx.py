"""SPDX 2.3 SBOM emitter — alternative output format.

Some compliance pipelines mandate SPDX (NTIA's Minimum Elements
for an SBOM cite both CycloneDX and SPDX as acceptable; specific
procurement programmes may require one). This module emits SPDX
2.3 JSON alongside the existing CycloneDX 1.5 output when the
operator passes ``--spdx``.

Pure data-shape conversion — same Dependency / VulnFinding inputs
the CycloneDX emitter consumes, just rendered to the SPDX schema.
No semantic difference; downstream consumers pick whichever
format they're set up for.

SPDX 2.3 spec: https://spdx.github.io/spdx-spec/v2.3/

What's emitted:

  * One ``packages[]`` entry per Dependency (the SPDX equivalent
    of CycloneDX's ``components[]``).
  * Document-level metadata (name, namespace URI, creation info,
    license-list version).
  * ``relationships[]`` linking the SPDX document to its packages
    via ``DESCRIBES``.

What's NOT emitted (deferred):

  * Vulnerability assertions — SPDX 2.3 doesn't have a native VEX
    block (SPDX 3.0 will). Operators wanting VEX-in-SPDX should
    use the CycloneDX output for now.
  * File-level metadata, snippets, hashes — RAPTOR-side scans
    don't compute file checksums per dep.
"""

from __future__ import annotations

import json as _json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from ._atomic import atomic_write_text
from .models import Dependency

logger = logging.getLogger(__name__)


# SPDX license-list version we declare. Spec recommends pinning so
# consumers know which SPDX-license-list snapshot the IDs validate
# against. Bump when SPDX publishes a major addition.
_SPDX_LICENSE_LIST_VERSION = "3.24"


def write_sbom_spdx_json(
    path: Path,
    *,
    deps: Iterable[Dependency],
    target_name: str,
    namespace_uri: Optional[str] = None,
) -> None:
    """Render an SPDX 2.3 JSON SBOM and write it atomically."""
    doc = render_sbom_spdx(
        deps=deps, target_name=target_name,
        namespace_uri=namespace_uri,
    )
    atomic_write_text(path, _json.dumps(doc, indent=2) + "\n")


def render_sbom_spdx(
    *,
    deps: Iterable[Dependency],
    target_name: str,
    namespace_uri: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the SPDX 2.3 document dict (does not write to disk)."""
    deps_list = list(deps)
    spdx_doc_id = "SPDXRef-DOCUMENT"
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Default namespace is a unique URI per document — SPDX requires
    # globally-unique. We compose target name + timestamp; operators
    # passing ``namespace_uri`` override.
    if namespace_uri is None:
        namespace_uri = (
            f"https://raptor-sca.local/spdxdocs/"
            f"{target_name}-{created.replace(':', '').replace('-', '')}"
        )

    packages: List[Dict[str, Any]] = []
    relationships: List[Dict[str, str]] = [
        # SPDX requires a DESCRIBES relationship from the document
        # to its top-level package(s). Without a single "root"
        # package we DESCRIBE every dep — equivalent semantically.
    ]
    seen_refs: set = set()
    for d in deps_list:
        spdx_id = _spdx_id_for(d, seen_refs)
        package = _package_block(d, spdx_id)
        packages.append(package)
        relationships.append({
            "spdxElementId": spdx_doc_id,
            "relatedSpdxElement": spdx_id,
            "relationshipType": "DESCRIBES",
        })

    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": spdx_doc_id,
        "name": f"{target_name}-sbom",
        "documentNamespace": namespace_uri,
        "creationInfo": {
            "created": created,
            "creators": ["Tool: raptor-sca"],
            "licenseListVersion": _SPDX_LICENSE_LIST_VERSION,
        },
        "packages": packages,
        "relationships": relationships,
    }


def _package_block(dep: Dependency, spdx_id: str) -> Dict[str, Any]:
    """Render one Dependency as an SPDX ``packages[]`` entry."""
    pkg: Dict[str, Any] = {
        "SPDXID": spdx_id,
        "name": dep.name,
        # SPDX requires either ``downloadLocation`` (URL) OR
        # ``NOASSERTION``. We don't have download URLs in the
        # mechanical pipeline; consumers needing them should
        # derive from purl.
        "downloadLocation": "NOASSERTION",
        # ``filesAnalyzed=false`` — we don't compute per-file
        # checksums for the dep tree. Required field on packages
        # without ``files`` per SPDX 2.3.
        "filesAnalyzed": False,
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": dep.purl,
            },
        ],
    }
    if dep.version:
        pkg["versionInfo"] = dep.version
    # License — SPDX has two fields: declared (what the package
    # says) vs concluded (what the analyser concluded). Without
    # a separate concluded-license analysis pass, we use NOASSERTION
    # for ``licenseConcluded`` per SPDX best practice.
    if dep.declared_license:
        pkg["licenseDeclared"] = _spdx_license_value(dep.declared_license)
    else:
        pkg["licenseDeclared"] = "NOASSERTION"
    pkg["licenseConcluded"] = "NOASSERTION"
    # ``copyrightText`` is required-or-NOASSERTION; we don't extract.
    pkg["copyrightText"] = "NOASSERTION"
    # Supplier — for OS packages we'd say ``Organization: <distro>``;
    # for registry packages we don't reliably know. NOASSERTION.
    pkg["supplier"] = "NOASSERTION"
    return pkg


def _spdx_license_value(declared: str) -> str:
    """Validate the license string fits SPDX expression grammar.

    SPDX 2.3 accepts: SPDX license IDs (``MIT``), composite
    expressions (``MIT OR Apache-2.0``), or ``NOASSERTION``.
    Free-text license strings should use ``LicenseRef-...``
    in the document; we don't manage that today, so anything
    not-obviously-SPDX falls back to ``NOASSERTION``.

    Heuristic: SPDX IDs / expressions are short, alphanumeric +
    ``- + . ()  AND OR WITH``. Anything else is flagged as
    NOASSERTION rather than risking SPDX-validator rejection.
    """
    text = declared.strip()
    if not text:
        return "NOASSERTION"
    # Accept obvious SPDX shapes; reject sentences / URLs / etc.
    allowed_chars = set(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789-+. ()"
    )
    if not all(c in allowed_chars for c in text):
        return "NOASSERTION"
    # English-prose detector — reject any token that's all-lowercase
    # AND all-alphabetic AND not an SPDX keyword (AND / OR / WITH).
    # "See the LICENSE file for details" gets rejected because "see",
    # "the", "license", "file", "for", "details" all match;
    # "MIT OR Apache-2.0" passes because "mit" is too short, "or" is
    # a keyword, "apache-2.0" isn't all-alphabetic.
    keywords = {"and", "or", "with"}
    for tok in text.split():
        low = tok.lower()
        if (tok.islower() and tok.isalpha()
                and low not in keywords
                and len(tok) >= 3):
            return "NOASSERTION"
    return text


def _spdx_id_for(dep: Dependency, seen: set) -> str:
    """Stable SPDX-ID for a Dependency.

    SPDX requires ``SPDXRef-<id>`` where id matches
    ``[A-Za-z0-9.-]+`` (no underscores, slashes, colons). We
    derive from ``ecosystem-name-version`` with non-conforming
    chars replaced by ``-``, plus a collision suffix if needed.
    """
    base = f"{dep.ecosystem}-{dep.name}-{dep.version or 'unknown'}"
    safe = "".join(c if c.isalnum() or c in ".-" else "-" for c in base)
    spdx_id = f"SPDXRef-{safe}"
    if spdx_id not in seen:
        seen.add(spdx_id)
        return spdx_id
    # Collision (same dep declared in multiple manifests at the
    # same version) — append a counter.
    n = 2
    while f"{spdx_id}-{n}" in seen:
        n += 1
    spdx_id = f"{spdx_id}-{n}"
    seen.add(spdx_id)
    return spdx_id


__all__ = ["render_sbom_spdx", "write_sbom_spdx_json"]

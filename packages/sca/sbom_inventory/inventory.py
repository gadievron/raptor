"""Project validated CycloneDX/SPDX and collected evidence into reusable audit records."""
from __future__ import annotations

import base64
from dataclasses import asdict
import hashlib
import re
from pathlib import Path, PurePosixPath
import urllib.parse

from core.oci.evidence import read_catalogue
from ..sbom_import import _check_document, _components, _license_declarations, _read_cyclonedx
from ..sbom_spdx_import import _read_spdx
from .coverage import collect
from .source import MAX_NOTICE_BYTES
from .projection import CycloneProjection, spdx_file, native_file, native_package, discard
from .model import FORMAT, Inventory, Notice, Record, from_snapshot, validate


def _embedded(content, embedded, *, path, encoding=""):
    if not isinstance(content, str):
        raise ValueError("embedded notice content must be a string")
    if encoding not in {"", "base64"}:
        raise ValueError("unsupported embedded notice encoding")
    encoded_limit = ((MAX_NOTICE_BYTES + 2) // 3) * 4 if encoding == "base64" else MAX_NOTICE_BYTES
    if len(content) > encoded_limit:
        raise ValueError("embedded notice exceeds size budget")
    raw = base64.b64decode(content, validate=True) if encoding == "base64" else content.encode("utf-8")
    if len(raw) > MAX_NOTICE_BYTES:
        raise ValueError("embedded notice exceeds size budget")
    sha = hashlib.sha256(raw).hexdigest()
    embedded[sha] = raw
    return Notice(sha, path, "embedded_sbom_text")


def _document_inventory(data, sha, name, *, known_refs=None):
    _check_document(data)
    embedded = {}
    extra_notices = []
    if "bomFormat" in data and "spdxVersion" in data:
        raise ValueError("ambiguous SBOM format markers")
    if "spdxVersion" in data:
        imported = _read_spdx(data, Path(name))
        inventory = Inventory("SPDX-2.3", sha, data["documentNamespace"], diagnostics=list(imported.warnings))
        extracted = {}
        for entry in data.get("hasExtractedLicensingInfos", []):
            if entry.get("extractedText"):
                extracted[entry["licenseId"]] = _embedded(entry["extractedText"], embedded, path=entry["licenseId"])
                extra_notices.append(extracted[entry["licenseId"]])
        for package in data.get("packages", []):
            declared = package.get("licenseDeclared", "")
            purls = [r["referenceLocator"] for r in package.get("externalRefs", []) if r.get("referenceType") == "purl"]
            row = Record(package["SPDXID"], package["name"], package.get("versionInfo", ""), "package",
                         purls[0] if purls else "", declarations=[declared] if declared else [])
            if package.get("primaryPackagePurpose") in {"OPERATING-SYSTEM", "CONTAINER"}:
                row.scope = "subjects"
            row.evidence["license_concluded"] = package.get("licenseConcluded", "")
            # Index only the identifiers actually named in this declaration.
            # Scanning every extracted licence per package amplifies input work.
            identifiers = dict.fromkeys(re.findall(r"[A-Za-z0-9.+:-]+", declared))
            row.notices = [extracted[key] for key in identifiers if key in extracted]
            row.notice_status = "captured" if row.notices else "not_assessed"
            inventory.records.append(row)
        inventory.file_count = len(data.get("files", []))
        edges = {}
        for rel in data.get("relationships", []):
            a, b = rel["spdxElementId"], rel["relatedSpdxElement"]
            if rel["relationshipType"] == "DEPENDENCY_OF":
                a, b = b, a
            elif rel["relationshipType"] != "DEPENDS_ON":
                continue
            edges.setdefault(a, set()).add(b)
    else:
        imported = _read_cyclonedx(data, Path(name), _known_refs=known_refs)
        inventory = Inventory("CycloneDX-1.5", sha, str(data.get("serialNumber", "")), diagnostics=list(imported.warnings))
        for component, ref in zip(_components(data), imported.component_refs):
            if component.get("type") == "file":
                inventory.file_count += 1
                continue
            group = component.get("group", "")
            display_name = (group + "/" if group else "") + component["name"]
            row = Record(ref, display_name, component.get("version", ""), component.get("type", "library"),
                         component.get("purl", ""), declarations=list(_license_declarations(component.get("licenses"))))
            if component.get("type") in {"operating-system", "container"}:
                row.scope = "subjects"
            for claim in component.get("licenses", []):
                license_text = claim.get("license", {}).get("text")
                if license_text is not None:
                    if not isinstance(license_text, dict):
                        raise ValueError("invalid embedded CycloneDX notice")
                    row.notices.append(_embedded(license_text.get("content"), embedded,
                                                 path=ref, encoding=license_text.get("encoding", "")))
            row.notice_status = "captured" if row.notices else "not_assessed"
            inventory.records.append(row)
        edges = {entry["ref"]: set(entry.get("dependsOn", [])) for entry in data.get("dependencies", [])}
    # Only supplied package relationships enter this graph; file, document
    # and external references remain outside package membership counts.
    by_id = {p.id: p for p in inventory.records}
    outside = 0
    for row in inventory.records:
        row.graph_supplied = row.id in edges
        row.children = sorted(ref for ref in edges.get(row.id, ()) if ref in by_id)
        outside += sum(ref not in by_id for ref in edges.get(row.id, ()))
        for ref in row.children:
            by_id[ref].parents.append(row.id)
    if outside:
        inventory.diagnostics.append(f"{outside} supplied edges reference non-package or external records")
    inventory.notice_files = list({(n.path, n.sha256, n.origin): n for n in ([notice for p in inventory.records for notice in p.notices] + extra_notices)}.values())
    return inventory, embedded


def _notice(record):
    origin = record.get("origin") or record.get("notice_origin") or "captured_file"
    path = record.get("path") or record.get("source_member") or record["sha256"]
    if path.startswith("/usr/share/common-licenses/"):
        origin = "standard_license_reference"
    return Notice(record["sha256"], path, origin, record.get("content_kind", "notice_candidate"),
                  record.get("catalogue_layer_diff_id", ""), record.get("visibility", "not_recorded"))


def _bundle(source):
    digest = source.read("image-digest.txt", 128).decode("ascii").strip()
    catalogue = source.read_json("syft.json", projectors={"files": native_file, "artifacts": native_package,
                                                        "artifactRelationships": discard})
    coverage = collect(PurePosixPath("."), digest, read=source.read, catalogue=catalogue)
    del catalogue
    if coverage.metrics is None:
        raise ValueError("evidence audit unavailable: " + "; ".join(coverage.errors))
    projection = CycloneProjection()
    data, sha = source.read_json("prepared/sbom.cdx.json", projectors={"components": projection.component}, observe=projection.observe)
    inventory, embedded = _document_inventory(data, sha, "prepared/sbom.cdx.json", known_refs=projection.refs)
    del data
    inventory.subject = digest
    inventory.coverage = asdict(coverage)
    provenance, _ = source.read_json("prepared/provenance.json")
    evidence = provenance["notice_evidence"]
    records = {row["id"]: row for row in evidence["packages"]}
    source_assessments = {row["id"]: row for row in provenance.get("packages", [])}
    matched = set()
    for row in inventory.records:
        package_ids = urllib.parse.parse_qs(urllib.parse.urlsplit(row.id).query).get("package-id", [])
        if len(package_ids) != 1 or package_ids[0] not in records:
            continue
        key = package_ids[0]
        if key in matched:
            raise ValueError("multiple SBOM packages claim one catalogue identity")
        matched.add(key)
        proof = records[key]
        row.evidence["catalogue_package_id"] = key
        row.evidence["notice_gaps"] = proof["gaps"]
        if key in source_assessments:
            row.evidence["source_assessment"] = source_assessments[key]
        row.notices = [_notice(f) for f in proof["files"] if f["content_kind"] == "notice_candidate"]
        row.notice_status = "captured" if row.notices and not proof["gaps"] else "missing"
    if matched != records.keys():
        raise ValueError("prepared SBOM does not cover the complete notice inventory")
    all_files = [item for row in records.values() for item in row["files"]]
    all_files.extend(evidence.get("unassociated_files", []))
    inventory.notice_files = list({(f["path"], f["catalogue_layer_diff_id"], f["sha256"]): _notice(f)
                                   for f in all_files if f["content_kind"] == "notice_candidate"}.values())
    for receipt in coverage.native_notice_collections:
        for item in receipt.get("files", []):
            if item.get("content_kind") != "source_sbom":
                continue
            candidates = read_catalogue(source.blob(item["sha256"]))
            if candidates.get("format") != "raptor-cargo-source-inventory":
                continue
            for package in candidates["packages"]:
                declared = package.get("license_declared")
                row = Record(receipt["name"] + ":" + package["name"] + "@" + package["version"],
                             package["name"], package["version"], "Cargo", scope="source-candidates",
                             declarations=[declared] if declared else [])
                row.evidence = {"tool": receipt["name"], "source": package.get("source"),
                                "archive_sha256": package.get("archive_sha256"),
                                "distributor_notice": package.get("distributor_notice"),
                                "notice_source_match": package.get("notice_source_match")}
                row.notices = [_notice(n) for n in package.get("notices", [])]
                row.notice_status = "captured" if row.notices else "missing"
                inventory.records.append(row)
    return inventory, embedded


def read_inventory(source, *, verify_notices=True, require_scan_document=False):
    """Read one inventory, verify original notice bytes lazily one blob at a time."""
    if require_scan_document and source.bundle:
        raise ValueError("verification requires the original emitted CycloneDX or SPDX document, not an evidence bundle")
    forms = [source.contains("notice-index.json"), source.contains("inventory.json"),
             source.contains("syft.json") or source.contains("prepared/provenance.json")]
    if sum(forms) > 1:
        raise ValueError("ambiguous evidence directory: inventory snapshot and original evidence formats overlap")
    if source.bundle and source.contains("inventory.json"):
        document, _ = source.read_json("inventory.json")
        inventory = from_snapshot(document)
        inventory.diagnostics.append("Inventory snapshot contains recorded evidence metadata; original notice bytes were not re-verified.")
        return inventory, {}
    if source.bundle and source.contains("notice-index.json"):
        index, _ = source.read_json("notice-index.json")
        if (index.get("format") != "raptor-sbom-notice-bundle" or type(index.get("schema_version")) is not int
                or index.get("schema_version") != 1):
            raise ValueError("unsupported notice bundle index")
        inventory, embedded = from_snapshot(index["inventory"]), {}
    elif source.bundle:
        inventory, embedded = _bundle(source)
    else:
        projection = CycloneProjection()
        document, sha = source.read_json(projectors={"components": projection.component, "files": spdx_file}, observe=projection.observe)
        if document.get("format") == FORMAT:
            if require_scan_document:
                raise ValueError("verification requires the original emitted CycloneDX or SPDX document, not an inventory snapshot")
            inventory = from_snapshot(document)
            inventory.diagnostics.append("Inventory snapshot contains recorded evidence metadata; original notice bytes were not re-verified.")
            return inventory, {}
        inventory, embedded = _document_inventory(document, sha, str(source.path), known_refs=projection.refs)
    validate(inventory)
    if verify_notices:
        failures = {}
        refs = inventory.notice_files + [n for p in inventory.records for n in p.notices]
        for sha in dict.fromkeys(n.sha256 for n in refs):
            if sha in embedded:
                continue
            try:
                source.blob(sha)
            except (OSError, ValueError) as error:
                failures[sha] = str(error)
        for row in inventory.records:
            if any(n.sha256 in failures for n in row.notices):
                row.notice_status = "invalid"
        for sha, message in failures.items():
            inventory.diagnostics.append("Notice " + sha + ": " + message)
        if failures and inventory.coverage is not None:
            inventory.coverage["status"] = "gaps"
            inventory.coverage["notice_verification_errors"] = failures
    return inventory, embedded

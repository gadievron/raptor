"""Shared catalogue-bound notice and ownership coverage; no image execution or network."""
from __future__ import annotations
from dataclasses import asdict, dataclass, field
import hashlib
import json
import re

MAX_BYTES = 64 * 1024 * 1024
LIMITATIONS = [
    "Coverage describes catalogued packages and retained notice candidates.",
    "Standard license reference copies remain distinct from upstream-authored notices.",
    "Source/build notes cover only explicitly assessed packages.",
    "Package checksum proofs, native identities and build-declared ownership are distinct evidence types.",
    "Nested payload completeness, legal review and exact build-source correspondence are separate checks.",
    "Gaps and unavailable audit evidence are warnings; they do not block publication.",
]


@dataclass
class _NativeIdentity:
    name: str
    version: str | None
    anchor_path: str | None
    sha256: str | None
    layer_id: str
    evidence_path: str
    evidence_sha256: str
    declared_files: list
    installed_metadata: list
    source_definitions: list


@dataclass
class Metrics:
    packages: int
    unresolved_declarations: int
    notice_gap_packages: int
    captured_notice_files: int
    source_gap_packages: int
    source_assessed_packages: int = 0
    unidentified_executables: int | None = None
    scanner_unidentified_executables: int | None = None
    checksum_matched_executables: int | None = None
    native_identity_matched_executables: int | None = None
    build_declared_executables: int | None = None
    version_identified_executables: int | None = None


@dataclass
class Issue:
    package_id: str
    name: str
    version: str
    ecosystem: str
    missing_declaration: bool
    notice_gaps: list[str]


@dataclass
class Report:
    image_digest: str
    status: str = "unavailable"
    schema_version: int = 1
    metrics: Metrics | None = None
    issues: list[Issue] = field(default_factory=list)
    source_gaps: list[dict] = field(default_factory=list)
    source_assessments: list[dict] = field(default_factory=list)
    inventory_candidates: list[dict] = field(default_factory=list)
    inventory_ownership: list[dict] = field(default_factory=list)
    native_identity_matches: list[dict] = field(default_factory=list)
    native_declaration_matches: list[dict] = field(default_factory=list)
    inventory_errors: list[str] = field(default_factory=list)
    native_notice_collections: list[dict] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _document(path, read, max_bytes):
    raw = read(path, max_bytes, raise_on_refusal=True)
    digest = hashlib.sha256(raw).hexdigest()
    text = raw.decode("utf-8")
    del raw
    result = json.loads(text, object_pairs_hook=_unique)
    del text
    if not isinstance(result, dict):
        raise ValueError("audit document must be an object")
    return result, digest


def _records(rows, identifiers, *, complete=True):
    if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
        raise ValueError("invalid package coverage records")
    indexed = {row["id"]: row for row in rows}
    if (len(indexed) != len(rows) or not set(indexed) <= identifiers
            or (complete and set(indexed) != identifiers)):
        raise ValueError("incomplete or duplicate package coverage inventory")
    return indexed


def match_inventory_ownership(native, candidates):
    from core.oci.file_ownership import match_inventory_ownership as match
    return match(native, candidates)



def _source_assessment(record):
    check = record.get("source_check") or {}
    if not isinstance(check, dict) or not isinstance(check.get("files", []), list):
        raise ValueError("invalid source assessment")
    status = check.get("status", "unverified")
    if not isinstance(status, str):
        raise ValueError("invalid source assessment status")
    matched = None
    if status in {"verified_interpreted_source", "verified_source_payload"}:
        matched = len(check.get("files", []))
    elif status == "verified_publisher_release_binary" and isinstance(check.get("binary"), dict):
        matched = 1
    return {"id": record["id"], "name": record["name"], "version": record.get("version", ""),
            "status": status, "matched_files": matched, "scope": check.get("scope", ""),
            "limitations": check.get("limitations", []), "gaps": record["gaps"]}

def collect(audit, image_digest, *, read=None, max_bytes=MAX_BYTES, catalogue=None):
    """Accept only complete evidence bound to the exact inventory and image."""
    from core.security.capped_read import read_capped
    from core.oci.evidence import subject
    read = read or read_capped
    from core.oci.license_declarations import catalogue_declaration_missing
    report = Report(image_digest)
    try:
        if not re.fullmatch(r"sha256:[a-f0-9]{64}", image_digest):
            raise ValueError("invalid exported image digest")
        native, native_sha = catalogue if catalogue is not None else _document(audit / "syft.json", read, max_bytes)
        provenance, _ = _document(audit / "prepared/provenance.json", read, max_bytes)
        image, _ = subject(native)
        notices = provenance["notice_evidence"]
        if image["manifest_digest"] != image_digest or notices["subject"] != image:
            raise ValueError("audit subject differs from the image being published")
        if not any(row.get("sha256") == native_sha for row in provenance["inputs"]):
            raise ValueError("prepared evidence is not bound to this inventory")
        artifacts = native["artifacts"]
        identifiers = {row["id"] for row in artifacts}
        if not identifiers or len(identifiers) != len(artifacts):
            raise ValueError("empty or duplicate package inventory")
        records = _records(notices["packages"], identifiers)
        sources = _records(provenance["packages"], identifiers, complete=False)
        files = set()
        for artifact in artifacts:
            row = records[artifact["id"]]
            gaps = row["gaps"]
            if (row["status"] not in {"notice_candidate_captured", "metadata_only", "no_associated_evidence"}
                    or not isinstance(gaps, list) or any(not isinstance(gap, str) for gap in gaps)):
                raise ValueError("invalid notice coverage status")
            if row["status"] != "notice_candidate_captured" and not gaps:
                raise ValueError("missing notice evidence has no recorded gap")
            if row["status"] == "notice_candidate_captured" and not any(
                    item["content_kind"] == "notice_candidate" for item in row["files"]):
                raise ValueError("captured notice status has no retained notice file")
            recovered = row.get("recovered_component_license") or row.get("recovered_distribution_license")
            missing = catalogue_declaration_missing(artifact) and not recovered
            if missing or gaps:
                report.issues.append(Issue(artifact["id"], artifact["name"], artifact.get("version", ""),
                                           artifact["type"], missing, gaps))
            files.update((item["path"], item["catalogue_layer_diff_id"], item["sha256"])
                         for item in row["files"] if item["content_kind"] == "notice_candidate")
        files.update((item["path"], item["catalogue_layer_diff_id"], item["sha256"])
                     for item in notices.get("unassociated_files", []) if item["content_kind"] == "notice_candidate")
        report.source_gaps = [sources[key] for key in sorted(sources) if sources[key]["gaps"]]
        report.source_assessments = [_source_assessment(sources[key]) for key in sorted(sources)]
        report.metrics = Metrics(len(artifacts), sum(item.missing_declaration for item in report.issues),
                                 sum(bool(item.notice_gaps) for item in report.issues), len(files), len(report.source_gaps), len(sources))
        evidence_files = list(notices.get("unassociated_files", []))
        for record in records.values():
            evidence_files.extend(record["files"])
        seen_receipts = set()
        native_identities = []
        for evidence in evidence_files:
            path = evidence["path"]
            if (not path.startswith("/usr/share/doc/raptor-native-notices/")
                    or not path.endswith("/NOTICE-PROVENANCE.json") or path in seen_receipts):
                continue
            seen_receipts.add(path)
            try:
                digest = evidence["sha256"]
                if not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError("invalid native notice receipt digest")
                receipt, actual = _document(audit / "prepared/notices/sha256" / digest, read, max_bytes)
                if actual != digest:
                    raise ValueError("native notice receipt hash mismatch")
                if receipt.get("status") not in {"unavailable", "release_notice_candidates_captured"}:
                    raise ValueError("invalid native notice collection status")
                dependency_notices = receipt.get("dependency_notices")
                if dependency_notices is not None:
                    if not isinstance(dependency_notices, dict):
                        raise ValueError("invalid native dependency notice summary")
                    counts = [dependency_notices.get(key) for key in ("candidates", "captured", "metadata_only", "unavailable")]
                    if any(type(value) is not int or value < 0 or value > 5000 for value in counts) or counts[0] != sum(counts[1:]):
                        raise ValueError("inconsistent native dependency notice counts")
                    distributor = dependency_notices.get("distributor_notices", 0)
                    if type(distributor) is not int or not 0 <= distributor <= counts[1]:
                        raise ValueError("invalid distributor notice count")
                toolchain = receipt.get("toolchain_notices")
                if toolchain is not None:
                    if not isinstance(toolchain, dict) or toolchain.get("status") not in {"unavailable", "release_library_notices_captured"}:
                        raise ValueError("invalid Rust toolchain notice status")
                    if toolchain["status"] == "release_library_notices_captured":
                        if (not isinstance(toolchain.get("version"), str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", toolchain["version"])
                                or type(toolchain.get("notice_files")) is not int or not 1 <= toolchain["notice_files"] <= 1000):
                            raise ValueError("invalid Rust toolchain notice summary")
                if receipt["status"] == "release_notice_candidates_captured":
                    if not receipt.get("files"):
                        raise ValueError("native notice collection has no files")
                    captured = {(item["path"], item["sha256"]) for item in evidence_files}
                    parent = path.rsplit("/", 1)[0]
                    if any((parent + "/" + item["file"], item["sha256"]) not in captured
                           for item in receipt["files"]):
                        raise ValueError("native release notice file missing from capture")
                    for item in receipt["files"]:
                        sha = item["sha256"]
                        if not re.fullmatch(r"[a-f0-9]{64}", sha):
                            raise ValueError("invalid native release notice digest")
                        source_sbom = item.get("content_kind") == "source_sbom"
                        if source_sbom and item["file"] != "NOTICE-SOURCE-SBOM-" + sha + ".json":
                            raise ValueError("invalid native source SBOM filename")
                        text = read(audit / "prepared/notices/sha256" / sha,
                                           (4 * 1024 * 1024 if source_sbom else 512 * 1024),
                                           raise_on_refusal=True)
                        if hashlib.sha256(text).hexdigest() != sha:
                            raise ValueError("native release notice hash mismatch")
                report.native_notice_collections.append(receipt)
                if (receipt["status"] == "release_notice_candidates_captured"
                        and any(item.get("content_kind") not in {"source_sbom", "build_declaration", "installed_build_metadata", "registry_metadata"} for item in receipt["files"])):
                    native_identities.append(asdict(_NativeIdentity(
                        name=receipt["name"], version=receipt.get("version"),
                        anchor_path=receipt.get("binary"), sha256=receipt.get("binary_sha256"),
                        layer_id=evidence["catalogue_layer_diff_id"], evidence_path=path,
                        evidence_sha256=digest, declared_files=receipt.get("declared_files", []),
                        installed_metadata=[item for item in receipt["files"] if item.get("content_kind") == "installed_build_metadata"],
                        source_definitions=[item["sha256"] for item in receipt["files"] if item.get("content_kind") == "build_declaration"],
                    )))
            except (OSError, ValueError, KeyError, TypeError) as exc:
                report.inventory_errors.append("Native notice receipt unavailable: " + str(exc))
        indexed_files = native.get("files")
        if not isinstance(indexed_files, list) or not indexed_files:
            report.inventory_errors.append("Executable inventory unavailable; completeness is unknown.")
        else:
            candidates = {}
            for entry in indexed_files:
                if not isinstance(entry, dict) or not isinstance(entry.get("unknowns", []), list):
                    raise ValueError("invalid executable inventory entry")
                if any(isinstance(reason, str) and "no package identified" in reason
                       for reason in entry.get("unknowns", [])):
                    path = entry["location"]["path"]
                    if not isinstance(path, str) or not path.startswith("/"):
                        raise ValueError("invalid executable inventory path")
                    candidates[(path, str(entry["location"].get("layerID")))] = {"path": path, "layer_id": entry["location"].get("layerID"),
                                        "reasons": entry["unknowns"]}
            raw_candidates = [candidates[key] for key in sorted(candidates)]
            report.inventory_ownership, report.inventory_candidates = match_inventory_ownership(native, raw_candidates)
            from core.oci.file_ownership import match_native_identities
            report.native_identity_matches, report.inventory_candidates = match_native_identities(
                native, report.inventory_candidates, native_identities)
            from core.oci.file_ownership import match_native_declarations
            report.native_declaration_matches, report.inventory_candidates = match_native_declarations(
                native, report.inventory_candidates, native_identities)
            report.metrics.build_declared_executables = sum(row["evidence_kind"] == "installed_build_declaration" for row in report.native_declaration_matches)
            report.metrics.version_identified_executables = sum(row["evidence_kind"] == "release_target_and_version" for row in report.native_declaration_matches)
            report.metrics.native_identity_matched_executables = len(report.native_identity_matches)
            report.metrics.scanner_unidentified_executables = len(raw_candidates)
            report.metrics.checksum_matched_executables = len(report.inventory_ownership)
            report.metrics.unidentified_executables = len(report.inventory_candidates)
        report.status = "gaps" if report.issues else "complete_for_catalogued_packages"
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as exc:
        # Partial results must never look like a clean or complete audit.
        report.metrics = None
        report.issues = []
        report.source_gaps = []
        report.source_assessments = []
        report.inventory_candidates = []
        report.inventory_ownership = []
        report.native_identity_matches = []
        report.native_declaration_matches = []
        report.inventory_errors = []
        report.native_notice_collections = []
        report.errors = [str(exc)]
    return report

"""Associate captured image notice candidates without changing licence claims.

Capture origin is recorded evidence, not a signed attestation. Preparation
binds it to the exact catalogue and checks all retained bytes; it does not
refetch image layers or establish runtime visibility or legal conclusions.
"""
from __future__ import annotations

from collections import defaultdict
from copy import deepcopy
import hashlib
import os
from pathlib import Path, PurePosixPath
import re

from core.json import dumps_artifact
from core.oci.evidence import MAX_CAPTURE_BYTES, _METADATA_NAMES, _path, subject
from core.oci.notice_paths import PackageNoticePaths, notice_name as _notice_name
from core.security.capped_read import read_capped

MAX_ASSOCIATIONS = 100_000

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMON = re.compile(r"/usr/share/common-licenses/([A-Za-z0-9][A-Za-z0-9.+_-]*)(?![A-Za-z0-9.+_/-])")
_PROJECTION = ("id", "name", "version", "type", "purl", "licenses")


def load_notices(root: Path, native: dict, native_sha256: str, report: dict) -> tuple[dict, dict[str, bytes]]:
    """Validate a capture and derive associations independently of its package IDs."""
    image, _ = subject(native)
    if type(report.get("version")) is not int or report["version"] not in {1, 2}:
        raise ValueError("unsupported notice evidence version")
    if report.get("subject") != image or report.get("catalogue_sha256") != native_sha256:
        raise ValueError("notice evidence subject, scope or catalogue hash mismatch")
    artifacts = {a["id"]: a for a in native["artifacts"]}
    if len(artifacts) != len(native["artifacts"]):
        raise ValueError("duplicate native package ID")
    expected = [{k: a[k] for k in _PROJECTION if k in a} for a in native["artifacts"]]
    if report.get("packages") != expected:
        raise ValueError("notice evidence package inventory mismatch")
    layers = {row["blob_digest"]: row["config_diff_id"] for row in image["layers"]}
    native_files = {(f["location"]["path"], f["location"]["layerID"]): f for f in native.get("files", [])}
    if len(native_files) != len(native.get("files", [])):
        raise ValueError("duplicate native file location")
    declared = {(loc["path"], loc["layerID"]) for a in native["artifacts"]
                for licence in a.get("licenses", []) for loc in licence.get("locations", [])}
    required = declared | {key for key, file in native_files.items()
                           if file.get("metadata", {}).get("type") in {None, "RegularFile"}
                           and (_notice_name(key[0]) or key[0].startswith("/usr/share/common-licenses/"))}
    package_paths = PackageNoticePaths(native["artifacts"])
    if report["version"] == 2:
        required.update(package_paths.records)
    probes = {(directory + "/" + name, layer) for (directory, layer), names in package_paths.pointers.items() for name in names}
    for artifact in native["artifacts"]:
        if artifact["type"] == "npm":
            for loc in artifact.get("locations", []):
                if PurePosixPath(loc["path"]).name == "package.json":
                    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE", "README.md"):
                        probes.add((str(PurePosixPath(loc["path"]).parent / name), loc["layerID"]))
    rows = report.get("files")
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise ValueError("invalid notice evidence file inventory")
    seen, blobs, validated = set(), {}, []
    total = 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    directories = []
    try:
        directories.append(os.open(root, flags | os.O_DIRECTORY))
        for part in ("notices", "sha256"):
            directories.append(os.open(part, flags | os.O_DIRECTORY, dir_fd=directories[-1]))
        for original in rows:
            row = deepcopy(original)
            path = _path(row["path"])
            origin = row["catalogue_layer_diff_id"]
            key = path, origin
            if key in seen or row["layer_blob_digest"] not in layers or layers[row["layer_blob_digest"]] != origin:
                raise ValueError("duplicate notice location or unrelated layer")
            seen.add(key)
            sha, size = row["sha256"], row["size"]
            if not isinstance(sha, str) or not _SHA256.fullmatch(sha) or type(size) is not int or size < 0:
                raise ValueError("invalid notice hash or size")
            if not isinstance(row.get("package_ids"), list) or any(p not in artifacts for p in row["package_ids"]):
                raise ValueError("notice evidence references an unknown package")
            file = native_files.get(key)
            if file:
                if file.get("metadata", {}).get("size", size) != size:
                    raise ValueError("notice size conflicts with native catalogue")
                for digest in file.get("digests", []):
                    if digest["algorithm"].lower() == "sha256" and digest["value"].lower() != sha:
                        raise ValueError("notice hash conflicts with native catalogue")
            recorded = package_paths.records.get(key)
            if recorded and ((recorded["sha256"] is not None and recorded["sha256"] != sha)
                             or (recorded["size"] is not None and recorded["size"] != size)):
                raise ValueError("notice evidence conflicts with Python RECORD")
            kind = row.get("content_kind")
            expected_kind = "package_metadata" if PurePosixPath(path).name in _METADATA_NAMES else "notice_candidate"
            if kind == "identity":
                if file is None or key in required or "notice_file" in row or row.get("roles") != ["identity_only"]:
                    raise ValueError("identity-only evidence must not contain copied bytes")
                validated.append(row)
                continue
            if key not in required | probes and key not in package_paths.records and not package_paths.matches(path, origin):
                raise ValueError("unexpected captured notice target")
            if kind != expected_kind or row.get("notice_file") != "notices/sha256/" + sha:
                raise ValueError("invalid notice classification or storage path")
            if row.get("visibility") not in {"catalogue_location", "layer_probe_runtime_visibility_unconfirmed"}:
                raise ValueError("unknown notice visibility")
            if sha not in blobs:
                total += size
                if total > MAX_CAPTURE_BYTES:
                    raise ValueError("notice evidence exceeds memory budget")
                data = read_capped(Path(sha), min(size, MAX_CAPTURE_BYTES), dir_fd=directories[-1], raise_on_refusal=True)
                if len(data) != size or hashlib.sha256(data).hexdigest() != sha:
                    raise ValueError("notice bytes disagree with their hash or size")
                blobs[sha] = data
            elif len(blobs[sha]) != size:
                raise ValueError("conflicting notice sizes")
            validated.append(row)
    finally:
        for directory in reversed(directories):
            os.close(directory)
    if required - seen:
        raise ValueError("notice evidence is missing required catalogue locations")
    return associate(native, image, validated, blobs), blobs


def associate(native: dict, image: dict, rows: list[dict], blobs: dict[str, bytes]) -> dict:
    """Retain exact-location claims and bounded package-directory candidates."""
    by_key = {(r["path"], r["catalogue_layer_diff_id"]): r for r in rows if r["content_kind"] != "identity"}
    by_path = defaultdict(list)
    for row in by_key.values():
        by_path[row["path"]].append(row)
    package_paths = PackageNoticePaths(native["artifacts"])
    directory_matches = defaultdict(list)
    match_count = 0
    for key, row in by_key.items():
        matches = package_paths.matches(*key)
        if key in package_paths.records:
            matches += [(identifier, "python_record_membership") for identifier in sorted(package_paths.records[key]["package_ids"])]
        match_count += len(matches)
        if match_count > MAX_ASSOCIATIONS:
            raise ValueError("notice association count exceeds memory budget")
        for identifier, reason in matches:
            directory_matches[identifier].append((row, reason))
    packages, associated = [], set()
    association_count = 0
    for artifact in native["artifacts"]:
        associations = {}

        def add(row: dict, reason: str):
            nonlocal association_count
            key = row["path"], row["catalogue_layer_diff_id"]
            if key not in associations:
                association_count += 1
                if association_count > MAX_ASSOCIATIONS:
                    raise ValueError("notice association count exceeds memory budget")
            entry = associations.setdefault(key, {**{k: row[k] for k in (
                "path", "layer_blob_digest", "catalogue_layer_diff_id", "sha256", "size", "notice_file", "content_kind", "visibility")}, "reasons": []})
            if reason not in entry["reasons"]:
                entry["reasons"].append(reason)
            associated.add(key)

        for licence in artifact.get("licenses", []):
            for loc in licence.get("locations", []):
                row = by_key.get((loc["path"], loc["layerID"]))
                if row is None:
                    raise ValueError("captured evidence is missing a declared licence location")
                add(row, "catalogue_licence_location")
        for row, reason in directory_matches[artifact["id"]]:
            add(row, reason)
        # Copyright files can refer to a separately installed Debian common text.
        # Ambiguous all-layer versions stay unresolved rather than being guessed.
        gaps = []
        if artifact["type"] == "deb":
            for entry in list(associations.values()):
                if PurePosixPath(entry["path"]).name != "copyright":
                    continue
                names = {name.rstrip(".") for name in (match[1] for match in _COMMON.finditer(
                    blobs[entry["sha256"]].decode("utf-8", errors="replace")))}
                for name in sorted(names):
                    matches = by_path["/usr/share/common-licenses/" + name]
                    if len(matches) == 1:
                        add(matches[0], "copyright_common_licence_reference")
                    else:
                        gaps.append("common licence text missing or ambiguous: " + name)
        evidence = sorted(associations.values(), key=lambda r: (r["path"], r["catalogue_layer_diff_id"]))
        status = ("notice_candidate_captured" if any(r["content_kind"] == "notice_candidate" for r in evidence)
                  else "metadata_only" if evidence else "no_associated_evidence")
        if status != "notice_candidate_captured":
            gaps.append("no associated notice candidate; licence text completeness is unverified")
        packages.append({"id": artifact["id"], "status": status, "files": evidence, "gaps": gaps})
    return {"version": 1, "subject": image, "packages": packages,
            "unassociated_files": [deepcopy(r) for r in rows if (r["path"], r["catalogue_layer_diff_id"]) not in associated],
            "scope": "catalogue and directory associations only; no licence conclusion, completeness or build-source certification"}


def append_notices(cdx: dict, spdx: dict, components: dict, packages: dict, summary: dict) -> None:
    """Use CDX evidence references/properties and SPDX comments, preserving claims."""
    for record in summary["packages"]:
        component, package = components[record["id"]], packages[record["id"]]
        component.pop("signature", None)
        encoded = dumps_artifact(record)
        component.setdefault("properties", []).append({"name": "raptor:notice-evidence", "value": encoded})
        for row in record["files"]:
            reference = {"type": "evidence", "url": row["notice_file"],
                         "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                         "comment": "Captured " + row["content_kind"] + "; applicable terms remain unreviewed"}
            if reference not in component.setdefault("externalReferences", []):
                component["externalReferences"].append(reference)
        package["comment"] = package.get("comment", "") + "\nRAPTOR notice evidence: " + encoded
    cdx.pop("signature", None)
    cdx.setdefault("properties", []).append({"name": "raptor:notice-evidence:scope", "value": summary["scope"]})
    cdx.setdefault("externalReferences", []).append({"type": "evidence", "url": "notice-evidence.json"})
    spdx["comment"] = spdx.get("comment", "") + "\nRAPTOR notice evidence: notice-evidence.json; " + summary["scope"]

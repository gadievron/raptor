"""Associate captured notices and recover explicit distribution declarations.

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
from core.oci.common_licenses import COMMON_ALIASES, COMMON_DIRECTORY, common_alias_target, corrected_common_reference
from core.oci.notice_paths import PackageNoticePaths, component_notice_paths, notice_name as _notice_name
from core.security.capped_read import read_capped

MAX_ASSOCIATIONS = 100_000

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_COMMON = re.compile(r"/usr/share/common-licenses/([A-Za-z0-9][A-Za-z0-9.+_-]*)(?![A-Za-z0-9.+_/-])")
_PROJECTION = ("id", "name", "version", "type", "purl", "licenses")


def load_notices(root: Path, native: dict, native_sha256: str, report: dict, *, owner_reader=None) -> tuple[dict, dict[str, bytes]]:
    """Validate a capture and derive associations independently of its package IDs."""
    image, _ = subject(native)
    if type(report.get("version")) is not int or report["version"] not in {1, 2, 3, 4}:
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
    if report["version"] >= 2:
        required.update(package_paths.records)
    if report["version"] >= 3:
        required.update(package_paths.metadata)
    probes = {(directory + "/" + name, layer) for (directory, layer), names in package_paths.pointers.items() for name in names}
    for artifact in native["artifacts"]:
        if artifact["type"] == "npm":
            for loc in artifact.get("locations", []):
                if PurePosixPath(loc["path"]).name == "package.json":
                    for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE", "README.md"):
                        probes.add((str(PurePosixPath(loc["path"]).parent / name), loc["layerID"]))
    probes.update(key for artifact in native["artifacts"] for key in component_notice_paths(artifact))
    common_origins = {origin for path, origin in native_files if path.startswith(COMMON_DIRECTORY)}
    common_probes = {(COMMON_DIRECTORY + alias, origin) for origin in common_origins for alias in COMMON_ALIASES}
    if report["version"] >= 4:
        probes.update(common_probes)
    rows = report.get("files")
    if not isinstance(rows, list) or len(rows) > 100_000:
        raise ValueError("invalid notice evidence file inventory")
    seen, blobs, validated = set(), {}, []
    total = 0
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    directories = []
    failed = False
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
    except BaseException:
        failed = True
        raise
    finally:
        close_error: BaseException | None = None
        for directory in reversed(directories):
            try:
                os.close(directory)
            except BaseException as exc:
                if not failed and close_error is None:
                    close_error = exc
        if close_error is not None:
            try:
                raise close_error
            finally:
                close_error = None
    aliases = report.get("common_license_aliases", []) if report["version"] >= 4 else []
    if not isinstance(aliases, list) or len(aliases) > len(common_probes):
        raise ValueError("invalid common-license alias inventory")
    alias_keys = set()
    by_key = {(row["path"], row["catalogue_layer_diff_id"]): row for row in validated}
    for alias in aliases:
        if set(alias) != {"path", "link_name", "target_path", "target_sha256", "catalogue_layer_diff_id", "layer_blob_digest", "visibility"}:
            raise ValueError("invalid common-license alias metadata")
        key = alias["path"], alias["catalogue_layer_diff_id"]
        destination = common_alias_target(alias["path"], alias["link_name"])
        target_key = destination, alias["catalogue_layer_diff_id"]
        target = by_key.get(target_key)
        native_target = native_files.get(target_key)
        if (key not in common_probes or key in alias_keys or key in seen
                or alias["target_path"] != destination or target is None or native_target is None
                or native_target.get("metadata", {}).get("type") not in {None, "RegularFile"}
                or target["content_kind"] != "notice_candidate" or target["sha256"] != alias["target_sha256"]
                or alias["layer_blob_digest"] != target["layer_blob_digest"]
                or alias["visibility"] != "layer_probe_runtime_visibility_unconfirmed"):
            raise ValueError("common-license alias does not bind its same-layer regular target")
        alias_keys.add(key)
    if required - seen:
        raise ValueError("notice evidence is missing required catalogue locations")
    return associate(native, image, validated, blobs, owner_reader=owner_reader, common_license_aliases=aliases), blobs


def associate(native: dict, image: dict, rows: list[dict], blobs: dict[str, bytes], *, owner_reader=None, common_license_aliases=()) -> dict:
    """Retain exact-location claims and bounded package-directory candidates."""
    by_key = {(r["path"], r["catalogue_layer_diff_id"]): r for r in rows if r["content_kind"] != "identity"}
    by_path = defaultdict(list)
    for row in by_key.values():
        by_path[row["path"]].append(row)
    aliases_by_path = defaultdict(list)
    for alias in common_license_aliases:
        aliases_by_path[alias["path"]].append(alias)
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
        associations: dict[tuple[str, str], dict] = {}

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
                declared_row = by_key.get((loc["path"], loc["layerID"]))
                if declared_row is None:
                    raise ValueError("captured evidence is missing a declared licence location")
                add(declared_row, "catalogue_licence_location")
        for row, reason in directory_matches[artifact["id"]]:
            add(row, reason)
        for key, identifiers in package_paths.metadata.items():
            if artifact["id"] in identifiers and key in by_key and key not in associations:
                add(by_key[key], "python_distribution_metadata")
        for key in component_notice_paths(artifact):
            if key in by_key:
                add(by_key[key], 'component_specific_notice_candidate')
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
                    common_matches = by_path["/usr/share/common-licenses/" + name]
                    if len(common_matches) == 1 and not aliases_by_path[COMMON_DIRECTORY + name]:
                        add(common_matches[0], "copyright_common_licence_reference")
                    elif not common_matches and len(aliases_by_path[COMMON_DIRECTORY + name]) == 1:
                        alias = aliases_by_path[COMMON_DIRECTORY + name][0]
                        row = by_key[(alias["target_path"], alias["catalogue_layer_diff_id"])]
                        add(row, "copyright_common_licence_alias_reference")
                        key = row["path"], row["catalogue_layer_diff_id"]
                        references = associations[key].setdefault("common_license_aliases", [])
                        if alias not in references:
                            references.append(deepcopy(alias))
                    else:
                        corrected = corrected_common_reference(name, blobs[entry["sha256"]].decode("utf-8", errors="replace"))
                        replacements = by_path[COMMON_DIRECTORY + corrected] if corrected else []
                        if not common_matches and not aliases_by_path[COMMON_DIRECTORY + name] and len(replacements) == 1:
                            replacement = replacements[0]
                            add(replacement, "copyright_common_licence_corrected_reference")
                            key = replacement["path"], replacement["catalogue_layer_diff_id"]
                            correction = {"referenced_path": COMMON_DIRECTORY + name,
                                          "copyright_path": entry["path"], "copyright_sha256": entry["sha256"]}
                            corrections = associations[key].setdefault("common_license_reference_corrections", [])
                            if correction not in corrections:
                                corrections.append(correction)
                        else:
                            gaps.append("common licence text missing or ambiguous: " + name)
        evidence = sorted(associations.values(), key=lambda r: (r["path"], r["catalogue_layer_diff_id"]))
        status = ("notice_candidate_captured" if any(r["content_kind"] == "notice_candidate" for r in evidence)
                  else "metadata_only" if evidence else "no_associated_evidence")
        if status != "notice_candidate_captured":
            gaps.append("no associated notice candidate; licence text completeness is unverified")
        record = {"id": artifact["id"], "status": status, "files": evidence, "gaps": gaps}
        from packages.sca.sbom_license_evidence import catalogue_declaration_missing, recover_distribution_license, recover_cpython_license
        if catalogue_declaration_missing(artifact):
            declaration = recover_distribution_license(artifact, evidence, blobs)
            if declaration is not None:
                record["recovered_distribution_license"] = declaration
            declaration = recover_cpython_license(artifact, evidence, blobs)
            if declaration is not None:
                record["recovered_component_license"] = declaration
        packages.append(record)
    from packages.sca.sbom_notice_owners import add_owner_context
    owner_statistics = add_owner_context(native, rows, blobs, packages, limit=MAX_ASSOCIATIONS)
    python_statistics = add_owner_context(native, rows, blobs, packages, limit=MAX_ASSOCIATIONS, owner_kind='python')
    measurements = []
    if owner_reader is not None:
        by_id = {p["id"]: p for p in packages}
        locations = {(loc["path"], loc["catalogue_layer_diff_id"])
                     for package in packages
                     for context_key in ("distro_owner_context", "python_record_owner_context")
                     for loc in package.get(context_key, {}).get("unresolved_locations", [])
                     if any(c["verification"] == "captured_bytes_unavailable"
                            and any(f["content_kind"] == "notice_candidate" for f in by_id[c["owner_package_id"]]["files"])
                            for c in loc["candidates"])}
        from packages.sca.sbom_java_license_evidence import reviewed_java_locations
        locations.update(reviewed_java_locations(native))
        from core.oci.evidence import read_identity_files
        verified = read_identity_files(native, owner_reader, locations)
        for package in packages:
            package.pop("distro_owner_context", None)
            package.pop("python_record_owner_context", None)
        owner_statistics = add_owner_context(native, rows, blobs, packages, limit=MAX_ASSOCIATIONS, verified_files=verified)
        python_statistics = add_owner_context(native, rows, blobs, packages, limit=MAX_ASSOCIATIONS,
                                              verified_files=verified, owner_kind='python')
        from packages.sca.sbom_java_license_evidence import recover_java_license
        for artifact in native['artifacts']:
            package = by_id[artifact['id']]
            recovered = recover_java_license(artifact, package, verified, native, rows, blobs)
            if recovered is None:
                continue
            declaration, notices = recovered
            package['recovered_component_license'] = declaration
            keys = {(row['path'], row['catalogue_layer_diff_id']) for row in package['files']}
            for notice in notices:
                key = notice['path'], notice['catalogue_layer_diff_id']
                if key in keys:
                    continue
                association_count += 1
                if association_count > MAX_ASSOCIATIONS:
                    raise ValueError('notice association count exceeds memory budget')
                keys.add(key)
                associated.add(key)
                entry = {key: deepcopy(notice[key]) for key in (
                    'path', 'layer_blob_digest', 'catalogue_layer_diff_id', 'sha256', 'size',
                    'notice_file', 'content_kind', 'visibility')}
                entry['reasons'] = ['reviewed_component_source_notice']
                package['files'].append(entry)
            package['files'].sort(key=lambda row: (row['path'], row['catalogue_layer_diff_id']))
            package['status'] = 'notice_candidate_captured'
            package['gaps'] = [gap for gap in package['gaps'] if gap != 'no associated notice candidate; licence text completeness is unverified']
        measurements = [verified[key][0] for key in sorted(verified)]
    from packages.sca.sbom_distro_python_notices import associate_project_notices
    associate_project_notices(native, packages, blobs)
    return {"version": 1, "subject": image, "common_license_aliases": list(common_license_aliases), "packages": packages, "owner_file_verification": measurements, "distro_owner_statistics": owner_statistics,
            "python_record_owner_statistics": python_statistics,
            "unassociated_files": [deepcopy(r) for r in rows if (r["path"], r["catalogue_layer_diff_id"]) not in associated],
            "scope": "catalogue, directory and enclosing package notice context; no licence conclusion, completeness or build-source certification"}


def append_notices(cdx: dict, spdx: dict, components: dict, packages: dict, summary: dict) -> None:
    """Retain evidence and recover missing declarations; preserve conclusions."""
    for record in summary["packages"]:
        component, package = components[record["id"]], packages[record["id"]]
        component.pop("signature", None)
        contexts = [context for key in ("distro_owner_context", "python_record_owner_context")
                    for context in record.get(key, {}).get("checksum_matched_notices", [])]
        for context in contexts:
            owner_id = context["owner_package_id"]
            context["owner_cyclonedx_ref"] = components[owner_id]["bom-ref"]
            context["owner_spdx_id"] = packages[owner_id]["SPDXID"]
            if components[owner_id].get("purl"):
                context["owner_purl"] = components[owner_id]["purl"]
        declaration = record.get("recovered_component_license") or record.get("recovered_distribution_license")
        if declaration:
            component["licenses"] = [{"expression": declaration["expression"]}]
            package["licenseDeclared"] = declaration["expression"]
        encoded = dumps_artifact(record)
        component.setdefault("properties", []).append({"name": "raptor:notice-evidence", "value": encoded})
        for row in record["files"]:
            reference = {"type": "evidence", "url": row["notice_file"],
                         "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                         "comment": "Captured " + row["content_kind"] + "; applicable terms remain unreviewed"}
            if reference not in component.setdefault("externalReferences", []):
                component["externalReferences"].append(reference)
        for context in contexts:
            for row in context["files"]:
                enclosing = "distro package" if context['scope'].startswith('enclosing_distro_') else "Python distribution"
                reference = {"type": "evidence", "url": row["notice_file"],
                             "hashes": [{"alg": "SHA-256", "content": row["sha256"]}],
                             "comment": "Enclosing " + enclosing + " notice context; component coverage unreviewed"}
                if reference not in component.setdefault("externalReferences", []):
                    component["externalReferences"].append(reference)
        package["comment"] = package.get("comment", "") + "\nRAPTOR notice evidence: " + encoded
    cdx.pop("signature", None)
    cdx.setdefault("properties", []).append({"name": "raptor:notice-evidence:scope", "value": summary["scope"]})
    cdx.setdefault("externalReferences", []).append({"type": "evidence", "url": "notice-evidence.json"})
    spdx["comment"] = spdx.get("comment", "") + "\nRAPTOR notice evidence: notice-evidence.json; " + summary["scope"]

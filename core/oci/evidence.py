"""Recover catalogue-referenced notices from digest-verified OCI layers.

The catalogue supplies associations, not trusted file contents or legal
conclusions. No image code is executed and no archive paths are extracted
onto the host. Layer origin does not by itself prove runtime visibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import posixpath
import re
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath
from typing import TypedDict

from core.oci.blob import UnresolvedLayerHardlinks, extract_files_from_layer
from core.oci.common_licenses import COMMON_ALIASES, COMMON_DIRECTORY, common_alias_target
from core.oci.manifest import LayerDescriptor, parse_image_manifest
from core.oci.notice_paths import (
    METADATA_NAMES as _METADATA_NAMES, NOTICE_NAME as _NOTICE,
    SOURCE_SUFFIXES as _SOURCE_SUFFIXES, image_path as _path, PackageNoticePaths, component_notice_paths,
)

MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_LAYER_SELECTED_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


def _unique(pairs: list) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _nonfinite(value: str) -> None:
    raise ValueError("non-finite JSON value")


def read_catalogue(raw: bytes) -> dict:
    """Parse bounded-by-caller JSON without accepting ambiguous keys."""
    result = json.loads(raw, object_pairs_hook=_unique, parse_constant=_nonfinite)
    if not isinstance(result, dict):
        raise ValueError("catalogue must be an object")
    return result


def _digest(value: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ValueError("expected a sha256 digest")
    return value


def _embedded(metadata: dict, key: str, expected: str) -> tuple[dict, bytes]:
    raw = base64.b64decode(metadata[key], validate=True)
    if "sha256:" + hashlib.sha256(raw).hexdigest() != _digest(expected):
        raise ValueError(f"embedded {key} digest mismatch")
    return read_catalogue(raw), raw


def subject(catalogue: dict) -> tuple[dict, list[LayerDescriptor]]:
    """Bind the catalogue to its embedded platform manifest and config."""
    if not str(catalogue.get("schema", {}).get("version", "")).startswith("16."):
        raise ValueError("expected native Syft schema 16.x")
    source = catalogue.get("source", {})
    if source.get("type") != "image":
        raise ValueError("expected an image catalogue")
    metadata = source["metadata"]
    manifest_digest = _digest(metadata["manifestDigest"])
    manifest, _ = _embedded(metadata, "manifest", manifest_digest)
    if manifest.get("schemaVersion") != 2 or manifest.get("mediaType") not in {
        "application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"
    }:
        raise ValueError("expected a single-platform image manifest")
    parsed = parse_image_manifest(manifest)
    config, config_raw = _embedded(metadata, "config", parsed.config_digest)
    if manifest["config"]["size"] != len(config_raw):
        raise ValueError("config size mismatch")
    if metadata.get("imageID") and metadata["imageID"] != parsed.config_digest:
        raise ValueError("catalogue config identity mismatch")
    platform = {k: config[k] for k in ("os", "architecture")}
    for key, value in platform.items():
        if not isinstance(value, str) or not value or (metadata.get(key) and metadata[key] != value):
            raise ValueError("catalogue platform mismatch")
    scope = catalogue["descriptor"]["configuration"]["search"]["scope"]
    if scope not in {"squashed", "all-layers"}:
        raise ValueError("unknown catalogue scope")
    diff_ids = config.get("rootfs", {}).get("diff_ids", [])
    if config.get("rootfs", {}).get("type") != "layers" or len(diff_ids) != len(parsed.layers):
        raise ValueError("config layer mapping is incomplete")
    for diff_id in diff_ids:
        _digest(diff_id)
    for layer in parsed.layers:
        _digest(layer.digest)
        if type(layer.size) is not int or layer.size <= 0:
            raise ValueError("invalid layer size")
    return {"manifest_digest": manifest_digest, "config_digest": parsed.config_digest,
            "platform": platform, "catalogue_scope": scope,
            "layers": [{"blob_digest": layer.digest, "config_diff_id": diff_id}
                       for layer, diff_id in zip(parsed.layers, diff_ids)]}, parsed.layers


def _verified(chunks: Iterable[bytes], layer: LayerDescriptor) -> Iterable[bytes]:
    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        size += len(chunk)
        if size > layer.size:
            raise ValueError("layer exceeds manifest size")
        digest.update(chunk)
        yield chunk
    if size != layer.size or "sha256:" + digest.hexdigest() != layer.digest:
        raise ValueError("layer size or digest mismatch")


def _selected_layer(reader, layer, wanted, *, diff_id, discover_path=None, selected_symlinks=None):
    def select(name):
        # Include replay-added hard-link targets in alias checks. Distinct tar
        # spellings must not shadow a selected path after normalisation.
        if posixpath.normpath("/" + name).lstrip("/") in wanted:
            _path("/" + name)
        return discover_path(name) if discover_path is not None else False

    for attempt in range(5):
        try:
            return extract_files_from_layer(
                _verified(reader(layer), layer), wanted,
                media_type=layer.media_type, compressed_size=layer.size,
                max_selected_bytes=MAX_LAYER_SELECTED_BYTES, resolve_selected_hardlinks=True,
                expected_diff_id=diff_id, discover_path=select, selected_symlinks=selected_symlinks)
        except UnresolvedLayerHardlinks as exc:
            if attempt == 4:
                raise ValueError("hard-link resolution exceeded replay bound") from exc
            wanted.update(exc.paths)


def read_identity_files(catalogue: dict, reader, locations: set[tuple[str, str]]) -> dict:
    """Read indexed identity files transiently from fully verified image layers.

    Returned bytes are for in-memory checks only. Callers retain the identity
    records, not executable/archive bytes. No filesystem overlay is replayed.
    """
    image, layers = subject(catalogue)
    origins = {r["blob_digest"]: r["config_diff_id"] for r in image["layers"]}
    indexed = {(f["location"]["path"], f["location"]["layerID"]): f for f in catalogue.get("files", [])}
    if len(indexed) != len(catalogue.get("files", [])):
        raise ValueError("duplicate catalogue file location")
    for path, origin in locations:
        _path(path)
        _digest(origin)
        if (path, origin) not in indexed or origin not in origins.values():
            raise ValueError("owner identity location is absent from the image catalogue")
        if indexed[(path, origin)].get("metadata", {}).get("type") not in {None, "RegularFile"}:
            raise ValueError("owner identity is not a catalogued regular file")
    result = {}
    total = 0
    for layer in layers:
        origin = origins[layer.digest]
        selected = {path for path, diff in locations if diff == origin and (path, diff) not in result}
        if not selected:
            continue
        contents = _selected_layer(reader, layer, {p.lstrip("/") for p in selected}, diff_id=origin)
        for path in sorted(selected):
            data = contents.get(path.lstrip("/"))
            if data is None:
                raise ValueError(f"required owner identity file {path!r} missing from layer")
            total += len(data)
            if total > MAX_CAPTURE_BYTES:
                raise ValueError("owner identity verification exceeds memory budget")
            file = indexed[(path, origin)]
            if file.get("metadata", {}).get("size", len(data)) != len(data):
                raise ValueError("owner identity size conflicts with catalogue")
            sha = hashlib.sha256(data).hexdigest()
            for digest in file.get("digests", []):
                if digest["algorithm"].lower() == "sha256" and digest["value"].lower() != sha:
                    raise ValueError("owner identity SHA-256 conflicts with catalogue")
            record = {"path": path, "catalogue_layer_diff_id": origin, "layer_blob_digest": layer.digest,
                      "sha256": sha, "size": len(data), "visibility": "catalogue_location",
                      "method": "verified_image_layer", "content_kind": "identity"}
            result[(path, origin)] = record, data
    return result


class _CaptureTarget(TypedDict):
    roles: set[str]
    packages: set[str]
    required: bool


def capture(catalogue: dict, reader: Callable[[LayerDescriptor], Iterable[bytes]],
            *, identify: tuple[str, ...] = ()) -> tuple[dict, dict[str, bytes]]:
    """Return evidence and content-addressed notice bytes, only after verification.

    Required catalogue and Python RECORD locations must be recoverable.
    Directory discovery and conventional probes remain notice candidates,
    with unconfirmed runtime visibility for files absent from the file index.
    Identity targets are hashed but their executable bytes are never returned.
    """
    image, layers = subject(catalogue)
    origins = {row["blob_digest"]: row["config_diff_id"] for row in image["layers"]}
    layer_ids = set(origins.values())
    files = {}
    targets: dict[tuple[str, str], _CaptureTarget] = {}
    package_paths = PackageNoticePaths(catalogue.get("artifacts", []))
    if any(origin not in layer_ids for _, origin in package_paths.directories):
        raise ValueError("package notice directory references an unrelated layer")

    def location(loc: dict, *, inventory_only: bool = False) -> tuple[str, str]:
        path = _path(loc["path"], inventory_only=inventory_only)
        layer = _digest(loc["layerID"])
        if layer not in layer_ids:
            raise ValueError("catalogue location references an unrelated layer")
        return path, layer

    def target(key: tuple[str, str], role: str, package: str | None = None, required: bool = True):
        _path(key[0])  # Evidence selection never accepts inventory-only names.
        entry = targets.setdefault(key, {"roles": set(), "packages": set(), "required": False})
        entry["roles"].add(role)
        entry["required"] |= required
        if package:
            entry["packages"].add(package)

    for file in catalogue.get("files", []):
        # All-file metadata includes Unicode executable aliases. Ignore only
        # noncanonical symlink names, after validating their normalized path
        # and layer. Never select them as evidence or follow their targets.
        # Canonical links stay indexed for common-license target refusals.
        if file.get("metadata", {}).get("type") == "SymbolicLink":
            path = file["location"]["path"]
            normal = unicodedata.normalize("NFKC", path)
            if normal != path:
                location({**file["location"], "path": normal}, inventory_only=True)
                continue
        key = location(file["location"], inventory_only=True)
        if key in files:
            raise ValueError("duplicate catalogue file location")
        files[key] = file
        file_path = PurePosixPath(key[0])
        regular = file.get("metadata", {}).get("type") in {None, "RegularFile"}
        if regular and ((bool(_NOTICE.fullmatch(file_path.name)) and file_path.suffix.lower() not in _SOURCE_SUFFIXES)
                        or str(file_path).startswith("/usr/share/common-licenses/")):
            target(key, "notice_filename")

    # Probe only the three documented common-license aliases, in layers that
    # already contain catalogued common texts. No arbitrary symlink is followed.
    for origin in {origin for path, origin in files if path.startswith(COMMON_DIRECTORY)}:
        for alias in COMMON_ALIASES:
            target((COMMON_DIRECTORY + alias, origin), "common_licence_alias_probe", required=False)

    packages = []
    package_ids = set()
    for artifact in catalogue.get("artifacts", []):
        package_id = artifact["id"]
        if not isinstance(package_id, str) or not package_id or package_id in package_ids:
            raise ValueError("invalid or duplicate package ID")
        package_ids.add(package_id)
        packages.append({k: artifact[k] for k in ("id", "name", "version", "type", "purl", "licenses") if k in artifact})
        for licence in artifact.get("licenses", []):
            for loc in licence.get("locations", []):
                target(location(loc), "catalogue_licence_location", package_id)
        if artifact.get("type") == "npm":
            for loc in artifact.get("locations", []):
                if PurePosixPath(loc["path"]).name != "package.json":
                    continue
                path, layer_id = location(loc)
                parent = PurePosixPath(path).parent
                for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE", "README.md"):
                    target((str(parent / name), layer_id), "conventional_package_notice_probe", package_id, False)
    for artifact in catalogue.get('artifacts', []):
        for key in component_notice_paths(artifact):
            target(key, 'component_specific_notice_probe', artifact['id'], False)
    for key, identifiers in package_paths.metadata.items():
        for identifier in sorted(identifiers):
            target(key, "python_distribution_metadata", identifier)
    for key, record in package_paths.records.items():
        for identifier in sorted(record["package_ids"]):
            target(key, "python_record_notice", identifier)
    for (directory, layer_id), names in package_paths.pointers.items():
        for name in names:
            target((directory + "/" + name, layer_id), "declared_notice_pointer", required=False)
    for path in identify:
        path = _path(path)
        matches = [key for key in files if key[0] == path]
        if not matches:
            raise ValueError("identity target is absent from catalogue")
        for key in matches:
            target(key, "identity_only")

    blobs = {}
    records = []
    common_aliases = []
    total = 0
    for layer in layers:
        selected = {path: entry for (path, origin), entry in targets.items() if origin == origins[layer.digest]}
        discover = lambda name: bool(package_paths.matches("/" + name, origins[layer.digest]))
        if not selected and not any(origin == origins[layer.digest] for _, origin in package_paths.directories):
            continue
        wanted = {path.lstrip("/") for path in selected}
        alias_paths = {COMMON_DIRECTORY + alias for alias in COMMON_ALIASES}
        symlinks: dict[str, str] = {}
        # Only common aliases may be observed. Any other selected symlink keeps
        # the normal refusal behavior, including package notice symlinks.
        contents = _selected_layer(reader, layer, wanted, diff_id=origins[layer.digest],
                                   discover_path=discover, selected_symlinks=symlinks)
        layer_aliases = []
        for name, link in symlinks.items():
            path = "/" + name
            if path not in alias_paths:
                raise ValueError("selected package notice is a symlink")
            destination = common_alias_target(path, link)
            data = contents.get(destination.lstrip("/"))
            if (data is None or (destination, origins[layer.digest]) not in files
                    or files[(destination, origins[layer.digest])].get("metadata", {}).get("type") not in {None, "RegularFile"}):
                raise ValueError("common-license alias lacks a catalogued regular target in the same layer")
            layer_aliases.append({"path": path, "link_name": link, "target_path": destination,
                                  "target_sha256": hashlib.sha256(data).hexdigest(),
                                  "catalogue_layer_diff_id": origins[layer.digest], "layer_blob_digest": layer.digest,
                                  "visibility": "layer_probe_runtime_visibility_unconfirmed"})
        common_aliases.extend(layer_aliases)
        for name in contents:
            path = "/" + name
            for identifier, reason in package_paths.matches(path, origins[layer.digest]):
                _path(path)
                target((path, origins[layer.digest]), reason, identifier, False)
                selected[path] = targets[(path, origins[layer.digest])]
        for path, entry in sorted(selected.items()):
            data = contents.get(path.lstrip("/"))
            if data is None:
                if entry["required"]:
                    raise ValueError(f"required evidence {path!r} missing from layer {layer.digest}")
                continue
            total += len(data)
            if total > MAX_CAPTURE_BYTES:
                raise ValueError("captured files exceed memory budget")
            sha = hashlib.sha256(data).hexdigest()
            file = files.get((path, origins[layer.digest]), {})
            expected_size = file.get("metadata", {}).get("size")
            if expected_size is not None and expected_size != len(data):
                raise ValueError("catalogue file size mismatch")
            recorded = package_paths.records.get((path, origins[layer.digest]))
            if recorded and ((recorded["sha256"] is not None and recorded["sha256"] != sha)
                             or (recorded["size"] is not None and recorded["size"] != len(data))):
                raise ValueError("Python RECORD notice hash or size mismatch")
            for expected in file.get("digests", []):
                if expected["algorithm"].lower() == "sha256" and expected["value"].lower() != sha:
                    raise ValueError("catalogue file digest mismatch")
            record = {"path": path, "layer_blob_digest": layer.digest, "catalogue_layer_diff_id": origins[layer.digest], "sha256": sha, "size": len(data),
                      "roles": sorted(entry["roles"]), "package_ids": sorted(entry["packages"]),
                      "visibility": "catalogue_location" if entry["required"] and (file or entry["roles"] & {"catalogue_licence_location", "python_distribution_metadata"}) else "layer_probe_runtime_visibility_unconfirmed"}
            record["content_kind"] = ("identity" if entry["roles"] == {"identity_only"}
                                      else "package_metadata" if PurePosixPath(path).name in _METADATA_NAMES
                                      else "notice_candidate")
            if entry["roles"] != {"identity_only"}:
                record["notice_file"] = "notices/sha256/" + sha
                blobs[sha] = data
            records.append(record)
    with_notices = {package for row in records if row["content_kind"] == "notice_candidate"
                    for package in row["package_ids"]}
    report = {"version": 4, "common_license_aliases": common_aliases, "gaps": {
                  "package_ids_without_associated_notice_candidate": sorted(
                      package["id"] for package in packages if package["id"] not in with_notices),
                  "identity_targets_without_version_or_build_source_verification": list(identify)}, "subject": image, "packages": packages, "files": records,
              "limitations": [
                  "Package associations and licence locations are catalogue claims, not legal conclusions.",
                  "Filename and package-directory probes do not establish the licence covering a package.",
                  "Layer evidence does not independently establish final runtime visibility.",
                  "Hashes establish file identity, not version, build source or corresponding-source availability.",
                  "This capture does not establish notice completeness or redistribution compliance."]}
    return report, blobs

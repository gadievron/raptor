"""Recover catalogue-referenced notices from digest-verified OCI layers.

The catalogue supplies associations, not trusted file contents or legal
conclusions. No image code is executed and no archive paths are extracted
onto the host. Layer origin does not by itself prove runtime visibility.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import unicodedata
from collections.abc import Callable, Iterable
from pathlib import PurePosixPath

from core.oci.blob import UnresolvedLayerHardlinks, extract_files_from_layer
from core.oci.manifest import LayerDescriptor, parse_image_manifest

MAX_CAPTURE_BYTES = 128 * 1024 * 1024
MAX_LAYER_SELECTED_BYTES = 64 * 1024 * 1024
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|authors)(?:[._-].*)?\Z", re.I)
_METADATA_NAMES = frozenset({"package.json", "METADATA", "PKG-INFO", "pyproject.toml", "Cargo.toml", "pom.xml"})
_SOURCE_SUFFIXES = frozenset({".py", ".pyc", ".js", ".ts", ".c", ".h", ".go", ".java", ".class", ".so", ".a", ".o", ".exe", ".dll", ".bin"})


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


def _path(value: str) -> str:
    if not isinstance(value, str) or not value.startswith("/"):
        raise ValueError("image path must be absolute")
    normal = unicodedata.normalize("NFKC", value)
    if (normal != value or "\\" in value or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in {"", ".", ".."} for p in value[1:].split("/"))):
        raise ValueError("unsafe or ambiguous image path")
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


def capture(catalogue: dict, reader: Callable[[LayerDescriptor], Iterable[bytes]],
            *, identify: tuple[str, ...] = ()) -> tuple[dict, dict[str, bytes]]:
    """Return evidence and content-addressed notice bytes, only after verification.

    Required catalogue locations must be recoverable. Conventional npm notice
    probes are optional and explicitly have unconfirmed runtime visibility.
    Identity targets are hashed but their executable bytes are never returned.
    """
    image, layers = subject(catalogue)
    origins = {row["blob_digest"]: row["config_diff_id"] for row in image["layers"]}
    layer_ids = set(origins.values())
    files = {}
    targets = {}

    def location(loc: dict) -> tuple[str, str]:
        path, layer = _path(loc["path"]), _digest(loc["layerID"])
        if layer not in layer_ids:
            raise ValueError("catalogue location references an unrelated layer")
        return path, layer

    def target(key: tuple[str, str], role: str, package: str | None = None, required: bool = True):
        entry = targets.setdefault(key, {"roles": set(), "packages": set(), "required": False})
        entry["roles"].add(role)
        entry["required"] |= required
        if package:
            entry["packages"].add(package)

    for file in catalogue.get("files", []):
        key = location(file["location"])
        if key in files:
            raise ValueError("duplicate catalogue file location")
        files[key] = file
        path = PurePosixPath(key[0])
        regular = file.get("metadata", {}).get("type") in {None, "RegularFile"}
        if regular and ((bool(_NOTICE.fullmatch(path.name)) and path.suffix.lower() not in _SOURCE_SUFFIXES)
                        or str(path).startswith("/usr/share/common-licenses/")):
            target(key, "notice_filename")

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
                path, layer = location(loc)
                parent = PurePosixPath(path).parent
                for name in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "NOTICE", "README.md"):
                    target((str(parent / name), layer), "conventional_package_notice_probe", package_id, False)
    for path in identify:
        path = _path(path)
        matches = [key for key in files if key[0] == path]
        if not matches:
            raise ValueError("identity target is absent from catalogue")
        for key in matches:
            target(key, "identity_only")

    blobs = {}
    records = []
    total = 0
    for layer in layers:
        selected = {path: entry for (path, origin), entry in targets.items() if origin == origins[layer.digest]}
        if not selected:
            continue
        wanted = {path.lstrip("/") for path in selected}
        for attempt in range(5):
            try:
                contents = extract_files_from_layer(
                    _verified(reader(layer), layer), wanted,
                    media_type=layer.media_type, compressed_size=layer.size,
                    max_selected_bytes=MAX_LAYER_SELECTED_BYTES, resolve_selected_hardlinks=True,
                    expected_diff_id=origins[layer.digest])
                break
            except UnresolvedLayerHardlinks as exc:
                if attempt == 4:
                    raise ValueError("hard-link resolution exceeded replay bound") from exc
                wanted.update(exc.paths)
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
            for expected in file.get("digests", []):
                if expected["algorithm"].lower() == "sha256" and expected["value"].lower() != sha:
                    raise ValueError("catalogue file digest mismatch")
            record = {"path": path, "layer_blob_digest": layer.digest, "catalogue_layer_diff_id": origins[layer.digest], "sha256": sha, "size": len(data),
                      "roles": sorted(entry["roles"]), "package_ids": sorted(entry["packages"]),
                      "visibility": "catalogue_location" if entry["required"] else "layer_probe_runtime_visibility_unconfirmed"}
            record["content_kind"] = ("identity" if entry["roles"] == {"identity_only"}
                                      else "package_metadata" if PurePosixPath(path).name in _METADATA_NAMES
                                      else "notice_candidate")
            if entry["roles"] != {"identity_only"}:
                record["notice_file"] = "notices/sha256/" + sha
                blobs[sha] = data
            records.append(record)
    with_notices = {package for row in records if row["content_kind"] == "notice_candidate"
                    for package in row["package_ids"]}
    report = {"version": 1, "gaps": {
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

"""Bind installed uv bytes to a digest-checked member of its publisher's image.

Signature verification belongs to GitHub CLI in the publishing workflow. This
module never executes a binary and never calls unsigned matches authenticated.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path
import re

from core.atomic_fs import write_bytes_atomically
from core.json import dumps_artifact, save_json
from core.json.projection import project_object
from core.oci.blob import extract_files_from_layer
from core.oci.evidence import _verified, subject
from core.oci.image_ref import parse_image_ref
from core.oci.manifest import LayerDescriptor, is_image_index, is_image_manifest, parse_image_index, parse_image_manifest
from .source import Source, SHA256

MAX_CATALOGUE_BYTES = 256 * 1024 * 1024
MAX_METADATA_BYTES = 2 * 1024 * 1024
MAX_BUNDLE_BYTES = 5 * 1024 * 1024
MAX_LAYER_BYTES = 64 * 1024 * 1024
MAX_BINARY_BYTES = 128 * 1024 * 1024
MAX_LAYERS = 8
UV_PATH = "/usr/local/bin/uv"


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("invalid upstream OCI digest")
    return value


def _uv_file(row):
    if not isinstance(row, dict) or not isinstance(row.get("location"), dict):
        raise ValueError("invalid native file inventory row")
    return row if row["location"].get("path") == UV_PATH else None


def installed_identity(audit: Path):
    """Project the large file inventory; retain only uv's exact regular-file row."""
    with Source(audit) as source:
        report, report_sha = source.read_json("license-report.json")
        image_digest = source.read("image-digest.txt", 256).decode("ascii").strip()
        native, native_sha = source.read_json("syft.json", max_bytes=MAX_CATALOGUE_BYTES, projectors={
            "files": _uv_file,
            "artifacts": lambda row: None, "artifactRelationships": lambda row: None})
    image, _ = subject(native)
    if image["manifest_digest"] != image_digest or report.get("image_digest") != image_digest:
        raise ValueError("uv evidence does not describe the exported image")
    files = native.get("files", [])
    if (len(files) != 1 or not isinstance(files[0].get("metadata"), dict)
            or files[0]["metadata"].get("type") != "RegularFile"):
        raise ValueError("installed uv is not a unique regular file")
    file = files[0]
    origin = _digest(file["location"].get("layerID"))
    if origin not in {row["config_diff_id"] for row in image["layers"]}:
        raise ValueError("installed uv layer is outside the exported image")
    digests = file.get("digests", [])
    if not isinstance(digests, list) or any(not isinstance(row, dict) for row in digests):
        raise ValueError("invalid installed uv digests")
    hashes = [row.get("value") for row in digests if row.get("algorithm") == "sha256"]
    if len(hashes) != 1 or not isinstance(hashes[0], str) or not SHA256.fullmatch(hashes[0]):
        raise ValueError("installed uv has no unique SHA-256")
    records = report.get("native_identity_matches", [])
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise ValueError("invalid native identity records")
    matches = [row for row in records if row.get("path") == UV_PATH]
    if len(matches) != 1:
        raise ValueError("installed uv identity is unavailable or ambiguous")
    match, identity = matches[0], matches[0].get("identity", {})
    if (not isinstance(identity, dict) or identity.get("name") != "uv" or match.get("sha256") != hashes[0]
            or identity.get("sha256") != hashes[0] or identity.get("anchor_path") != UV_PATH
            or identity.get("layer_id") != origin
            or match.get("layer_id") != file.get("location", {}).get("layerID")):
        raise ValueError("uv identity disagrees with the installed file inventory")
    version = identity.get("version")
    if not isinstance(version, str) or len(version) > 64 or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("uv release version is unavailable or unsupported")
    if image["platform"]["os"] != "linux":
        raise ValueError("uv source-image verification requires a Linux inventory")
    return {"image_digest": image_digest, "version": version, "binary_sha256": hashes[0],
            "catalogue_sha256": native_sha, "report_sha256": report_sha, "platform": image["platform"],
            "path": UV_PATH, "layer_diff_id": origin}


def _manifest(response):
    data, sha = project_object(io.BytesIO(response.raw), max_bytes=MAX_METADATA_BYTES)
    if type(data.get("schemaVersion")) is not int or data["schemaVersion"] != 2:
        raise ValueError("unsupported upstream OCI schema version")
    if response.digest != "sha256:" + sha:
        raise ValueError("upstream manifest digest mismatch")
    return data


def bind_container(installed, client):
    """Return unsigned binding evidence and small original OCI documents."""
    ref = parse_image_ref("ghcr.io/astral-sh/uv:" + installed["version"])
    index = client.fetch_manifest(ref)
    index_data = _manifest(index)
    if not is_image_index(index_data.get("mediaType", "")):
        raise ValueError("expected the uv publisher's multi-platform image index")
    platform = installed["platform"]
    entries = [entry for entry in parse_image_index(index_data) if
               entry.os == platform["os"] and entry.architecture == platform["architecture"]]
    if len(entries) != 1:
        raise ValueError("uv upstream platform is missing or ambiguous")
    entry = entries[0]
    child = client.fetch_manifest(ref, reference=_digest(entry.digest))
    child_data = _manifest(child)
    if child.digest != entry.digest or len(child.raw) != entry.size or not is_image_manifest(child_data.get("mediaType", "")):
        raise ValueError("uv platform manifest does not match its index")
    manifest = parse_image_manifest(child_data)
    config_descriptor = child_data["config"]
    size = config_descriptor.get("size")
    if type(size) is not int or not 0 < size <= MAX_METADATA_BYTES:
        raise ValueError("uv config exceeds its byte budget")
    descriptor = LayerDescriptor(_digest(manifest.config_digest), size, "")
    config_raw = b"".join(_verified(client.stream_blob(ref, descriptor.digest), descriptor))
    config, _ = project_object(io.BytesIO(config_raw), max_bytes=MAX_METADATA_BYTES)
    if any(config.get(key) != platform[key] for key in ("os", "architecture")):
        raise ValueError("uv source config platform differs from the installed image")
    rootfs = config.get("rootfs")
    if not isinstance(rootfs, dict):
        raise ValueError("invalid uv source root filesystem")
    diff_ids = rootfs.get("diff_ids", [])
    if (rootfs.get("type") != "layers" or not isinstance(diff_ids, list)
            or not 0 < len(manifest.layers) <= MAX_LAYERS or len(diff_ids) != len(manifest.layers)
            or any(type(layer.size) is not int or not 0 < layer.size <= MAX_LAYER_BYTES for layer in manifest.layers)):
        raise ValueError("uv source layer inventory is invalid or exceeds its budget")
    matches = []
    for layer, diff_id in zip(manifest.layers, diff_ids):
        _digest(layer.digest)
        symlinks = {}
        found = extract_files_from_layer(_verified(client.stream_blob(ref, layer.digest), layer), {"uv"},
            media_type=layer.media_type, compressed_size=layer.size, expected_diff_id=_digest(diff_id),
            max_entry_bytes=MAX_BINARY_BYTES, max_selected_bytes=MAX_BINARY_BYTES, selected_symlinks=symlinks)
        if symlinks:
            raise ValueError("upstream uv member is a symbolic link")
        if "uv" in found:
            matches.append({"blob_digest": layer.digest, "diff_id": diff_id, "member": "uv",
                            "sha256": hashlib.sha256(found["uv"]).hexdigest()})
        del found
    if len(matches) != 1 or matches[0]["sha256"] != installed["binary_sha256"]:
        raise ValueError("installed uv does not uniquely match the publisher's source-image member")
    receipt = {"format": "raptor-uv-container-binding", "schema_version": 1,
               "status": "binary_match_requires_signature_verification", "installed": installed,
               "upstream": {"repository": "astral-sh/uv", "reference": ref.to_canonical(),
                            "index_digest": index.digest, "manifest_digest": child.digest,
                            "config_digest": manifest.config_digest},
               "matching_layer": matches[0],
               "limitations": ["Binary matching is not signature verification; verify the retained index attestation separately.",
                               "Proves matching bytes in a publisher image layer, not runtime visibility or compiled dependency membership."]}
    return receipt, {"index.json": index.raw, "manifest.json": child.raw, "config.json": config_raw}


def _publisher_bundle(client, index_digest):
    # Public endpoint only: no GitHub token or response-provided bundle URL.
    raw = client.http.get_bytes(
        "https://api.github.com/repos/astral-sh/uv/attestations/" + _digest(index_digest) + "?per_page=5",
        max_bytes=MAX_BUNDLE_BYTES, headers={"Accept": "application/vnd.github+json"})
    data, _ = project_object(io.BytesIO(raw), max_bytes=MAX_BUNDLE_BYTES)
    records = data.get("attestations")
    if (not isinstance(records, list) or not 0 < len(records) <= 5
            or any(not isinstance(row, dict) or not isinstance(row.get("bundle"), dict) for row in records)):
        raise ValueError("uv publisher attestation bundle is missing or invalid")
    result = "".join(dumps_artifact(row["bundle"], indent=None, ensure_ascii=True) + "\n" for row in records).encode("ascii")
    if len(result) > MAX_BUNDLE_BYTES:
        raise ValueError("uv publisher bundle exceeds its byte budget")
    return result


def prepare(audit: Path, out: Path, *, client=None):
    """Explicit online collection; use a new output directory, preserving failures."""
    if out.exists() or out.is_symlink():
        raise ValueError("uv provenance output must be a new directory")
    installed = installed_identity(audit)
    if client is None:
        from core.http.urllib_backend import UrllibClient
        from core.oci.client import OciRegistryClient
        client = OciRegistryClient(UrllibClient(user_agent="raptor-uv-provenance/1"))
    receipt, originals = bind_container(installed, client)
    bundle = _publisher_bundle(client, receipt["upstream"]["index_digest"])
    out.mkdir(parents=True, mode=0o700, exist_ok=False)
    for name, raw in originals.items():
        write_bytes_atomically(out / name, raw, replace=False)
    write_bytes_atomically(out / "uv-publisher-attestation.jsonl", bundle, replace=False)
    save_json(out / "uv-container-binding.json", receipt, stream=True)
    return receipt

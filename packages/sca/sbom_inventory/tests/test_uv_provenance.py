"""Authenticate exact member bytes without conflating a match with a signature."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

import pytest

from core.oci.client import ManifestResponse
from packages.sca.sbom_inventory import uv_provenance as uv


def sha(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value).encode()


def response(value):
    raw = encoded(value)
    return ManifestResponse(raw, value, value["mediaType"], sha(raw))


def layer(name, raw, *, symlink=False):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        item = tarfile.TarInfo(name)
        if symlink:
            item.type, item.linkname = tarfile.SYMTYPE, "uvx"
            archive.addfile(item)
        else:
            item.size = len(raw)
            archive.addfile(item, io.BytesIO(raw))
    uncompressed = stream.getvalue()
    compressed = gzip.compress(uncompressed, mtime=0)
    return {"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip", "digest": sha(compressed),
            "size": len(compressed)}, compressed, sha(uncompressed)


class Publisher:
    """Same manifest-response and streamed-blob shapes as the registry client."""
    def __init__(self, *, content=b"published uv bytes", second="uvx", symlink=False):
        layers = [layer("uv", content, symlink=symlink), layer(second, b"other bytes")]
        self.config = {"os": "linux", "architecture": "amd64", "rootfs": {
            "type": "layers", "diff_ids": [row[2] for row in layers]}}
        self.config_raw = encoded(self.config)
        self.manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": sha(self.config_raw), "size": len(self.config_raw)},
            "layers": [row[0] for row in layers]}
        child = response(self.manifest)
        self.index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [
            {"digest": child.digest, "size": len(child.raw), "mediaType": child.content_type,
             "platform": {"os": "linux", "architecture": "amd64"}}]}
        self.blobs = {row[0]["digest"]: row[1] for row in layers}
        self.blobs[sha(self.config_raw)] = self.config_raw
        self.reads = []
        self.http = self

    def fetch_manifest(self, ref, *, reference=None):
        assert ref.registry == "ghcr.io" and ref.repository == "astral-sh/uv" and ref.tag == "0.7.22"
        return response(self.index if reference is None else self.manifest)

    def get_bytes(self, url, *, max_bytes, headers):
        assert url == "https://api.github.com/repos/astral-sh/uv/attestations/" + response(self.index).digest + "?per_page=5"
        assert max_bytes == uv.MAX_BUNDLE_BYTES
        assert headers == {"Accept": "application/vnd.github+json"}
        return encoded({"attestations": [{"bundle": {"mediaType": "test unsigned bundle"}}]})

    def stream_blob(self, ref, digest):
        self.reads.append(digest)
        raw = self.blobs[digest]
        for start in range(0, len(raw), 31):
            yield raw[start:start + 31]


def installed():
    return {"version": "0.7.22", "binary_sha256": hashlib.sha256(b"published uv bytes").hexdigest(),
            "platform": {"os": "linux", "architecture": "amd64"}, "image_digest": "sha256:" + "a" * 64}


@pytest.fixture
def audit(bundle):
    native = json.loads((bundle / "syft.json").read_text())
    digest = installed()["binary_sha256"]
    layer_digest = "sha256:" + "a" * 64
    native["files"].append({"location": {"path": uv.UV_PATH, "layerID": layer_digest},
                            "metadata": {"type": "RegularFile"}, "digests": [{"algorithm": "sha256", "value": digest}]})
    (bundle / "syft.json").write_bytes(encoded(native))
    (bundle / "license-report.json").write_bytes(encoded({"image_digest": (bundle / "image-digest.txt").read_text().strip(),
        "native_identity_matches": [{"path": uv.UV_PATH, "sha256": digest, "layer_id": layer_digest,
            "identity": {"name": "uv", "version": "0.7.22", "sha256": digest, "anchor_path": uv.UV_PATH, "layer_id": layer_digest}}]}))
    return bundle


def test_bound_files_are_small_original_documents_and_match_is_not_a_signature(audit, tmp_path):
    out = tmp_path / "publisher"
    client = Publisher()
    receipt = uv.prepare(audit, out, client=client)
    assert receipt["status"] == "binary_match_requires_signature_verification"
    assert receipt["installed"]["binary_sha256"] == receipt["matching_layer"]["sha256"]
    assert receipt["installed"]["catalogue_sha256"] == hashlib.sha256((audit / "syft.json").read_bytes()).hexdigest()
    assert len(client.reads) == 3
    assert set(p.name for p in out.iterdir()) == {"index.json", "manifest.json", "config.json", "uv-container-binding.json", "uv-publisher-attestation.jsonl"}
    assert sha((out / "index.json").read_bytes()) == receipt["upstream"]["index_digest"]
    assert json.loads((out / "uv-container-binding.json").read_text()) == receipt


@pytest.mark.parametrize("problem", ["version", "file", "sha", "identity", "layer", "subject", "platform"])
def test_installed_identity_requires_consistent_inventory_and_report(audit, problem):
    native = json.loads((audit / "syft.json").read_text())
    report = json.loads((audit / "license-report.json").read_text())
    if problem == "version": report["native_identity_matches"][0]["identity"]["version"] = "../../other"
    elif problem == "file": native["files"][-1]["metadata"]["type"] = "SymbolicLink"
    elif problem == "sha": native["files"][-1]["digests"].append({"algorithm": "sha256", "value": "f" * 64})
    elif problem == "identity": report["native_identity_matches"] *= 2
    elif problem == "layer": report["native_identity_matches"][0]["layer_id"] = "sha256:" + "c" * 64
    elif problem == "subject": report["image_digest"] = "sha256:" + "d" * 64
    elif problem == "platform":
        metadata = native["source"]["metadata"]
        metadata["architecture"] = "arm64"
    (audit / "syft.json").write_bytes(encoded(native))
    (audit / "license-report.json").write_bytes(encoded(report))
    with pytest.raises(ValueError):
        uv.installed_identity(audit)


@pytest.mark.parametrize("problem", ["platform", "ambiguous", "member", "symlink", "duplicate", "layer-size", "config-size", "changed-blob", "changed-manifest"])
def test_upstream_disagreement_is_never_a_verified_match(problem):
    client = Publisher(content=b"wrong" if problem == "member" else b"published uv bytes",
                       second="uv" if problem == "duplicate" else "uvx", symlink=problem == "symlink")
    if problem == "platform": client.index["manifests"][0]["platform"]["architecture"] = "arm64"
    elif problem == "ambiguous": client.index["manifests"] *= 2
    elif problem in {"layer-size", "config-size", "changed-manifest"}:
        if problem == "layer-size": client.manifest["layers"][0]["size"] = uv.MAX_LAYER_BYTES + 1
        elif problem == "config-size": client.manifest["config"]["size"] = uv.MAX_METADATA_BYTES + 1
        else: client.manifest["schemaVersion"] = 3
        if problem != "changed-manifest":
            child = response(client.manifest)
            client.index["manifests"][0].update(digest=child.digest, size=len(child.raw))
    elif problem == "changed-blob":
        key = client.manifest["layers"][0]["digest"]
        client.blobs[key] += b"changed"
    with pytest.raises(ValueError):
        uv.bind_container(installed(), client)


def test_existing_destination_refuses_before_network_or_inventory_read(tmp_path, monkeypatch):
    def forbidden(*args):
        pytest.fail("must refuse before reading inputs")
    monkeypatch.setattr(uv, "installed_identity", forbidden)
    with pytest.raises(ValueError, match="new directory"):
        uv.prepare(tmp_path / "missing", tmp_path)


def test_explicit_source_json_budget_applies_to_open_and_projection(tmp_path):
    from packages.sca.sbom_inventory.source import Source
    raw = b'{"kept": [1, 2, 3]}'
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with Source(path) as source:
        with pytest.raises(ValueError, match="budget"):
            source.read_json(max_bytes=len(raw) - 1)
        document, digest = source.read_json(max_bytes=len(raw))
    assert document == {"kept": [1, 2, 3]}
    assert digest == hashlib.sha256(raw).hexdigest()


def test_missing_publisher_bundle_leaves_no_complete_output(audit, tmp_path, monkeypatch):
    client = Publisher()
    monkeypatch.setattr(client, "get_bytes", lambda *args, **kwargs: encoded({"attestations": []}))
    out = tmp_path / "publisher"
    with pytest.raises(ValueError, match="bundle"):
        uv.prepare(audit, out, client=client)
    assert not out.exists()

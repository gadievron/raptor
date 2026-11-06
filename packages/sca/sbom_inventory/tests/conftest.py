"""Owned, format-valid inputs; all notice bytes and writes stay under tmp_path."""
import base64
import hashlib
import json

import pytest

from core.oci.evidence import subject


@pytest.fixture
def cdx():
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": [{"bom-ref": "pkg:npm/example@1?package-id=package", "type": "library", "name": "example",
                            "version": "1", "purl": "pkg:npm/example@1", "licenses": [{"license": {"id": "MIT"}}]}],
            "dependencies": [{"ref": "pkg:npm/example@1?package-id=package", "dependsOn": []}]}


@pytest.fixture
def spdx():
    return {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "dataLicense": "CC0-1.0",
            "name": "test inventory", "documentNamespace": "https://example.invalid/sbom/1",
            "creationInfo": {"created": "2026-11-05T00:00:00Z", "creators": ["Tool: test"]},
            "packages": [{"SPDXID": "SPDXRef-example", "name": "example", "versionInfo": "1",
                          "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                          "licenseDeclared": "MIT", "licenseConcluded": "NOASSERTION",
                          "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:npm/example@1"}]}],
            "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-example"}]}


@pytest.fixture
def bundle(tmp_path, cdx):
    root = tmp_path / "bundle"
    notices = root / "prepared/notices/sha256"
    notices.mkdir(parents=True)
    text = b"Copyright Example\nPermission is hereby granted...\n"
    digest = hashlib.sha256(text).hexdigest()
    (notices / digest).write_bytes(text)
    config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]}}).encode()
    config_sha = "sha256:" + hashlib.sha256(config).hexdigest()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                           "config": {"digest": config_sha, "size": len(config)},
                           "layers": [{"digest": "sha256:" + "b" * 64, "size": 1,
                                       "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}).encode()
    image = "sha256:" + hashlib.sha256(manifest).hexdigest()
    native = {"schema": {"version": "16.1.11"}, "source": {"type": "image", "name": "example/image", "version": image,
              "metadata": {"manifestDigest": image, "imageID": config_sha, "manifest": base64.b64encode(manifest).decode(),
                           "config": base64.b64encode(config).decode()}},
              "descriptor": {"configuration": {"search": {"scope": "squashed"}}},
              "files": [{"location": {"path": "/usr/bin/known"}}],
              "artifacts": [{"id": "package", "name": "example", "version": "1", "type": "npm", "licenses": [{"value": "MIT"}]}]}
    raw = json.dumps(native).encode()
    provenance = {"inputs": [{"sha256": hashlib.sha256(raw).hexdigest()}], "packages": [],
                  "notice_evidence": {"subject": subject(native)[0], "packages": [{"id": "package", "status": "notice_candidate_captured", "gaps": [],
                  "files": [{"path": "/usr/share/example/LICENSE", "sha256": digest, "size": len(text),
                             "catalogue_layer_diff_id": "sha256:" + "a" * 64, "content_kind": "notice_candidate"}]}]}}
    (root / "syft.json").write_bytes(raw)
    (root / "image-digest.txt").write_text(image + "\n")
    (root / "prepared/provenance.json").write_text(json.dumps(provenance))
    (root / "prepared/sbom.cdx.json").write_text(json.dumps(cdx))
    return root


@pytest.fixture
def write_json(tmp_path):
    def write(value, name="sbom.json"):
        path = tmp_path / name
        path.write_text(json.dumps(value))
        return path
    return write

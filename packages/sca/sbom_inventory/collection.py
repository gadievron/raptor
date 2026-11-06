"""Collect portable image evidence using the shared, digest-checked OCI reader."""
from __future__ import annotations

import hashlib
from pathlib import Path
from urllib.parse import quote

from core.atomic_fs import write_bytes_atomically, write_text_atomically, publish_new_directory
from core.run.scratch import scratch_dir
from core.json import save_json
from core.json.projection import project_object
from core.oci.evidence import capture, subject
from core.oci.evidence_source import layout_reader, registry_reader
from core.security.capped_read import path_may_exist
from core.source.gated import open_regular_gated
from ..sbom_notices import load_notices

MAX_CATALOGUE_BYTES = 64 * 1024 * 1024


def _components(native, notices):
    proofs = {row["id"]: row for row in notices["packages"]}
    refs, components = {}, []
    for artifact in native["artifacts"]:
        identifier = artifact["id"]
        if not isinstance(identifier, str) or identifier in refs:
            raise ValueError("invalid or duplicate native package identifier")
        ref = "urn:raptor:package?package-id=" + quote(identifier, safe="")
        refs[identifier] = ref
        component = {"type": "library", "bom-ref": ref, "name": artifact["name"],
                     "version": artifact.get("version", "")}
        if artifact.get("purl"):
            component["purl"] = artifact["purl"]
        declarations = [row["value"] for row in artifact.get("licenses", []) if row.get("value")]
        if declarations:
            component["licenses"] = [{"license": {"name": value}} for value in declarations]
        proof = proofs[identifier]
        recovered = proof.get("recovered_component_license") or proof.get("recovered_distribution_license")
        if recovered:
            component["licenses"] = [{"expression": recovered["expression"]}]
        components.append(component)
    edges = {}
    for row in native.get("artifactRelationships", []):
        if row.get("type") == "dependency-of" and row.get("parent") in refs and row.get("child") in refs:
            # Syft parent is the dependency; child is the package that uses it.
            edges.setdefault(refs[row["child"]], set()).add(refs[row["parent"]])
    return {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "components": components,
            "dependencies": [{"ref": ref, "dependsOn": sorted(targets)} for ref, targets in sorted(edges.items())]}


def collect_image(syft: Path, out: Path, *, oci_layout=None, registry_ref=None, identify=()):
    """Never run an image; commit a new bundle only after all evidence validates."""
    if bool(oci_layout) == bool(registry_ref):
        raise ValueError("select exactly one OCI layout or digest-pinned registry reference")
    if path_may_exist(out):
        raise ValueError("output must be a new directory")
    with open_regular_gated(syft) as stream:
        native, sha = project_object(stream, max_bytes=MAX_CATALOGUE_BYTES)
        image, _ = subject(native)
        if oci_layout:
            report, blobs = capture(native, layout_reader(oci_layout), identify=tuple(identify))
        else:
            from core.http import HttpError
            from core.oci.client import RegistryError
            try:
                reader = registry_reader(image["manifest_digest"], registry_ref)
                report, blobs = capture(native, reader, identify=tuple(identify))
            except (HttpError, RegistryError) as error:
                raise ValueError("registry evidence unavailable: " + str(error)) from error
        report["catalogue_sha256"] = sha
        out.parent.mkdir(parents=True, exist_ok=True)
        with scratch_dir("raptor-sca-collect-", dir=out.parent, keepalive=True) as temporary:
            staging = Path(temporary) / "bundle"
            capture_dir = staging / "capture"
            blob_dir = capture_dir / "notices/sha256"
            blob_dir.mkdir(parents=True)
            for digest, data in blobs.items():
                write_bytes_atomically(blob_dir / digest, data)
            save_json(capture_dir / "evidence.json", report, stream=True)
            notices, _ = load_notices(capture_dir, native, sha, report)
            prepared = staging / "prepared"
            prepared.mkdir()
            prepared_blobs = prepared / "notices/sha256"
            prepared_blobs.mkdir(parents=True)
            for digest, data in blobs.items():
                write_bytes_atomically(prepared_blobs / digest, data)
            save_json(prepared / "provenance.json", {"inputs": [{"path": "syft.json", "sha256": sha}],
                      "packages": [], "notice_evidence": notices}, stream=True)
            save_json(prepared / "sbom.cdx.json", _components(native, notices), stream=True)
            write_text_atomically(staging / "image-digest.txt", image["manifest_digest"] + "\n")
            stream.seek(0)
            def original():
                digest, total = hashlib.sha256(), 0
                while chunk := stream.read(65536):
                    total += len(chunk)
                    if total > MAX_CATALOGUE_BYTES:
                        raise ValueError("catalogue changed during collection")
                    digest.update(chunk)
                    yield chunk
                if digest.hexdigest() != sha:
                    raise ValueError("catalogue changed during collection")
            write_bytes_atomically(staging / "syft.json", original())
            del native, blobs, notices, report
            # Exercise the same consumer contract before publishing the directory.
            from .inventory import read_inventory
            from .source import Source
            with Source(staging) as source:
                inventory, _ = read_inventory(source)
            if path_may_exist(out):
                raise ValueError("output must be a new directory")
            publish_new_directory(staging, out)
    return {"format": "raptor-sbom-collection", "schema_version": 1, "subject": image["manifest_digest"],
            "catalogue_sha256": sha, "summary": inventory.summary(),
            "limitations": ["CycloneDX contains catalogued packages and supplied package relationships; the original file inventory remains in syft.json.",
                            "Collection establishes retained-byte identity, not complete bundled dependencies, legal review or build provenance."]}

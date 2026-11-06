import hashlib
import json

import pytest

from core.oci.tests.test_evidence import fixture_image, digest
from core.tar import TarOpenError
from core.testing.logging_state import isolated_cli_logging
from packages.sca.sbom_import import read_sbom
from packages.sca.sbom_inventory.cli import main
from packages.sca.sbom_notices import load_notices
from packages.sca.sbom_inventory.collection import collect_image
from packages.sca.sbom_inventory.inventory import read_inventory
from packages.sca.sbom_inventory.output import export_notices
from packages.sca.sbom_inventory.source import Source


def image(tmp_path):
    native, blob = fixture_image()
    native["artifacts"][0]["purl"] = "pkg:npm/package@1"
    path = tmp_path / "syft.json"
    original = json.dumps(native, indent=2).encode() + b"\n"
    path.write_bytes(original)
    layout = tmp_path / "image"
    store = layout / "blobs/sha256"
    store.mkdir(parents=True)
    (store / digest(blob).removeprefix("sha256:")).write_bytes(blob)
    return path, layout, original


def test_offline_collection_is_inspectable_exportable_and_preserves_source(tmp_path):
    path, layout, original = image(tmp_path)
    out = tmp_path / "evidence"
    result = collect_image(path, out, oci_layout=layout)
    assert result["summary"]["packages"] == 1
    imported = read_sbom(out / "prepared/sbom.cdx.json")
    assert [(dep.ecosystem, dep.name, dep.version) for dep in imported.dependencies] == [("npm", "package", "1")]
    assert result["summary"]["notice_gap_packages"] == 0
    assert (out / "syft.json").read_bytes() == original
    receipt = json.loads((out / "capture/evidence.json").read_text())
    notices, blobs = load_notices(out / "capture", json.loads(original), result["catalogue_sha256"], receipt)
    assert notices["packages"] and list(blobs.values()) == [b"original licence\n"]
    assert result["catalogue_sha256"] == hashlib.sha256(original).hexdigest()
    with Source(out) as source:
        inventory, embedded = read_inventory(source)
        assert inventory.records[0].purl == "pkg:npm/package@1"
        exported = export_notices(tmp_path / "notices", inventory, inventory.records, source, embedded, include_unassociated=True)
    assert exported["unique_texts"] == 1
    assert next((out / "prepared/notices/sha256").iterdir()).read_bytes() == b"original licence\n"


def test_bad_blob_leaves_no_output_or_staging_directory(tmp_path):
    path, layout, _ = image(tmp_path)
    next((layout / "blobs/sha256").iterdir()).write_bytes(b"changed")
    with pytest.raises((OSError, ValueError, TarOpenError)):
        collect_image(path, tmp_path / "evidence", oci_layout=layout)
    assert not (tmp_path / "evidence").exists()
    assert not list(tmp_path.glob("raptor-sca-collect-*"))


def test_output_refusal_and_registry_pin_happen_before_fetch(tmp_path):
    path, layout, _ = image(tmp_path)
    with pytest.raises(ValueError, match="new directory"):
        collect_image(path, tmp_path, oci_layout=layout)
    with pytest.raises(ValueError, match="manifest digest"):
        collect_image(path, tmp_path / "evidence", registry_ref="example/image:latest")
    assert not (tmp_path / "evidence").exists()


@isolated_cli_logging()
def test_public_collection_and_dependency_help_and_errors(tmp_path, capsys):
    path, layout, _ = image(tmp_path)
    assert main(["collect", "--syft", str(path), "--oci-layout", str(layout), "--out", str(tmp_path / "evidence")]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["notice_gap_packages"] == 0
    for name in ("collect", "why"):
        with pytest.raises(SystemExit) as error:
            main([name, "--help"])
        assert error.value.code == 0
        assert capsys.readouterr().out.count("raptor-sca sbom " + name) >= 3
    assert main(["why", str(tmp_path / "evidence"), "absent"]) == 2
    assert "not found" in capsys.readouterr().err


def test_collection_preserves_dependency_direction_and_does_not_infer_contains(tmp_path):
    path, layout, _ = image(tmp_path)
    native = json.loads(path.read_text())
    native["artifacts"].append({"id": "application", "name": "application", "version": "2", "type": "npm", "licenses": []})
    native["artifactRelationships"] = [
        {"parent": "package-id", "child": "application", "type": "dependency-of"},
        {"parent": "application", "child": "package-id", "type": "contains"},
    ]
    path.write_text(json.dumps(native))
    out = tmp_path / "collected"
    collect_image(path, out, oci_layout=layout)
    with Source(out) as source:
        inventory, _ = read_inventory(source)
    dependency, app = inventory.records
    assert app.children == [dependency.id] and dependency.parents == [app.id]
    assert app.graph_supplied and not dependency.graph_supplied
    assert dependency.children == []


@isolated_cli_logging()
@pytest.mark.parametrize("error_kind", ["http", "registry"])
def test_registry_failures_are_reported_without_partial_output(tmp_path, monkeypatch, capsys, error_kind):
    from core.http import HttpError
    from core.oci.client import RegistryError
    from packages.sca.sbom_inventory import collection
    path, _, original = image(tmp_path)
    manifest = json.loads(original)["source"]["metadata"]["manifestDigest"]
    def failed_reader(*args):
        def read(layer):
            raise HttpError("unavailable") if error_kind == "http" else RegistryError(503, "unavailable")
        return read
    monkeypatch.setattr(collection, "registry_reader", failed_reader)
    out = tmp_path / "evidence"
    assert main(["collect", "--syft", str(path), "--registry-ref", "example/image@" + manifest,
                 "--out", str(out)]) == 2
    assert "registry evidence unavailable" in capsys.readouterr().err
    assert not out.exists()

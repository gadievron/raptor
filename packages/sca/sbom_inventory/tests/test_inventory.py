import base64
import hashlib
import stat
import warnings
import zipfile

import pytest

from packages.sca.sbom_inventory.inventory import read_inventory
from packages.sca.sbom_inventory.model import selected
from packages.sca.sbom_inventory.source import Source


def load(path):
    with Source(path) as source:
        return read_inventory(source)


@pytest.mark.parametrize("format_name", ["cdx", "spdx"])
def test_standard_sbom_declarations_do_not_claim_notice_coverage(request, write_json, format_name):
    inventory, _ = load(write_json(request.getfixturevalue(format_name)))
    assert inventory.summary()["packages"] == 1
    assert inventory.summary()["unresolved_declarations"] == 0
    assert inventory.summary()["notice_gap_packages"] is None
    assert inventory.records[0].notice_status == "not_assessed"
    assert selected(inventory, license_id="MIT") == inventory.records


def test_compound_license_filter_and_embedded_original_bytes(cdx, write_json):
    original = b"Copyright \xc2\xa9 example\r\nOriginal text\r\n"
    cdx["components"][0]["licenses"] = [{"expression": "Apache-2.0 OR MIT"}]
    compound, _ = load(write_json(cdx))
    assert len(selected(compound, license_id="MIT")) == 1
    cdx["components"][0]["licenses"] = [{"license": {"id": "MIT", "text": {"encoding": "base64", "content": base64.b64encode(original).decode()}}}]
    inventory, embedded = load(write_json(cdx))
    assert len(selected(inventory, license_id="MIT")) == 1
    assert not selected(inventory, license_id="MIT-0")
    assert embedded[hashlib.sha256(original).hexdigest()] == original
    assert inventory.records[0].notice_status == "captured"


def test_spdx_conclusion_does_not_replace_missing_declaration(spdx, write_json):
    spdx["packages"][0].update(licenseDeclared="NOASSERTION", licenseConcluded="MIT")
    inventory, _ = load(write_json(spdx))
    assert inventory.summary()["unresolved_declarations"] == 1
    assert inventory.records[0].evidence["license_concluded"] == "MIT"


def test_nested_packages_files_and_graph_are_kept_separate(cdx, write_json):
    cdx["components"][0]["components"] = [{"type": "file", "name": "payload", "bom-ref": "file"},
        {"type": "library", "name": "child", "bom-ref": "child", "licenses": [{"license": {"id": "ISC"}}]}]
    cdx["dependencies"][0]["dependsOn"] = ["child", "file"]
    inventory, _ = load(write_json(cdx))
    assert inventory.file_count == 1 and len(inventory.records) == 2
    assert inventory.records[0].children == ["child"]
    assert inventory.records[1].parents == [inventory.records[0].id]
    assert not inventory.records[1].graph_supplied


@pytest.mark.parametrize("bad", ['{"bomFormat":"CycloneDX","bomFormat":"SPDX"}', '{"x":NaN}', '{broken', '[]'])
def test_bad_documents_are_not_clean_empty_inventories(tmp_path, bad):
    path = tmp_path / "bad.json"
    path.write_text(bad)
    with pytest.raises((ValueError, KeyError)):
        load(path)


def test_bundle_verifies_catalogue_binding_and_notice_bytes(bundle):
    inventory, _ = load(bundle)
    assert inventory.summary()["notice_gap_packages"] == 0
    assert inventory.coverage["status"] == "complete_for_catalogued_packages"
    sha = inventory.records[0].notices[0].sha256
    (bundle / "prepared/notices/sha256" / sha).write_bytes(b"changed")
    changed, _ = load(bundle)
    assert changed.summary()["notice_gap_packages"] == 1
    assert changed.records[0].notice_status == "invalid"
    assert changed.coverage["status"] == "gaps"


def test_evidence_subject_mismatch_is_not_accepted(bundle):
    (bundle / "image-digest.txt").write_text("sha256:" + "f" * 64)
    with pytest.raises(ValueError, match="subject"):
        load(bundle)


def test_directory_evidence_does_not_follow_internal_symlinks(bundle, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_bytes(b"host data")
    sha = next((bundle / "prepared/notices/sha256").iterdir())
    sha.unlink()
    sha.symlink_to(target)
    inventory, _ = load(bundle)
    assert inventory.records[0].notice_status == "invalid"


def test_zip_bundle_matches_directory_without_extraction(bundle, tmp_path):
    archive = tmp_path / "evidence.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as z:
        for path in bundle.rglob("*"):
            if path.is_file():
                z.write(path, path.relative_to(bundle))
    assert load(archive)[0].to_dict() == load(bundle)[0].to_dict()


@pytest.mark.parametrize("unsafe", ["../outside", "/absolute", "nested\\file", "duplicate", "symlink"])
def test_unsafe_archive_structure_is_refused(tmp_path, unsafe):
    archive = tmp_path / "evidence.zip"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(archive, "w") as z:
            if unsafe == "symlink":
                info = zipfile.ZipInfo("link")
                info.create_system = 3
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
                z.writestr(info, "outside")
            elif unsafe == "duplicate":
                z.writestr("same", "one")
                z.writestr("same", "two")
            else:
                z.writestr(unsafe, "data")
    with pytest.raises(ValueError):
        with Source(archive):
            pytest.fail("unsafe archive accepted")
    assert not (tmp_path / "outside").exists()


def test_os_subject_is_retained_outside_package_gap_counts(cdx, write_json):
    cdx["components"].append({"type": "operating-system", "name": "debian", "version": "12", "bom-ref": "os:debian@12"})
    inventory, _ = load(write_json(cdx))
    assert inventory.summary()["packages"] == 1
    assert inventory.summary()["subject_records"] == 1
    assert inventory.summary()["unresolved_declarations"] == 0
    assert selected(inventory, scope="subjects")[0].name == "debian"
    assert selected(inventory, scope="subjects")[0].declaration_missing


def test_unassociated_spdx_text_is_retained_without_claiming_package_coverage(spdx, write_json):
    spdx["hasExtractedLicensingInfos"] = [{"licenseId": "LicenseRef-extra", "extractedText": "Original additional notice"}]
    inventory, embedded = load(write_json(spdx))
    assert len(inventory.notice_files) == 1
    assert inventory.notice_files[0].sha256 in embedded
    assert inventory.records[0].notice_status == "not_assessed"
    assert not inventory.records[0].notices


def test_mixed_snapshot_and_original_evidence_is_refused(bundle):
    (bundle / "inventory.json").write_text('{"format":"raptor-sbom-inventory","schema_version":1}')
    with pytest.raises(ValueError, match="ambiguous"):
        load(bundle)


def test_directory_member_read_is_capped_before_return(bundle):
    with Source(bundle) as source:
        with pytest.raises(ValueError, match="budget"):
            source.read("syft.json", 8)


def test_license_operand_filter_does_not_classify_free_text_as_mit(cdx, write_json):
    cdx["components"][0]["licenses"] = [{"license": {"name": "not MIT"}}]
    inventory, _ = load(write_json(cdx))
    assert not selected(inventory, license_id="MIT")
    assert selected(inventory, license_id="not MIT")
    cdx["components"][0]["licenses"] = [{"expression": "(MIT OR Apache-2.0) AND BSD-3-Clause"}]
    inventory, _ = load(write_json(cdx))
    assert selected(inventory, license_id="MIT")
    assert inventory.records[0].declarations == ["(MIT OR Apache-2.0) AND BSD-3-Clause"]


@pytest.mark.parametrize("field,value", [("coverage", []), ("coverage", {"metrics": []}),
                                        ("coverage", {"metrics": {"packages": -1}}),
                                        ("diagnostics", "not a list"), ("schema_version", True)])
def test_invalid_snapshot_metadata_is_refused_before_rendering(cdx, write_json, field, value):
    inventory, _ = load(write_json(cdx))
    data = inventory.to_dict()
    data[field] = value
    with pytest.raises((TypeError, ValueError)):
        load(write_json(data, "snapshot.json"))


def test_crc_failure_is_a_controlled_invalid_input(tmp_path):
    import struct
    path = tmp_path / "corrupt.zip"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as archive:
        archive.writestr("selected.json", '{"bomFormat":"CycloneDX"}')
    raw = bytearray(path.read_bytes())
    central = raw.index(b"PK\x01\x02")
    struct.pack_into("<I", raw, central + 16, 0)
    path.write_bytes(raw)
    with Source(path) as source:
        with pytest.raises(ValueError, match="unreadable"):
            source.read_json("selected.json")


def test_compacted_file_values_keep_original_depth_validation(cdx, write_json):
    nested = "leaf"
    for _ in range(65):
        nested = {"extension": nested}
    cdx["components"].append({"type": "file", "name": "file", "extra": nested})
    with pytest.raises(ValueError, match="nesting"):
        load(write_json(cdx))

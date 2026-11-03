"""Reviewed Java grants require complete payload and independently verified ownership."""

from copy import deepcopy
import hashlib
import io
import zipfile

import pytest

from packages.sca import sbom_java_license_evidence as module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def archive(
    classes=None,
    *,
    creator="17.0.6 (Debian)",
    extra_manifest="",
    comment=b"",
    duplicate=False,
):
    # ZipInfo uses a fixed timestamp, so archive bytes agree across workers.
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as jar:
        jar.comment = comment
        jar.writestr(
            zipfile.ZipInfo("META-INF/MANIFEST.MF"),
            "Manifest-Version: 1.0\r\nCreated-By: "
            + creator
            + "\r\n"
            + extra_manifest
            + "\r\n",
        )
        for name, data in (
            classes or {"gnu/gettext/Example.class": b"class bytes"}
        ).items():
            jar.writestr(zipfile.ZipInfo(name), data)
            if duplicate:
                with pytest.warns(UserWarning):
                    jar.writestr(zipfile.ZipInfo(name), data)
    return stream.getvalue()


@pytest.fixture
def evidence(monkeypatch):
    rule = deepcopy(module._rules()[0])
    data = archive()
    rule["classes"] = {"gnu/gettext/Example.class": sha(b"class bytes")}
    rule["copyright_sha256"] = sha(b"copyright and source grant")
    rule["common_licenses"] = {"GPL-3": sha(b"complete GPL terms")}
    monkeypatch.setattr(module, "_rules", lambda: [rule])
    path, origin, blob = (
        "/usr/share/java/gettext.jar",
        "sha256:" + "d" * 64,
        "sha256:" + "e" * 64,
    )
    artifact = {
        "id": "jar",
        "name": "gettext",
        "type": "java-archive",
        "version": "UNKNOWN",
        "licenses": [],
        "locations": [{"path": path, "layerID": origin}],
    }
    owner = {"id": "owner", "name": "gettext", "type": "deb", "version": "0.21-12"}
    native = {"artifacts": [artifact, owner]}
    measurement = {
        "path": path,
        "catalogue_layer_diff_id": origin,
        "layer_blob_digest": blob,
        "sha256": sha(data),
        "size": len(data),
        "method": "verified_image_layer",
    }
    verified = {(path, origin): (measurement, data)}
    notices, blobs = [], {}
    for path, payload in [
        ("/usr/share/doc/gettext/copyright", b"copyright and source grant"),
        ("/usr/share/common-licenses/GPL-3", b"complete GPL terms"),
    ]:
        notices.append(
            {
                "path": path,
                "catalogue_layer_diff_id": origin,
                "layer_blob_digest": blob,
                "sha256": sha(payload),
                "size": len(payload),
                "content_kind": "notice_candidate",
                "notice_file": "notices/sha256/" + sha(payload),
                "visibility": "catalogue_location",
            }
        )
        blobs[sha(payload)] = payload
    context = {
        "owner_package_id": "owner",
        "owner_name": "gettext",
        "owner_version": owner["version"],
        "files": [notices[0]],
        "matched_locations": [
            {
                "path": measurement["path"],
                "catalogue_layer_diff_id": origin,
                "layer_blob_digest": blob,
                "verification": "verified_image_bytes_match_inventory_checksum",
                "captured_sha256": sha(data),
            }
        ],
    }
    package = {"distro_owner_context": {"checksum_matched_notices": [context]}}
    return artifact, package, verified, native, notices, blobs


def test_recovery_retains_specific_source_grant_identity_and_notices(evidence):
    declaration, notices = module.recover_java_license(*evidence)
    assert declaration["expression"] == "GPL-3.0-or-later"
    assert declaration["basis"] == "reviewed_java_class_payload"
    assert declaration["identity"] == next(iter(evidence[2].values()))[0]
    assert declaration["class_sha256"] == {
        "gnu/gettext/Example.class": sha(b"class bytes")
    }
    assert declaration["original_catalogue_licenses"] == []
    assert len(notices) == 2
    assert module.reviewed_java_locations(evidence[3]) == set(evidence[2])


def test_version_and_packaging_metadata_changes_reuse_identical_classes(evidence):
    artifact, package, verified, native, rows, blobs = evidence
    artifact["version"] = "0.22"
    native["artifacts"][1]["version"] = "0.22-1"
    context = package["distro_owner_context"]["checksum_matched_notices"][0]
    context["owner_version"] = "0.22-1"
    key = next(iter(verified))
    measurement = verified[key][0]
    data = archive(creator="17.0.19 (Debian)")
    verified[key] = (dict(measurement, sha256=sha(data), size=len(data)), data)
    context["matched_locations"][0]["captured_sha256"] = sha(data)
    assert (
        module.recover_java_license(artifact, package, verified, native, rows, blobs)[
            0
        ]["expression"]
        == "GPL-3.0-or-later"
    )


@pytest.mark.parametrize(
    "change",
    [
        "missing-bytes",
        "hash",
        "size",
        "method",
        "layer",
        "blob",
        "name",
        "path",
        "type",
        "extra-location",
        "owner-name",
        "owner-version",
        "owner-id",
        "owner-checksum",
        "duplicate-owner",
        "copyright",
        "common-text",
        "missing-common",
        "ambiguous-common",
    ],
)
def test_unbound_identity_or_notice_evidence_stays_unresolved(evidence, change):
    artifact, package, verified, native, rows, blobs = evidence
    key = next(iter(verified))
    measurement, data = verified[key]
    context = package["distro_owner_context"]["checksum_matched_notices"][0]
    if change == "missing-bytes":
        verified.clear()
    elif change == "hash":
        measurement["sha256"] = "a" * 64
    elif change == "size":
        measurement["size"] += 1
    elif change == "method":
        measurement["method"] = "catalogue_claim"
    elif change == "layer":
        measurement["catalogue_layer_diff_id"] = "unrelated"
    elif change == "blob":
        context["matched_locations"][0]["layer_blob_digest"] = "unrelated"
    elif change == "name":
        artifact["name"] = "another"
    elif change == "path":
        artifact["locations"][0]["path"] = "/other/gettext.jar"
    elif change == "type":
        artifact["type"] = "binary"
    elif change == "extra-location":
        artifact["locations"].append(deepcopy(artifact["locations"][0]))
    elif change == "owner-name":
        native["artifacts"][1]["name"] = "another"
    elif change == "owner-version":
        native["artifacts"][1]["version"] = "different"
    elif change == "owner-id":
        context["owner_package_id"] = "unknown"
    elif change == "owner-checksum":
        context["matched_locations"][0]["verification"] = "path_only"
    elif change == "duplicate-owner":
        package["distro_owner_context"]["checksum_matched_notices"].append(
            deepcopy(context)
        )
    elif change == "copyright":
        blobs[rows[0]["sha256"]] = b"changed grant"
    elif change == "common-text":
        rows[1]["sha256"] = sha(b"changed")
        blobs[rows[1]["sha256"]] = b"changed"
    elif change == "missing-common":
        rows.pop()
    else:
        rows.append(deepcopy(rows[1]))
    assert (
        module.recover_java_license(artifact, package, verified, native, rows, blobs)
        is None
    )


@pytest.mark.parametrize(
    "claims",
    [
        [{"value": "MIT"}],
        [{"value": "UNKNOWN"}, {"value": "MIT"}],
        [{"value": "UNLICENSED"}],
        [{"value": "NONE"}],
    ],
)
def test_review_does_not_replace_existing_or_non_grant_claims(evidence, claims):
    evidence[0]["licenses"] = claims
    assert module.recover_java_license(*evidence) is None


@pytest.mark.parametrize(
    "data",
    [
        archive({"gnu/gettext/Example.class": b"changed"}),
        archive({"gnu/gettext/Example.class": b"class bytes", "Other.class": b"extra"}),
        archive({"gnu/gettext/Other.class": b"class bytes"}),
        archive(extra_manifest="Class-Path: external.jar\r\n"),
        archive(extra_manifest="Created-By: duplicate\r\n"),
        archive(creator="unreviewed vendor"),
        archive(comment=b"custom terms"),
        b"MZ" + archive(),
        archive() + b"trailing payload",
        b"not a jar",
    ],
    ids=[
        "changed-class", "extra-class", "different-class", "external-classpath",
        "duplicate-creator", "unreviewed-creator", "archive-comment",
        "executable-prefix", "trailing-payload", "not-a-jar",
    ],
)
def test_changed_payload_or_unreviewed_manifest_stays_unresolved(evidence, data):
    artifact, package, verified, native, rows, blobs = evidence
    key = next(iter(verified))
    measurement = verified[key][0]
    verified[key] = (dict(measurement, sha256=sha(data), size=len(data)), data)
    package["distro_owner_context"]["checksum_matched_notices"][0]["matched_locations"][
        0
    ]["captured_sha256"] = sha(data)
    assert (
        module.recover_java_license(artifact, package, verified, native, rows, blobs)
        is None
    )


def test_duplicate_class_members_and_oversize_archives_are_refused():
    assert module._class_hashes(archive(duplicate=True)) is None
    assert (
        module._class_hashes(archive({"Example.class": b"x" * (32 * 1024 + 1)})) is None
    )
    assert (
        module._class_hashes(archive({"Example.class": b"x" * module.MAX_JAR_BYTES}))
        is None
    )


def test_actual_reviewed_rules_keep_runtime_and_utility_grants_separate():
    rules = {rule["name"]: rule for rule in module._rules()}
    assert rules["gettext"]["expression"] == "GPL-3.0-or-later"
    assert rules["libintl"]["expression"] == "LGPL-2.1-or-later"
    assert set(rules["gettext"]["classes"]) == {
        "gnu/gettext/GetURL.class",
        "gnu/gettext/GetURL$1.class",
        "gnu/gettext/DumpResource.class",
    }
    assert set(rules["libintl"]["classes"]) == {"gnu/gettext/GettextResource.class"}


def test_java_projection_preserves_license_conclusion_and_original_claims(evidence):
    from packages.sca.sbom_notices import append_notices

    declaration, notices = module.recover_java_license(*evidence)
    record = {"id": "jar", "files": notices, "recovered_component_license": declaration}
    cdx, spdx = {}, {}
    component = {"licenses": [{"license": {"name": "UNKNOWN"}}]}
    package = {"licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION"}
    append_notices(
        cdx,
        spdx,
        {"jar": component},
        {"jar": package},
        {"packages": [record], "scope": "reviewed component evidence"},
    )
    assert component["licenses"] == [{"expression": "GPL-3.0-or-later"}]
    assert package["licenseDeclared"] == "GPL-3.0-or-later"
    assert package["licenseConcluded"] == "NOASSERTION"
    assert evidence[0]["licenses"] == []
    assert declaration["original_catalogue_licenses"] == []

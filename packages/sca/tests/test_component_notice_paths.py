"""Named component notices remain exact-path candidates, not inherited grants."""

import hashlib
import json

import pytest

from core.oci.evidence import capture
from core.oci.notice_paths import component_notice_paths
from core.oci.tests.test_evidence import fixture_image
from packages.sca.sbom_notices import load_notices


def image(files, *, link=False):
    native, blob = fixture_image(files, link=link)
    native["artifacts"][0].update(
        type="binary",
        name="node",
        licenses=[],
        locations=[native["files"][0]["location"]],
    )
    return native, blob


def prepare(tmp_path, native, blob):
    report, blobs = capture(native, lambda layer: [blob])
    raw_sha = hashlib.sha256(json.dumps(native).encode()).hexdigest()
    report["catalogue_sha256"] = raw_sha
    store = tmp_path / "notices/sha256"
    store.mkdir(parents=True)
    for sha, data in blobs.items():
        (store / sha).write_bytes(data)
    summary, _ = load_notices(tmp_path, native, raw_sha, report)
    return report, summary["packages"][0]


@pytest.mark.parametrize("name", ["node", "t32.exe", "gettext.jar"])
def test_specific_component_notice_is_probed_and_associated_without_catalogue_file(
    tmp_path, name
):
    native, blob = image(
        {
            "runtime/" + name: b"component",
            "runtime/LICENSE." + name: b"own complete notice",
        }
    )
    native["files"] = native["files"][:1]
    if name.endswith(".jar"):
        native["artifacts"][0]["type"] = "java-archive"
    report, package = prepare(tmp_path, native, blob)
    (row,) = report["files"]
    assert row["path"] == "/runtime/LICENSE." + name
    assert row["roles"] == ["component_specific_notice_probe"]
    assert row["visibility"] == "layer_probe_runtime_visibility_unconfirmed"
    assert package["status"] == "notice_candidate_captured" and package["gaps"] == []
    assert package["files"][0]["reasons"] == ["component_specific_notice_candidate"]
    assert not any(key.startswith("recovered_") for key in package)
    assert native["artifacts"][0]["licenses"] == []


def test_general_or_other_component_notice_is_not_inherited(tmp_path):
    native, blob = image(
        {
            "runtime/node": b"component",
            "runtime/LICENSE": b"general notice",
            "runtime/LICENSE.other": b"other component notice",
        }
    )
    _, package = prepare(tmp_path, native, blob)
    assert package["status"] == "no_associated_evidence" and package["files"] == []


def test_notice_in_another_directory_is_not_associated(tmp_path):
    native, blob = image(
        {"runtime/node": b"component", "another/LICENSE.node": b"unrelated"}
    )
    _, package = prepare(tmp_path, native, blob)
    assert package["status"] == "no_associated_evidence" and package["files"] == []


def test_component_probe_does_not_expand_python_or_npm_notice_scope():
    for kind in ["python", "npm"]:
        assert (
            component_notice_paths(
                {
                    "type": kind,
                    "locations": [{"path": "/runtime/node", "layerID": "layer"}],
                }
            )
            == set()
        )


def test_component_notice_symlink_is_refused():
    native, blob = image(
        {"runtime/node": b"component", "runtime/LICENSE.node": b""}, link=True
    )
    with pytest.raises(ValueError):
        capture(native, lambda layer: [blob])


def test_named_notice_from_another_layer_stays_unassociated():
    from packages.sca.sbom_notices import associate

    native, blob = image(
        {"runtime/node": b"component", "runtime/LICENSE.node": b"notice"}
    )
    report, blobs = capture(native, lambda layer: [blob])
    row = report["files"][0]
    row["catalogue_layer_diff_id"] = "sha256:" + "f" * 64
    summary = associate(native, report["subject"], [row], blobs)
    assert summary["packages"][0]["status"] == "no_associated_evidence"
    assert summary["packages"][0]["files"] == []

"""Project-specific Debian notices require verified correspondence and source."""
from copy import deepcopy
import hashlib

import pytest

from packages.sca.sbom_distro_python_notices import associate_project_notices


GAP = "no associated notice candidate; licence text completeness is unverified"


def fixture(source="Source: https://pypi.org/project/pip/\n", *, newline="\n"):
    text = (source + "\nFiles: *\nLicense: Expat\n Full text\n").replace("\n", newline).encode()
    sha = hashlib.sha256(text).hexdigest()
    row = {"path": "/usr/share/doc/python3-pip/copyright", "sha256": sha,
           "catalogue_layer_diff_id": "layer", "content_kind": "notice_candidate"}
    native = {"artifacts": [{"id": "child", "name": "pip", "type": "python"},
                            {"id": "owner", "name": "python3-pip", "type": "deb"}]}
    record = {"id": "child", "status": "metadata_only", "files": [], "gaps": [GAP],
              "distro_owner_context": {"checksum_matched_notices": [{"owner_package_id": "owner",
              "files": [row], "owner_notice_gaps": []}], "unresolved_locations": []}}
    return native, [record], {sha: text}


@pytest.mark.parametrize("source", [
    "Source: https://pypi.org/project/pip/\n",
    "Source: https://pypi.python.org/pypi/pip\n",
    "It was downloaded from\nhttp://pypi.python.org/pypi/pip\n",
])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["LF", "CRLF"])
def test_project_notice_is_associated_without_inheriting_license(source, newline):
    native, records, blobs = fixture(source, newline=newline)
    original = deepcopy((native, blobs))
    associate_project_notices(native, records, blobs)
    assert records[0]["status"] == "notice_candidate_captured"
    assert records[0]["gaps"] == []
    assert records[0]["files"][0]["reasons"] == ["checksum_matched_debian_python_project_notice"]
    assert (native, blobs) == original
    assert "recovered_component_license" not in records[0]
    assert "recovered_distribution_license" not in records[0]
    assert "reasons" not in records[0]["distro_owner_context"]["checksum_matched_notices"][0]["files"][0]


@pytest.mark.parametrize("source", [
    "Source: https://pypi.org/project/other/\n",
    "Source: https://pypi.org.evil/project/pip/\n",
    "Source: https://pypi.org/project/pip/extra\n",
    "Files: vendor/*\nSource: https://pypi.org/project/pip/\n",
    "License:\nSource: https://pypi.org/project/pip/\n",
    "Source: https://pypi.org/project/pip/\nSource: https://pypi.org/project/other/\n",
])
@pytest.mark.parametrize("newline", ["\n", "\r\n"], ids=["LF", "CRLF"])
def test_incidental_or_conflicting_source_does_not_close_gap(source, newline):
    data = fixture(source, newline=newline)
    original = deepcopy(data)
    associate_project_notices(*data)
    assert data == original


@pytest.mark.parametrize("change", ["ambiguous", "unresolved", "wrong_owner", "wrong_type", "wrong_path", "npm"])
def test_unverified_or_different_package_keeps_gap(change):
    data = fixture()
    context = data[1][0]["distro_owner_context"]
    if change == "ambiguous":
        context["checksum_matched_notices"] *= 2
    elif change == "unresolved":
        context["unresolved_locations"].append({"path": "/unknown"})
    elif change == "wrong_owner":
        data[0]["artifacts"][1]["name"] = "nodejs"
    elif change == "wrong_type":
        data[0]["artifacts"][1]["type"] = "npm"
    elif change == "wrong_path":
        context["checksum_matched_notices"][0]["files"][0]["path"] = "/other/copyright"
    else:
        data[0]["artifacts"][0]["type"] = "npm"
    original = deepcopy(data)
    associate_project_notices(*data)
    assert data == original


def test_common_reference_gaps_remain_and_second_pass_is_idempotent():
    data = fixture()
    data[1][0]["distro_owner_context"]["checksum_matched_notices"][0]["owner_notice_gaps"] = ["missing referenced text"]
    associate_project_notices(*data)
    assert data[1][0]["gaps"] == ["missing referenced text"]
    original = deepcopy(data)
    associate_project_notices(*data)
    assert data == original


def test_association_budget_is_enforced():
    with pytest.raises(ValueError, match="budget"):
        associate_project_notices(*fixture(), limit=0)

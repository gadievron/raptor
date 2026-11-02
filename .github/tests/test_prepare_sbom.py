"""Provenance corrections must preserve inventory and refuse false identities."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("prepare_sbom", ROOT / ".github/scripts/prepare_sbom.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)
MANIFEST = mod.read_document(ROOT / ".github/sbom-provenance.json")[0]


def documents(kind="python", name="raptor", version="3.1.0", metadata=None, purl=None):
    identifier = "a" * 16
    purl = purl or f"pkg:pypi/{name}@{version}"
    artifact = {"id": identifier, "type": kind, "name": name, "version": version,
                "purl": purl, "locations": [{"path": "/uv.lock"}], "metadata": metadata or {"index": "."}, "cpes": [{"cpe": "old"}]}
    native = {"schema": {"version": "16.1.11"}, "source": {"name": mod.REPOSITORY, "version": "b" * 40},
              "artifacts": [artifact], "artifactRelationships": [{"parent": "root", "child": identifier}]}
    cdx = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "metadata": {"component": {"name": mod.REPOSITORY, "version": "b" * 40}},
           "components": [{"bom-ref": identifier, "type": "library", "name": name, "version": version,
                           "purl": purl, "cpe": "old", "properties": [{"name": "syft:cpe23", "value": "old"}]},
                          {"bom-ref": "file", "type": "file", "name": "./LICENSE", "hashes": [{"alg": "SHA-256", "content": "c" * 64}]}],
           "dependencies": [{"ref": identifier, "dependsOn": ["file"]}]}
    spdx = {"spdxVersion": "SPDX-2.3", "packages": [
        {"name": mod.REPOSITORY, "versionInfo": "b" * 40},
        {"SPDXID": "SPDXRef-Package-python-test-" + identifier, "name": name, "versionInfo": version,
         "licenseDeclared": "NOASSERTION", "licenseConcluded": "NOASSERTION", "downloadLocation": "NOASSERTION",
         "externalRefs": [{"referenceType": "purl", "referenceLocator": purl}, {"referenceType": "cpe23Type", "referenceLocator": "old"}]}],
        "relationships": [{"spdxElementId": "root", "relationshipType": "CONTAINS", "relatedSpdxElement": "file"}],
        "files": [{"SPDXID": "file", "fileName": "./LICENSE"}]}
    return native, cdx, spdx


PROJECT = {"name": "raptor", "version": "3.1.0", "revision": "b" * 40}


def test_local_project_is_git_identified_without_mutating_evidence():
    native, cdx, spdx = documents()
    originals = deepcopy((native, cdx, spdx))
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)
    assert (native, cdx, spdx) == originals
    assert c["components"][0]["purl"] == "pkg:generic/gadievron/raptor@" + "b" * 40
    assert c["components"][0]["version"] == "b" * 40
    assert c["components"][0]["licenses"] == [{"license": {"id": "MIT"}}]
    assert s["packages"][1]["licenseDeclared"] == "MIT"
    assert s["packages"][1]["licenseConcluded"] == "NOASSERTION"
    assert c["dependencies"] == cdx["dependencies"]
    assert c["components"][1] == cdx["components"][1]
    assert s["files"] == spdx["files"] and s["relationships"] == spdx["relationships"]
    assert not any(p["name"] == "syft:cpe23" for p in c["components"][0]["properties"])
    assert report["packages"][0]["original_purl"] == "pkg:pypi/raptor@3.1.0"


def test_name_alone_does_not_establish_local_project_origin():
    native, cdx, spdx = documents(metadata={"index": "https://pypi.org/simple"})
    with pytest.raises(ValueError, match="local RAPTOR project"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)


@pytest.mark.parametrize("homepage", ["https://github.com/nvm-sh/nvm", "https://example.org/nvm"])
def test_nvm_identity_requires_matching_upstream_metadata(homepage):
    native, cdx, spdx = documents("npm", "nvm", "0.40.8",
        {"homepage": homepage, "url": "git://github.com/nvm-sh/nvm.git"}, "pkg:npm/nvm@0.40.8")
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST)
    if homepage.endswith("/nvm-sh/nvm"):
        assert c["components"][0]["purl"] == "pkg:generic/nvm-sh/nvm@0.40.8"
        assert report["packages"][0]["sources"][0]["status"] == "candidate_build_correspondence_unverified"
        assert "unverified" in s["packages"][1]["sourceInfo"]
    else:
        assert c["components"][0]["purl"] == cdx["components"][0]["purl"]
        assert not report["packages"][0]["sources"]
        assert report["packages"][0]["gaps"]


@pytest.mark.parametrize("vendor", [True, False])
def test_nodesource_is_never_conflated_with_debian(vendor):
    version = "24.21.0-1nodesource1"
    native, cdx, spdx = documents("deb", "nodejs", version,
        {"maintainer": "NodeSource Support <support@nodesource.com>" if vendor else "someone else", "architecture": "amd64"},
        f"pkg:deb/debian/nodejs@{version}?arch=amd64&distro=debian-12")
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST)
    assert not report["packages"][0]["sources"]
    assert "do not use Debian source" in s["packages"][1]["sourceInfo"]
    if vendor:
        assert c["components"][0]["purl"] == f"pkg:deb/nodesource/nodejs@{version}?arch=amd64"
    else:
        assert c["components"][0]["purl"] == cdx["components"][0]["purl"]
        assert len(report["packages"][0]["gaps"]) == 2


@pytest.mark.parametrize("name,version", [("cart", "1.2.3"), ("playwright", "1.60.0"), ("tree-sitter-php", "0.24.1")])
def test_wheel_source_candidates_are_not_asserted_as_build_sources(name, version):
    native, cdx, spdx = documents(name=name, version=version)
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST)
    assert c["components"][0]["purl"] == cdx["components"][0]["purl"]
    assert "licenses" not in c["components"][0]
    assert s["packages"][1]["downloadLocation"] == "NOASSERTION"
    assert s["packages"][1]["licenseDeclared"] == "NOASSERTION"
    assert report["packages"][0]["sources"][0]["status"] == "candidate_build_correspondence_unverified"
    assert all("/blob/" in r["url"] for r in c["components"][0]["externalReferences"] if r["type"] == "license")


def test_new_version_does_not_inherit_an_old_source_pin():
    native, cdx, spdx = documents(name="playwright", version="2.0")
    result = mod.prepare(native, cdx, spdx, MANIFEST)[2]["packages"]
    assert len(result) == 1 and not result[0]["sources"]
    assert "no source candidate" in result[0]["gaps"][0]


@pytest.mark.parametrize("change", [
    lambda n,c,s: c["components"][0].update(version="different"),
    lambda n,c,s: s["packages"][1].update(name="different"),
    lambda n,c,s: c["metadata"]["component"].update(version="different"),
    lambda n,c,s: c.update(components=[]),
    lambda n,c,s: n["artifacts"].append(deepcopy(n["artifacts"][0])),
])
def test_conflicting_or_incomplete_exports_fail_before_output(change):
    native, cdx, spdx = documents()
    change(native, cdx, spdx)
    with pytest.raises(ValueError):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)


def test_package_id_before_purl_subpath_is_matched():
    native, cdx, spdx = documents()
    cdx["components"][0]["bom-ref"] = "pkg:pypi/raptor@3.1.0?package-id=" + "a" * 16 + "&upstream=source#subdir"
    assert mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)[2]["packages"]


@pytest.mark.parametrize("body", ['{"x":1,"x":2}', '{"x":NaN}', '{"x":"\\ud800"}'])
def test_ambiguous_or_invalid_json_is_refused(tmp_path, body):
    path = tmp_path / "input.json"
    path.write_text(body)
    with pytest.raises(ValueError):
        mod.read_document(path)


def test_cli_refuses_missing_repository_evidence_without_writing(tmp_path):
    docs = list(documents())
    docs[0]["source"]["type"] = "directory"
    paths = []
    for i, data in enumerate(docs):
        path = tmp_path / f"input-{i}.json"
        path.write_text(json.dumps(data))
        paths.append(path)
    out = tmp_path / "out"
    p = subprocess.run([sys.executable, str(ROOT / ".github/scripts/prepare_sbom.py"),
        "--syft", str(paths[0]), "--cyclonedx", str(paths[1]), "--spdx", str(paths[2]), "--out", str(out)],
        capture_output=True, text=True)
    assert p.returncode != 0 and not out.exists()
    assert "requires --repo" in p.stderr



def test_nested_lockfile_does_not_establish_the_root_project():
    native, cdx, spdx = documents()
    native["artifacts"][0]["locations"] = [{"path": "/nested/uv.lock"}]
    with pytest.raises(ValueError, match="local RAPTOR project"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)


def test_duplicate_package_id_qualifiers_are_rejected():
    native, cdx, spdx = documents()
    cdx["components"][0]["bom-ref"] = "pkg:pypi/raptor@3.1.0?package-id=" + "a" * 16 + "&package-id=" + "b" * 16
    with pytest.raises(ValueError, match="occurrence identity"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)


@pytest.mark.parametrize("change", [
    lambda m: m["sources"][0].update(revision="main"),
    lambda m: m["sources"][0].update(repository="https://example.org/repo"),
    lambda m: m["sources"].append(deepcopy(m["sources"][0])),
    lambda m: m["sources"][0].update(licence_path=".."),
    lambda m: m.update(version=True),
])
def test_invalid_source_candidate_fails_instead_of_supplying_a_link(change):
    manifest = deepcopy(MANIFEST)
    change(manifest)
    with pytest.raises(ValueError):
        mod.source_entries(manifest)



def test_cli_refuses_malformed_retained_evidence_before_writing(tmp_path):
    docs = list(documents(name="cart", version="1.2.3"))
    paths = []
    for i, data in enumerate(docs):
        path = tmp_path / f"input-{i}.json"
        path.write_text(json.dumps(data))
        paths.append(path)
    output = tmp_path / "out"
    result = subprocess.run([sys.executable, str(ROOT / ".github/scripts/prepare_sbom.py"),
        "--syft", str(paths[0]), "--cyclonedx", str(paths[1]), "--spdx", str(paths[2]),
        "--out", str(output)], capture_output=True, text=True)
    # Unit fixtures deliberately omit required SPDX document fields. Identity
    # matching alone must not be enough to publish a prepared output pair.
    assert result.returncode != 0 and not output.exists()


def test_occurrence_qualifiers_are_bounded():
    native, cdx, spdx = documents()
    cdx["components"][0]["bom-ref"] = "pkg:pypi/raptor@3.1.0?" + "&".join(f"x{i}=v" for i in range(65))
    with pytest.raises(ValueError):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)

"""Provenance corrections must preserve inventory and refuse false identities."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[3]
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



def archive_fixture():
    native, cdx, spdx = documents()
    extra_n, extra_c, extra_s = documents(name="Example_Package", version="1.0", metadata={"index": "https://pypi.org/simple"})
    extra_n["artifacts"][0]["id"] = "d" * 16
    extra_c["components"][0]["bom-ref"] = "d" * 16
    extra_s["packages"][1]["SPDXID"] = "SPDXRef-Package-python-example-" + "d" * 16
    native["artifacts"] += extra_n["artifacts"]
    cdx["components"].append(extra_c["components"][0])
    spdx["packages"].append(extra_s["packages"][1])
    lock = {"package": [{"name": "example-package", "version": "1.0",
                         "source": {"registry": "https://pypi.org/simple"},
                         "sdist": {"url": "https://files.pythonhosted.org/example-1.0.tar.gz", "hash": "sha256:" + "e" * 64}}]}
    return native, cdx, spdx, lock


def test_locked_archives_preserve_binary_hashes_and_download_location():
    native, cdx, spdx, lock = archive_fixture()
    cdx["components"][-1]["hashes"] = [{"alg": "SHA-256", "content": "f" * 64}]
    spdx["packages"][-1]["checksums"] = [{"algorithm": "SHA256", "checksumValue": "f" * 64}]
    spdx["packages"][-1]["downloadLocation"] = "https://example.org/installed.whl"
    originals = deepcopy((native, cdx, spdx, lock))
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)
    assert (native, cdx, spdx, lock) == originals
    reference = c["components"][-1]["externalReferences"][0]
    assert reference["url"] == lock["package"][0]["sdist"]["url"]
    assert reference["hashes"] == [{"alg": "SHA-256", "content": "e" * 64}]
    assert reference["comment"] == "lockfile_source_archive_content_unverified"
    assert c["components"][-1]["hashes"] == cdx["components"][-1]["hashes"]
    assert s["packages"][-1]["checksums"] == spdx["packages"][-1]["checksums"]
    assert s["packages"][-1]["downloadLocation"] == "https://example.org/installed.whl"
    assert s["packages"][-1]["licenseDeclared"] == "NOASSERTION"
    assert '"content": "' + "e" * 64 in s["packages"][-1]["sourceInfo"]
    assert report["lock_inventory"] == {"expected_packages": 1, "matched_packages": 1, "missing_packages": []}


@pytest.mark.parametrize("field,value", [("index", "https://other.example/simple"), ("path", "/nested/uv.lock")])
def test_source_archive_is_not_borrowed_from_a_different_origin_or_location(field, value):
    native, cdx, spdx, lock = archive_fixture()
    if field == "index":
        native["artifacts"][-1]["metadata"]["index"] = value
    else:
        native["artifacts"][-1]["locations"][0]["path"] = value
    entries = mod.locked_sources(lock)
    result = mod.plan(native["artifacts"][-1], {}, PROJECT, entries)
    assert result is None or not result["sources"]
    with pytest.raises(ValueError, match="missing package identities"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)


def test_wheel_only_locked_release_has_an_explicit_source_gap():
    native, cdx, spdx, lock = archive_fixture()
    del lock["package"][0]["sdist"]
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)
    record = report["packages"][-1]
    assert not record["sources"]
    assert "no source archive" in record["gaps"][0]
    assert any("no source archive" in p["value"] for p in c["components"][-1]["properties"])
    assert "no source archive" in s["packages"][-1]["sourceInfo"]


@pytest.mark.parametrize("change", [
    lambda p: p["sdist"].update(hash="sha256:abc"),
    lambda p: p["sdist"].update(url="file:///tmp/source.tar.gz"),
    lambda p: p["sdist"].update(url="https://user:password@example.org/source.tar.gz"),
    lambda p: p["source"].update(registry="http://example.org/simple"),
    lambda p: p.update(source=None),
    lambda p: p.update(source="unsupported"),
])
def test_invalid_archive_evidence_is_refused(change):
    native, cdx, spdx, lock = archive_fixture()
    change(lock["package"][0])
    with pytest.raises(ValueError):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)


def test_duplicate_and_missing_lock_entries_cannot_look_complete():
    native, cdx, spdx, lock = archive_fixture()
    lock["package"].append(deepcopy(lock["package"][0]))
    with pytest.raises(ValueError, match="duplicate locked"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)
    lock["package"][-1]["version"] = "2.0"
    with pytest.raises(ValueError, match="missing package identities"):
        mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, lock)



@pytest.fixture
def material_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "data").mkdir()
    (repo / "data/payload.json").write_text('{"_source":{"license":"source-specific terms"},"value":1}\n')
    (repo / "NOTICE").write_text("Fixture copyright and licence evidence\n")
    subprocess.run(["git", "init", "-q", str(repo)], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "core.autocrlf=false", "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    manifest = {"bundles": [{"id": "test-data", "name": "Retained upstream excerpts", "root": "data", "files": ["*.json"],
        "license": "GPL-2.0-only", "license_scope": "Upstream excerpts; original annotations remain MIT.",
        "upstream": "https://example.org/upstream", "notice_paths": ["NOTICE"], "source_credits": True}]}
    return repo, revision, manifest


def test_bundled_material_bytes_notices_and_scoped_licences_reach_both_exports(material_repo):
    import hashlib
    repo, revision, manifest = material_repo
    (repo / "data/untracked.json").write_text('{"untracked":true}')
    records, references = mod.bundled_materials(repo, revision, manifest)
    assert not references and len(records) == 1
    record = records[0]
    assert [f["path"] for f in record["files"]] == ["data/payload.json"]
    assert record["files"][0]["sha256"] == hashlib.sha256((repo / "data/payload.json").read_bytes()).hexdigest()
    assert '/'+revision+'/' in record["files"][0]["url"]
    assert record["source_credits"][0]["source"]["license"] == "source-specific terms"
    _, cdx, spdx = documents()
    cdx["metadata"]["component"]["version"] = revision
    spdx["packages"][0].update(versionInfo=revision, SPDXID="SPDXRef-root")
    original = deepcopy((cdx, spdx))
    mod.append_bundles(cdx, spdx, records)
    bundle = cdx["metadata"]["component"]["components"][0]
    assert bundle["type"] == "data" and bundle["licenses"] == [{"license": {"id": "GPL-2.0-only"}}]
    assert bundle["externalReferences"][0]["type"] == "website"
    assert bundle["externalReferences"][1]["hashes"][0]["content"] == record["files"][0]["sha256"]
    assert spdx["packages"][-1]["primaryPackagePurpose"] == "OTHER"
    assert '"material_kind": "data"' in spdx["packages"][-1]["sourceInfo"]
    assert spdx["packages"][-1]["licenseDeclared"] == "GPL-2.0-only"
    assert spdx["packages"][-1]["licenseConcluded"] == "NOASSERTION"
    assert "original annotations remain MIT" in spdx["packages"][-1]["licenseComments"]
    assert spdx["relationships"][-1]["relationshipType"] == "CONTAINS"
    assert cdx["components"] == original[0]["components"]
    assert spdx["files"] == original[1]["files"]


def test_changed_worktree_material_is_not_mislabelled_as_committed_bytes(material_repo):
    repo, revision, manifest = material_repo
    (repo / "data/payload.json").write_text('{"changed":true}')
    with pytest.raises(ValueError, match="differs from committed"):
        mod.bundled_materials(repo, revision, manifest)


@pytest.mark.parametrize("change", [
    lambda r: r.update(root="../outside"),
    lambda r: r.update(files=["../outside"]),
    lambda r: r.update(notice_paths=["missing-notice"]),
    lambda r: r.update(license="invented-license"),
    lambda r: r.update(files=["missing.json"]),
    lambda r: r.update(upstream_type="invented-type"),
])
def test_invalid_or_unavailable_material_evidence_fails(material_repo, change):
    repo, revision, manifest = material_repo
    change(manifest["bundles"][0])
    with pytest.raises(ValueError):
        mod.bundled_materials(repo, revision, manifest)


def test_unknown_dataset_terms_remain_explicit_unknowns(material_repo):
    repo, revision, manifest = material_repo
    manifest["bundles"][0]["license"] = None
    record = mod.bundled_materials(repo, revision, manifest)[0][0]
    assert record["gaps"] and record["license"] is None
    _, cdx, spdx = documents()
    cdx["metadata"]["component"]["version"] = revision
    spdx["packages"][0].update(versionInfo=revision, SPDXID="SPDXRef-root")
    mod.append_bundles(cdx, spdx, [record])
    assert "licenses" not in cdx["metadata"]["component"]["components"][0]
    assert spdx["packages"][-1]["licenseDeclared"] == "NOASSERTION"


def test_bundle_revision_cannot_be_borrowed_from_another_checkout(material_repo):
    repo, revision, manifest = material_repo
    records, _ = mod.bundled_materials(repo, revision, manifest)
    _, cdx, spdx = documents()
    with pytest.raises(ValueError, match="revision does not match"):
        mod.append_bundles(cdx, spdx, records)


def test_external_snippet_classification_is_closed_and_scope_is_retained(material_repo):
    repo, _, manifest = material_repo
    prefix = "out/dataflow-corpus-fixtures/example/"
    (repo / "data/payload.json").write_text(json.dumps({"source": {"file_path": prefix+"source.c", "snippet": "example();"}}))
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "finding"], check=True)
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    rule = manifest["bundles"][0]
    del rule["files"]
    rule["snippet_prefix"] = prefix
    records, _ = mod.bundled_materials(repo, revision, manifest)
    assert records[0]["snippet_origins"] == [prefix+"source.c"]
    rule["snippet_prefix"] = prefix+"other/"
    with pytest.raises(ValueError, match="no committed material"):
        mod.bundled_materials(repo, revision, manifest)


def test_unpopulated_gitlinks_are_references_and_populated_ones_are_not_silently_omitted(material_repo):
    repo, revision, manifest = material_repo
    subprocess.run(["git", "-C", str(repo), "update-index", "--add", "--cacheinfo", "160000,"+revision+",submodule"], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "gitlink"], check=True)
    current = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    _, references = mod.bundled_materials(repo, current, manifest)
    assert references == [{"path": "submodule", "revision": revision, "status": "reference_only_unpopulated_gitlink"}]
    (repo / "submodule").mkdir()
    (repo / "submodule/source.c").write_text("populated source")
    with pytest.raises(ValueError, match="populated submodules"):
        mod.bundled_materials(repo, current, manifest)



def test_symlink_swaps_cannot_supply_bundle_evidence(material_repo, tmp_path):
    repo, revision, manifest = material_repo
    outside = tmp_path / "outside.json"
    outside.write_text('{"outside":true}')
    (repo / "data/payload.json").unlink()
    (repo / "data/payload.json").symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        mod.bundled_materials(repo, revision, manifest)


@pytest.mark.parametrize("path,body", [
    ("core/domains/data/public_suffix_list.dat", "// source snapshot\ncom\n"),
    ("packages/sca/data/calibration/example.json", '{"_source":{"license":"upstream terms"}}'),
    ("core/dataflow/corpus/findings/external.json", '{"source":{"file_path":"out/dataflow-corpus-fixtures/unregistered/source.c","snippet":"example();"}}'),
])
def test_deleting_a_whole_material_class_does_not_silently_reduce_coverage(material_repo, path, body):
    repo, _, manifest = material_repo
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    subprocess.run(["git", "-C", str(repo), "add", "."], check=True)
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid",
                    "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "additional material"], check=True)
    revision = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
    with pytest.raises(ValueError, match="no (inventory|bundled-material) rule"):
        mod.bundled_materials(repo, revision, manifest)


def test_duplicate_notices_are_refused_before_emitting_invalid_references(material_repo):
    repo, revision, manifest = material_repo
    manifest["bundles"][0]["notice_paths"] *= 2
    with pytest.raises(ValueError, match="duplicate bundle notice"):
        mod.bundled_materials(repo, revision, manifest)

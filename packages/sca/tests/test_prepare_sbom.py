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


def test_owned_cli_preparation_matches_public_copying_result():
    native, cdx, spdx = documents()
    original_native = deepcopy(native)
    summary = {"scope": "captured notice candidates", "packages": [
        {"id": "a" * 16, "files": [], "gaps": ["retained gap"]}]}
    expected = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, notice_summary=summary)
    actual = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, notice_summary=summary, _copy_inputs=False)
    assert actual == expected
    assert actual[0] is cdx and actual[1] is spdx
    assert native == original_native


def test_public_preparation_keeps_graph_and_notice_results_independent():
    native, cdx, spdx = documents()
    summary = {"scope": "captured notice candidates", "packages": [
        {"id": "a" * 16, "files": [], "gaps": ["retained gap"]}]}
    originals = deepcopy((native, cdx, spdx, summary))
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT, notice_summary=summary)
    c["components"][-1]["hashes"][0]["content"] = "d" * 64
    s["files"][0]["fileName"] = "changed"
    report["notice_evidence"]["packages"][0]["gaps"].append("changed")
    assert (native, cdx, spdx, summary) == originals


def test_compact_provenance_view_preserves_enrichment_and_retained_inventory():
    native, cdx, spdx = documents()
    native["files"] = [{"location": {"path": "/large/file/index"}}]
    native["artifacts"][0]["metadata"]["files"] = [{"path": "large/record/index"}]
    before = deepcopy(native)
    expected = mod.prepare(native, cdx, spdx, MANIFEST, PROJECT)
    actual = mod.prepare(mod._provenance_view(native), cdx, spdx, MANIFEST, PROJECT)
    assert actual == expected
    assert native == before
    assert actual[0]["components"][-1] == cdx["components"][-1]
    assert actual[1]["files"] == spdx["files"]


@pytest.mark.parametrize("raw", [b'{ "text": "\\u00e9" }\n', '{"text":"é"}\n'.encode()])
def test_document_digest_keeps_exact_input_bytes(tmp_path, raw):
    import hashlib

    path = tmp_path / "input.json"
    path.write_bytes(raw)
    data, digest = mod.read_document(path)
    assert data == {"text": "é"}
    assert digest == hashlib.sha256(raw).hexdigest()
    assert path.read_bytes() == raw


@pytest.fixture
def nvm_source_case():
    import hashlib
    native, cdx, spdx = documents("npm", "nvm", "0.40.8",
        {"homepage": "https://github.com/nvm-sh/nvm", "url": "git://github.com/nvm-sh/nvm.git"}, "pkg:npm/nvm@0.40.8")
    artifact = native["artifacts"][0]
    artifact["locations"] = [{"path": "/opt/nvm/package.json"}]
    payloads = {name: name.encode() for name in ("nvm.sh", "nvm-exec", "bash_completion", "install.sh", "LICENSE.md")}
    payloads["package.json"] = b'{"version":"0.40.8"}'
    native["files"] = [{"location": {"path": "/opt/nvm/" + name}, "digests": [
        {"algorithm": "sha256", "value": hashlib.sha256(raw).hexdigest()}]} for name, raw in payloads.items()]
    def fetch(url):
        if "/commits/" in url:
            return json.dumps({"sha": "c" * 40}).encode()
        assert "/" + "c" * 40 + "/" in url
        return payloads[url.rsplit("/", 1)[1]]
    return native, cdx, spdx, fetch


def test_verified_nvm_source_is_bound_to_all_runtime_files(nvm_source_case):
    native, cdx, spdx, fetch = nvm_source_case
    checks = mod.verify_nvm_source(native, fetch=fetch)
    check = checks[native["artifacts"][0]["id"]]
    assert check["status"] == "verified_interpreted_source"
    assert len(check["files"]) == 6
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks=checks)
    record = report["packages"][0]
    assert record["gaps"] == []
    assert record["source_check"] == check
    assert record["sources"][0]["status"] == "verified_interpreted_source"
    assert "verified_interpreted_source" in s["packages"][1]["sourceInfo"]
    assert c["components"][0]["externalReferences"][0]["url"].endswith("c" * 40)


@pytest.mark.parametrize("fault", ["changed", "missing", "duplicate", "network", "revision", "version"])
def test_nvm_source_refuses_incomplete_or_different_evidence(nvm_source_case, fault):
    native, cdx, spdx, fetch = nvm_source_case
    if fault == "changed":
        native["files"][0]["digests"][0]["value"] = "0" * 64
    elif fault == "missing":
        native["files"].pop()
    elif fault == "duplicate":
        native["files"].append(native["files"][0])
    original = fetch
    def fetch(url):
        if fault == "network":
            raise OSError("offline")
        if fault == "revision" and "/commits/" in url:
            return b'{"sha":"main"}'
        if fault == "version" and url.endswith("/package.json"):
            return b'{"version":"0.40.9"}'
        return original(url)
    checks = mod.verify_nvm_source(native, fetch=fetch)
    assert checks[native["artifacts"][0]["id"]]["status"] == "unverified"
    report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks=checks)[2]
    assert report["packages"][0]["gaps"]


def test_nvm_new_version_resolves_source_without_manifest_edit(nvm_source_case):
    import hashlib
    native, cdx, spdx, fetch = nvm_source_case
    version = "0.40.99"
    raw = json.dumps({"version": version}).encode()
    for file in native["files"]:
        if file["location"]["path"].endswith("/package.json"):
            file["digests"][0]["value"] = hashlib.sha256(raw).hexdigest()
    for obj, key in [(native["artifacts"][0], "version"), (cdx["components"][0], "version"),
                     (spdx["packages"][1], "versionInfo")]:
        obj[key] = version
    calls = []
    def track(url):
        calls.append(url)
        return raw if url.endswith("/package.json") else fetch(url)
    checks = mod.verify_nvm_source(native, fetch=track)
    assert calls[0].endswith("/commits/v" + version)
    assert all("/" + "c" * 40 + "/" in url for url in calls[1:])
    report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks=checks)[2]
    assert report["packages"][0]["gaps"] == []


def test_nvm_retained_source_cache_verifies_offline(nvm_source_case, tmp_path):
    native, _, _, fetch = nvm_source_case
    responses = {}
    def retain(url):
        raw = fetch(url)
        responses[url] = raw.decode()
        return raw
    expected = mod.verify_nvm_source(native, fetch=retain)
    path = tmp_path / "source-cache.json"
    path.write_text(json.dumps({"version": 1, "responses": responses}))
    assert mod.verify_nvm_cache(native, path) == expected
    del responses[next(url for url in responses if url.endswith("/nvm.sh"))]
    path.write_text(json.dumps({"version": 1, "responses": responses}))
    assert mod.verify_nvm_cache(native, path)[native["artifacts"][0]["id"]]["status"] == "unverified"


def test_nvm_missing_cache_keeps_warning(nvm_source_case, tmp_path):
    native, _, _, _ = nvm_source_case
    checks = mod.verify_nvm_cache(native, tmp_path / "absent.json")
    assert checks[native["artifacts"][0]["id"]]["status"] == "unverified"


def test_playwright_source_proof_preserves_its_scope_and_original_inventory():
    native, cdx, spdx = documents("python", "playwright", "1.60.0", {"index": "https://pypi.org/simple"})
    proof = {"status": "verified_source_payload", "sdk_url": "https://github.com/microsoft/playwright-python/tree/" + "a" * 40,
             "driver_url": "https://github.com/microsoft/playwright/tree/" + "b" * 40,
             "files": [{"path": "/site/playwright/__init__.py", "sha256": "c" * 64}],
             "limitations": ["not a wheel build attestation"]}
    originals = deepcopy((native, cdx, spdx))
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks={native["artifacts"][0]["id"]: proof})
    record = report["packages"][0]
    assert record["gaps"] == []
    assert record["source_check"] == proof
    assert [source["status"] for source in record["sources"]] == ["verified_interpreted_source_payload", "verified_slsa_driver_payload"]
    assert (native, cdx, spdx) == originals
    assert c["components"][0]["purl"] == cdx["components"][0]["purl"]
    assert s["packages"][1]["licenseDeclared"] == "NOASSERTION"


def test_failed_playwright_verification_retains_source_warning():
    native, cdx, spdx = documents("python", "playwright", "1.60.0", {"index": "https://pypi.org/simple"})
    proof = {"status": "unverified", "gap": "Playwright source check failed"}
    report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks={native["artifacts"][0]["id"]: proof})[2]
    assert "Playwright source check failed" in report["packages"][0]["gaps"]
    assert report["packages"][0]["sources"][0]["status"] == "candidate_build_correspondence_unverified"


def test_authenticated_nodesource_binary_keeps_build_gap_and_vendor_identity():
    version = "24.21.0-1nodesource1"
    native, cdx, spdx = documents("deb", "nodejs", version,
        {"maintainer": "NodeSource Support <support@nodesource.com>", "architecture": "amd64"}, "pkg:deb/debian/nodejs@" + version)
    proof = {"status": "verified_publisher_release_binary", "source": {"type": "distribution",
        "url": "https://nodejs.org/dist/v24.21.0/node-v24.21.0.tar.xz", "status": "publisher_signed_source_reference",
        "hashes": [{"alg": "SHA-256", "content": "c" * 64}]}, "limitations": ["not a binary-to-source build attestation"]}
    c, s, report = mod.prepare(native, cdx, spdx, MANIFEST, source_checks={native["artifacts"][0]["id"]: proof})
    record = report["packages"][0]
    assert len(record["gaps"]) == 1 and "not attested" in record["gaps"][0]
    assert record["source_check"] == proof
    assert record["sources"][0] == proof["source"]
    assert c["components"][0]["purl"].startswith("pkg:deb/nodesource/nodejs@")
    assert s["packages"][1]["licenseDeclared"] == "NOASSERTION"

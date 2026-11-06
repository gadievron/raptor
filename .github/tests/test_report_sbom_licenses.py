"""Coverage reports warn without gating and never turn incomplete data into zero."""
import base64
from dataclasses import asdict
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys

import pytest

from core.oci.evidence import subject

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("container_license_report", ROOT / ".github/scripts/report_sbom_licenses.py")
tool = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = tool
SPEC.loader.exec_module(tool)



def test_report_import_requires_only_the_standard_library():
    result = subprocess.run(
        [sys.executable, '-I', '-S', '-c',
         'import runpy, sys; sys.path.insert(0, sys.argv[1]); '
         'runpy.run_path(sys.argv[2], run_name="sbom_report_import_check"); '
         'assert "core.http.egress_backend" not in sys.modules; '
         'assert "urllib3" not in sys.modules',
         str(ROOT), str(ROOT / '.github/scripts/report_sbom_licenses.py')],
        capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr


def sha(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def inputs(tmp_path):
    config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "a" * 64]}}).encode()
    manifest = json.dumps({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": sha(config), "size": len(config)},
                           "layers": [{"digest": "sha256:" + "b" * 64, "size": 1, "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"}]}).encode()
    native = {"schema": {"version": "16.1.11"}, "source": {"type": "image", "name": "example/image", "version": sha(manifest), "metadata": {"manifestDigest": sha(manifest), "imageID": sha(config),
              "manifest": base64.b64encode(manifest).decode(), "config": base64.b64encode(config).decode()}},
              "descriptor": {"configuration": {"search": {"scope": "squashed"}}},
              "files": [{"location": {"path": "/usr/bin/known"}}], "artifacts": [{"id": "package", "name": "example", "version": "1", "type": "npm", "licenses": [{"value": "MIT"}]}]}
    raw = json.dumps(native).encode()
    provenance = {"inputs": [{"sha256": hashlib.sha256(raw).hexdigest()}], "packages": [{"id": "package", "name": "example", "gaps": []}],
                  "notice_evidence": {"subject": subject(native)[0], "packages": [{"id": "package", "status": "notice_candidate_captured", "files": [{"path": "/LICENSE", "catalogue_layer_diff_id": "layer", "sha256": "c" * 64, "content_kind": "notice_candidate"}], "gaps": []}]}}
    (tmp_path / "prepared").mkdir()
    (tmp_path / "syft.json").write_bytes(raw)
    save(tmp_path, provenance)
    return native, provenance, sha(manifest)


def save(root, provenance):
    (root / "prepared/provenance.json").write_text(json.dumps(provenance))


def test_complete_report_has_counts_and_no_warning(tmp_path):
    _, _, digest = inputs(tmp_path)
    report = tool.collect(tmp_path, digest)
    assert report.status == "complete_for_catalogued_packages"
    assert report.metrics.packages == 1
    assert report.metrics.unresolved_declarations == report.metrics.notice_gap_packages == 0
    assert tool.annotations(report) == []
    assert "container-sbom" in tool.markdown(report)
    assert asdict(report)["schema_version"] == 1


def test_notice_gaps_and_source_gaps_remain_separate(tmp_path):
    _, provenance, digest = inputs(tmp_path)
    record = provenance["notice_evidence"]["packages"][0]
    record.update(status="metadata_only", gaps=["missing notice"])
    provenance["packages"][0]["gaps"] = ["source correspondence unavailable"]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.status == "gaps" and report.metrics.notice_gap_packages == 1
    assert report.metrics.source_gap_packages == 1
    assert report.metrics.unresolved_declarations == 0
    assert "missing notice" in tool.markdown(report)
    assert len(tool.annotations(report)) == 3
    assert any(line.startswith("::notice title=Container source/build evidence") for line in tool.annotations(report))
    assert "source correspondence unavailable" in tool.markdown(report)


@pytest.mark.parametrize("change", ["missing", "wrong_image", "stale_inventory", "omitted", "duplicate", "empty", "hidden_gap", "malformed"])
def test_incomplete_or_unbound_audits_have_unknown_coverage(tmp_path, change):
    native, provenance, digest = inputs(tmp_path)
    if change == "missing":
        (tmp_path / "prepared/provenance.json").unlink()
    elif change == "wrong_image":
        digest = "sha256:" + "f" * 64
    elif change == "stale_inventory":
        provenance["inputs"][0]["sha256"] = "0" * 64
    elif change == "omitted":
        provenance["notice_evidence"]["packages"] = []
    elif change == "duplicate":
        provenance["notice_evidence"]["packages"] *= 2
    elif change == "empty":
        native["artifacts"] = []
        raw = json.dumps(native).encode()
        (tmp_path / "syft.json").write_bytes(raw)
        provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    elif change == "hidden_gap":
        provenance["notice_evidence"]["packages"][0]["status"] = "metadata_only"
    else:
        (tmp_path / "syft.json").write_text("{broken")
    if change != "missing":
        save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.status == "unavailable" and report.metrics is None
    assert "Coverage is unknown" in tool.markdown(report)
    assert tool.annotations(report)[0].startswith("::warning")


def test_cli_returns_success_and_emits_downloadable_unavailable_report(tmp_path):
    result = subprocess.run([sys.executable, str(ROOT / ".github/scripts/report_sbom_licenses.py"),
                             "--audit-dir", str(tmp_path), "--image-digest", "sha256:" + "a" * 64,
                             "--emit-annotations"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "::warning" in result.stdout
    report = json.loads((tmp_path / "license-report.json").read_text())
    assert report["status"] == "unavailable" and report["metrics"] is None
    assert (tmp_path / "license-report.md").exists()


def test_annotation_commands_and_markdown_are_escaped_and_bounded():
    report = tool.Report("sha256:" + "a" * 64, status="gaps", metrics=tool.Metrics(20, 0, 20, 0, 0))
    report.issues = [tool.Issue(str(i), "name%\n::error::injected|<b>`", "1", "npm", False, ["missing\rnotice"]) for i in range(20)]
    warnings = tool.annotations(report)
    assert len(warnings) == 10
    assert all("\n" not in line and "\r" not in line for line in warnings)
    assert "%25%0A" in warnings[1]
    assert "<b>" not in tool.markdown(report)
    assert "&#124;" in tool.markdown(report)


def test_failed_preparation_cannot_reuse_a_clean_report(tmp_path):
    _, _, digest = inputs(tmp_path)
    result = subprocess.run([sys.executable, str(ROOT / ".github/scripts/report_sbom_licenses.py"),
                             "--audit-dir", str(tmp_path), "--image-digest", digest,
                             "--audit-status", "failure", "--emit-annotations"], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    report = json.loads((tmp_path / "license-report.json").read_text())
    assert report["status"] == "unavailable" and report["metrics"] is None
    assert "Evidence preparation outcome: failure" in result.stdout


def test_inventory_budget_refusal_is_reported_as_unknown(tmp_path, monkeypatch):
    _, _, digest = inputs(tmp_path)
    monkeypatch.setattr(tool, "MAX_BYTES", 64)
    report = tool.collect(tmp_path, digest)
    assert report.status == "unavailable" and report.metrics is None
    assert tool.annotations(report)[0].startswith("::warning")


def test_uncatalogued_executables_warn_without_inventing_package_license_gaps(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    native["files"] = [{"location": {"path": "/usr/local/bin/uv", "layerID": "layer"},
                        "unknowns": ["unknowns-labeler: no package identified in executable file"]},
                       {"location": {"path": "/usr/bin/known"}}]
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.status == "complete_for_catalogued_packages"
    assert report.metrics.unidentified_executables == 1
    assert report.metrics.notice_gap_packages == 0
    assert report.inventory_candidates[0]["path"] == "/usr/local/bin/uv"
    assert "::warning" in tool.annotations(report)[0]
    assert "/usr/local/bin/uv" in tool.markdown(report)


def test_missing_executable_inventory_is_unknown(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    del native["files"]
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.unidentified_executables is None
    assert report.inventory_errors
    assert "unknown" in tool.markdown(report)
    assert "::warning" in tool.annotations(report)[0]


@pytest.mark.parametrize("status,retain_text", [("unavailable", False), ("release_notice_candidates_captured", True),
                                               ("release_notice_candidates_captured", False)])
@pytest.mark.parametrize("origin", ["release_file", "source_header", "upstream_commit"])
def test_native_collection_receipts_require_captured_text(tmp_path, status, retain_text, origin):
    _, provenance, digest = inputs(tmp_path)
    text = b"upstream release notice"
    text_sha = hashlib.sha256(text).hexdigest()
    receipt = {"name": "uv", "version": "0.7.22", "status": status,
               "files": ([{"file": "LICENSE.txt", "sha256": text_sha}] if status != "unavailable" else [])}
    if receipt["files"] and origin == "source_header":
        receipt["files"][0].update(notice_origin="source_header", source_sha256="d" * 64,
                                   source_packages=["SPDXRef-PACKAGE-component"])
    elif receipt["files"] and origin == "upstream_commit":
        receipt["files"][0].update(upstream_revision="d" * 40, git_blob_sha1="e" * 40,
                                   source_package="SPDXRef-PACKAGE-component")
    raw = json.dumps(receipt).encode()
    receipt_sha = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / "prepared/notices/sha256"
    directory.mkdir(parents=True)
    (directory / receipt_sha).write_bytes(raw)
    prefix = "/usr/share/doc/raptor-native-notices/uv/"
    evidence = [{"path": prefix + "NOTICE-PROVENANCE.json", "sha256": receipt_sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"}]
    if retain_text:
        (directory / text_sha).write_bytes(text)
        evidence.append({"path": prefix + "LICENSE.txt", "sha256": text_sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"})
    provenance["notice_evidence"]["unassociated_files"] = evidence
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    if status == "release_notice_candidates_captured" and not retain_text:
        assert report.inventory_errors and not report.native_notice_collections
    else:
        assert report.native_notice_collections == [receipt]
        assert bool(tool.annotations(report)) == (status == "unavailable")


def test_empty_file_inventory_does_not_report_zero_unidentified_executables(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    native["files"] = []
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.unidentified_executables is None
    assert report.inventory_errors and tool.annotations(report)


def ownership_fixture():
    raw_digest = hashlib.sha256(b"installed executable").digest()
    digest = raw_digest.hex()
    location = {"path": "/usr/local/lib/python3.14/site-packages/example-1.dist-info/METADATA", "layerID": "layer"}
    artifact = {"id": "example", "name": "example", "version": "1", "type": "python",
                "locations": [location], "metadata": {"files": [
                    {"path": "../../../bin/example", "digest": {"algorithm": "sha256", "value": base64.urlsafe_b64encode(raw_digest).rstrip(b"=").decode()}}]}}
    entry = {"location": {"path": "/usr/local/bin/example", "layerID": "layer"},
             "metadata": {"type": "RegularFile"}, "digests": [{"algorithm": "sha256", "value": digest}]}
    candidate = {"path": entry["location"]["path"], "layer_id": "layer", "reasons": ["no package identified"]}
    return {"artifacts": [artifact], "files": [entry]}, [candidate]


def test_checksum_record_resolves_normalised_script_path_without_directory_guess():
    native, candidates = ownership_fixture()
    resolved, pending = tool.match_inventory_ownership(native, candidates)
    assert not pending and len(resolved) == 1
    assert resolved[0]["package_id"] == "example"
    assert resolved[0]["sha256"] == resolved[0]["expected_sha256"]


@pytest.mark.parametrize("change,reason", [
    ("mismatch", "package_file_checksum_mismatch"),
    ("missing_hash", "file_sha256_unavailable"),
    ("other_layer", "no_sha256_package_file_record"),
    ("no_record", "no_sha256_package_file_record"),
    ("invalid_base64", "no_sha256_package_file_record"),
    ("directory_only", "no_sha256_package_file_record"),
    ("ambiguous_owner", "ambiguous_package_file_records"),
    ("duplicate_inventory", "ambiguous_file_inventory"),
    ("symlink", "non_regular_file_requires_identity_verification"),
])
def test_insufficient_or_conflicting_evidence_never_hides_candidates(change, reason):
    import copy
    native, candidates = ownership_fixture()
    artifact = native["artifacts"][0]
    if change == "mismatch":
        native["files"][0]["digests"][0]["value"] = "0" * 64
    elif change == "missing_hash":
        native["files"][0].pop("digests")
    elif change == "other_layer":
        artifact["locations"][0]["layerID"] = "different"
    elif change == "no_record":
        artifact["metadata"]["files"] = []
    elif change == "invalid_base64":
        artifact["metadata"]["files"][0]["digest"]["value"] = "!" * 43
    elif change == "directory_only":
        artifact["metadata"]["files"][0]["path"] = "../../../bin/unrelated"
    elif change == "ambiguous_owner":
        second = copy.deepcopy(artifact)
        second["id"] = "other"
        native["artifacts"].append(second)
    elif change == "duplicate_inventory":
        native["files"] *= 2
    else:
        native["files"][0]["metadata"]["type"] = "SymbolicLink"
    resolved, pending = tool.match_inventory_ownership(native, candidates)
    assert not resolved and len(pending) == 1
    assert pending[0]["ownership_gap"] == reason


def test_report_keeps_raw_count_and_checksum_proof_after_resolving_warning(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    claim, candidates = ownership_fixture()
    artifact = claim["artifacts"][0]
    artifact["id"] = "package"
    artifact["licenses"] = [{"value": "MIT"}]
    native["artifacts"] = [artifact]
    native["files"] = claim["files"]
    native["files"][0]["unknowns"] = candidates[0]["reasons"]
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.scanner_unidentified_executables == 1
    assert report.metrics.checksum_matched_executables == 1
    assert report.metrics.unidentified_executables == 0
    assert report.inventory_ownership[0]["sha256"]
    assert not report.inventory_candidates and not tool.annotations(report)


def test_pipeline_collects_sha256_for_files_outside_package_catalogue():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    step = workflow.split("      - name: Generate container inventories\n", 1)[1].split("      - name:", 1)[0]
    assert "SYFT_FILE_METADATA_SELECTION: all" in step
    assert "SYFT_FILE_METADATA_DIGESTS: sha256" in step
    assert "continue-on-error: true" in step


@pytest.mark.parametrize("kind", ["source_sbom", "notice_candidate"])
def test_larger_upstream_sbom_is_bounded_separately_from_notice_text(tmp_path, kind):
    _, provenance, digest = inputs(tmp_path)
    source = json.dumps({"spdxVersion": "SPDX-2.3", "padding": "x" * (600 * 1024)}).encode()
    source_sha = hashlib.sha256(source).hexdigest()
    filename = "NOTICE-SOURCE-SBOM-" + source_sha + ".json"
    receipt = {"name": "cpython", "version": "3.14.10", "status": "release_notice_candidates_captured",
               "files": [{"file": filename, "sha256": source_sha, "content_kind": kind}]}
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / "prepared/notices/sha256"
    directory.mkdir(parents=True)
    (directory / sha).write_bytes(raw)
    (directory / source_sha).write_bytes(source)
    prefix = "/usr/share/doc/raptor-native-notices/cpython/"
    provenance["notice_evidence"]["unassociated_files"] = [
        {"path": prefix + "NOTICE-PROVENANCE.json", "sha256": sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"},
        {"path": prefix + filename, "sha256": source_sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"}]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert bool(report.native_notice_collections) == (kind == "source_sbom")
    assert bool(report.inventory_errors) == (kind != "source_sbom")


def test_report_matches_native_receipt_only_after_notice_bytes_are_validated(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    binary_sha = "a" * 64
    native["files"] = [{"location": {"path": path, "layerID": "layer"},
                        "metadata": {"type": "RegularFile"},
                        "digests": [{"algorithm": "sha256", "value": binary_sha}],
                        "unknowns": ["no package identified"]}
                       for path in ("/usr/local/bin/git", "/usr/local/bin/git-upload-pack")]
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    notice = b"upstream release notice"
    notice_sha = hashlib.sha256(notice).hexdigest()
    receipt = {"name": "git", "version": "2.56.0", "binary": "/usr/local/bin/git", "binary_sha256": binary_sha,
               "status": "release_notice_candidates_captured", "files": [{"file": "LICENSE.txt", "sha256": notice_sha}]}
    raw_receipt = json.dumps(receipt).encode()
    receipt_sha = hashlib.sha256(raw_receipt).hexdigest()
    directory = tmp_path / "prepared/notices/sha256"
    directory.mkdir(parents=True)
    (directory / receipt_sha).write_bytes(raw_receipt)
    (directory / notice_sha).write_bytes(notice)
    prefix = "/usr/share/doc/raptor-native-notices/git/"
    provenance["notice_evidence"]["unassociated_files"] = [
        {"path": prefix + "NOTICE-PROVENANCE.json", "sha256": receipt_sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"},
        {"path": prefix + "LICENSE.txt", "sha256": notice_sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": "layer"}]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.scanner_unidentified_executables == 2
    assert report.metrics.native_identity_matched_executables == 2
    assert report.metrics.unidentified_executables == 0
    assert len(report.native_identity_matches) == 2
    assert report.metrics.checksum_matched_executables == 0
    (directory / notice_sha).write_bytes(b"changed notice")
    report = tool.collect(tmp_path, digest)
    assert report.metrics.native_identity_matched_executables == 0
    assert report.metrics.unidentified_executables == 2
    assert report.inventory_errors


def test_report_grades_build_declarations_and_rejects_changed_install_metadata(tmp_path):
    native, provenance, digest = inputs(tmp_path)
    layer = "layer"
    metadata = {"/usr/lib/python/config/Makefile": b"declared modules", "/usr/include/python/patchlevel.h": b"3.14.10"}
    hashes = {path: hashlib.sha256(body).hexdigest() for path, body in metadata.items()}
    native["files"] = [
        {"location": {"path": "/usr/bin/python3", "layerID": layer}, "metadata": {"type": "RegularFile"},
         "digests": [{"algorithm": "sha256", "value": "a" * 64}]},
        {"location": {"path": "/usr/lib/python/_example.so", "layerID": layer}, "metadata": {"type": "RegularFile"},
         "digests": [{"algorithm": "sha256", "value": "e" * 64}], "unknowns": ["no package identified"]}]
    for path, sha in hashes.items():
        native["files"].append({"location": {"path": path, "layerID": layer}, "metadata": {"type": "RegularFile"},
                                "digests": [{"algorithm": "sha256", "value": sha}]})
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / "prepared/notices/sha256"
    directory.mkdir(parents=True)
    prefix = "/usr/share/doc/raptor-native-notices/cpython/"
    records, evidence = [], []
    for path, body in metadata.items():
        sha = hashes[path]
        filename = "NOTICE-INSTALLED-METADATA-" + sha + ".txt"
        (directory / sha).write_bytes(body)
        records.append({"file": filename, "sha256": sha, "image_path": path, "content_kind": "installed_build_metadata"})
        evidence.append({"path": prefix + filename, "sha256": sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": layer})
    text = b"upstream release license"
    sha = hashlib.sha256(text).hexdigest()
    (directory / sha).write_bytes(text)
    records.append({"file": "LICENSE.txt", "sha256": sha})
    evidence.append({"path": prefix + "LICENSE.txt", "sha256": sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": layer})
    receipt = {"name": "cpython", "version": "3.14.10", "binary": "/usr/bin/python3", "binary_sha256": "a" * 64,
               "status": "release_notice_candidates_captured", "files": records,
               "declared_files": [{"path": "/usr/lib/python/_example.so", "sha256": "e" * 64,
                                   "basis": "cpython_installed_module_build_inventory", "metadata_sha256": list(hashes.values())}]}
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    (directory / sha).write_bytes(raw)
    evidence.append({"path": prefix + "NOTICE-PROVENANCE.json", "sha256": sha, "content_kind": "notice_candidate", "catalogue_layer_diff_id": layer})
    provenance["notice_evidence"]["unassociated_files"] = evidence
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.build_declared_executables == 1 and report.metrics.unidentified_executables == 0
    assert report.native_declaration_matches[0]["evidence_kind"] == "installed_build_declaration"
    assert report.metrics.checksum_matched_executables == report.metrics.native_identity_matched_executables == 0
    native["files"][-1]["digests"][0]["value"] = "f" * 64
    raw = json.dumps(native).encode()
    (tmp_path / "syft.json").write_bytes(raw)
    provenance["inputs"][0]["sha256"] = hashlib.sha256(raw).hexdigest()
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.build_declared_executables == 0 and report.metrics.unidentified_executables == 1


@pytest.mark.parametrize("status,count,label", [
    ("verified_interpreted_source", 6, "Source and metadata matched upstream"),
    ("verified_source_payload", 173, "Python sources and signed driver matched"),
    ("verified_publisher_release_binary", 1, "Binary matches publisher-signed release"),
])
def test_source_assessments_are_visible_without_reclassifying_license_gaps(tmp_path, status, count, label):
    _, provenance, digest = inputs(tmp_path)
    row = provenance["packages"][0]
    row.update(version="1", source_check={"status": status, "files": [{}] * count,
        "binary": {"path": "/usr/bin/node"}, "scope": "explicit files only", "limitations": ["not a complete build attestation"]})
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.unresolved_declarations == report.metrics.notice_gap_packages == 0
    assert report.source_assessments[0]["matched_files"] == count
    assert asdict(report)["source_assessments"][0]["limitations"] == ["not a complete build attestation"]
    text = tool.markdown(report)
    assert label in text and str(count) in text
    assert "prepared/provenance.json" in text
    assert tool.annotations(report) == []


def test_expected_node_build_limit_is_a_notice_without_license_gaps(tmp_path):
    _, provenance, digest = inputs(tmp_path)
    provenance["packages"][0].update(gaps=["exact binary-to-source build correspondence is not attested"],
        source_check={"status": "verified_publisher_release_binary", "binary": {"path": "/usr/bin/node"}})
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.status == "complete_for_catalogued_packages" and not report.issues
    assert report.metrics.source_gap_packages == 1
    assert tool.annotations(report)[0].startswith("::notice title=Container source/build evidence")
    assert "not attested" in tool.markdown(report)


def test_failed_source_check_is_an_actionable_warning(tmp_path):
    _, provenance, digest = inputs(tmp_path)
    provenance["packages"][0].update(gaps=["source check unavailable"], source_check={"status": "unverified"})
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.source_assessments[0]["matched_files"] is None
    assert tool.annotations(report)[0].startswith("::warning title=Container source/build evidence")
    assert "unknown" in tool.markdown(report)


def test_source_summary_escapes_package_names_and_warnings():
    report = tool.Report("sha256:" + "a" * 64, metrics=tool.Metrics(1, 0, 0, 1, 1))
    report.source_assessments = [{"id": "a", "name": "package|<b>\n", "version": "1", "status": "unverified",
                                  "matched_files": None, "gaps": ["missing|<script>\rproof"]}]
    text = tool.markdown(report)
    assert "<b>" not in text and "<script>" not in text
    assert "&#124;" in text and "&lt;script&gt;" in text


def test_malformed_source_proof_cannot_produce_successful_coverage(tmp_path):
    _, provenance, digest = inputs(tmp_path)
    provenance["packages"][0]["source_check"] = "broken"
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics is None and report.status == "unavailable"
    assert report.source_assessments == []


@pytest.mark.parametrize('unavailable', [0, 1])
def test_cargo_candidate_summary_does_not_change_installed_coverage(tmp_path, unavailable):
    _, provenance, digest = inputs(tmp_path)
    counts = dict(candidates=3, captured=2-unavailable, metadata_only=1, unavailable=unavailable)
    receipt = dict(name='uv', version='0.7.22', status='unavailable', files=[], dependency_notices=counts)
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / 'prepared/notices/sha256'
    directory.mkdir(parents=True)
    (directory / sha).write_bytes(raw)
    provenance['notice_evidence']['unassociated_files'] = [dict(
        path='/usr/share/doc/raptor-native-notices/uv/NOTICE-PROVENANCE.json', sha256=sha,
        content_kind='notice_candidate', catalogue_layer_diff_id='layer')]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    assert report.metrics.packages == 1
    assert report.metrics.notice_gap_packages == report.metrics.unresolved_declarations == 0
    assert 'Native dependency notice candidates' in tool.markdown(report)
    assert any(line.startswith('::' + ('warning' if unavailable else 'notice') + ' title=Native dependency notice candidates')
               for line in tool.annotations(report))
    receipt['dependency_notices']['candidates'] = 99
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    (directory / sha).write_bytes(raw)
    provenance['notice_evidence']['unassociated_files'][0]['sha256'] = sha
    save(tmp_path, provenance)
    assert tool.collect(tmp_path, digest).inventory_errors


@pytest.mark.parametrize('status', ['release_library_notices_captured','unavailable','invalid'])
def test_rust_notice_summary_keeps_collection_separate_from_installed_packages(tmp_path, status):
    _, provenance, digest = inputs(tmp_path)
    receipt = dict(name='uv', version='0.7.22', status='unavailable', files=[],
                   toolchain_notices=dict(status=status, version='1.88.0', notice_files=4))
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / 'prepared/notices/sha256'
    directory.mkdir(parents=True)
    (directory / sha).write_bytes(raw)
    provenance['notice_evidence']['unassociated_files'] = [dict(
        path='/usr/share/doc/raptor-native-notices/uv/NOTICE-PROVENANCE.json', sha256=sha,
        content_kind='notice_candidate', catalogue_layer_diff_id='layer')]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    if status == 'invalid':
        assert report.inventory_errors
    else:
        assert report.metrics.packages == 1 and report.metrics.notice_gap_packages == 0
        assert 'Rust standard-library notice candidates' in tool.markdown(report)
        assert 'do not establish the compiler' in tool.markdown(report)
        assert any('title=Rust standard-library notice candidates' in line for line in tool.annotations(report)) == (status == 'unavailable')


@pytest.mark.parametrize('distributor', [3,4,'3'])
def test_distributor_notice_count_is_separate_and_validated(tmp_path, distributor):
    _, provenance, digest = inputs(tmp_path)
    receipt = dict(name='uv', version='0.7.22', status='unavailable', files=[], dependency_notices=dict(
        candidates=3, captured=3, distributor_notices=distributor, metadata_only=0, unavailable=0))
    raw = json.dumps(receipt).encode()
    sha = hashlib.sha256(raw).hexdigest()
    directory = tmp_path / 'prepared/notices/sha256'
    directory.mkdir(parents=True)
    (directory / sha).write_bytes(raw)
    provenance['notice_evidence']['unassociated_files'] = [dict(
        path='/usr/share/doc/raptor-native-notices/uv/NOTICE-PROVENANCE.json', sha256=sha,
        content_kind='notice_candidate', catalogue_layer_diff_id='layer')]
    save(tmp_path, provenance)
    report = tool.collect(tmp_path, digest)
    if type(distributor) is int and distributor == 3:
        assert 'Distributor notices' in tool.markdown(report)
        assert '| uv | 3 | 0 | 3 | 0 | 0 |' in tool.markdown(report)
        assert 'distinct from upstream-authored text' in tool.markdown(report)
        assert not any('title=Native dependency notice candidates' in line for line in tool.annotations(report))
        assert report.metrics.packages == 1 and report.metrics.notice_gap_packages == 0
    else:
        assert report.inventory_errors and not report.native_notice_collections

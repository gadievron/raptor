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
    assert len(tool.annotations(report)) == 2


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
def test_native_collection_receipts_require_captured_text(tmp_path, status, retain_text):
    _, provenance, digest = inputs(tmp_path)
    text = b"upstream release notice"
    text_sha = hashlib.sha256(text).hexdigest()
    receipt = {"name": "uv", "version": "0.7.22", "status": status,
               "files": ([{"file": "LICENSE.txt", "sha256": text_sha}] if status != "unavailable" else [])}
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

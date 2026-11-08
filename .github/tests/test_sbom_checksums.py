"""The signed manifest binds exact evidence bytes without following foreign paths."""
import hashlib
import importlib.util
from pathlib import Path
import shutil
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("write_sbom_checksums", ROOT / ".github/scripts/write_sbom_checksums.py")
SCRIPT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SCRIPT)


@pytest.fixture
def evidence(tmp_path):
    root = tmp_path / "evidence"
    root.mkdir()
    raw = b'{"schemaVersion":2}'
    (root / "manifest.json").write_bytes(raw)
    (root / "image-digest.txt").write_text("sha256:" + hashlib.sha256(raw).hexdigest() + "\n")
    (root / "prepared").mkdir()
    (root / "prepared/notice with spaces.txt").write_bytes(b"Original notice\r\n")
    return root


def test_manifest_covers_image_original_notices_and_partial_reports(evidence):
    assert SCRIPT.write_checksums(evidence) == 3
    manifest = (evidence / SCRIPT.MANIFEST).read_text()
    header, records = manifest.split("\n", 1)
    assert header == "# OCI image: " + (evidence / "image-digest.txt").read_text().strip()
    assert hashlib.sha256(b"Original notice\r\n").hexdigest() + "  prepared/notice with spaces.txt\n" in manifest
    checker = shutil.which("sha256sum")
    if checker:
        # Metadata is checked above; strict checkers differ on comment support.
        result = subprocess.run([checker, "--check", "--strict"], input=records.encode(),
                                cwd=evidence, capture_output=True)
        assert result.returncode == 0, result.stderr
        (evidence / "prepared/notice with spaces.txt").write_bytes(b"Changed")
        assert subprocess.run([checker, "--check", "--strict"], input=records.encode(),
                              cwd=evidence, capture_output=True).returncode != 0


@pytest.mark.parametrize("problem", ["symlink", "directory-link", "fifo", "newline", "backslash", "digest", "missing-manifest", "size", "total", "entries", "existing", "signature"])
def test_unsafe_or_incomplete_evidence_does_not_produce_a_manifest(evidence, tmp_path, monkeypatch, problem):
    import os
    if problem == "symlink":
        (evidence / "linked").symlink_to(tmp_path / "outside")
    elif problem == "directory-link":
        (evidence / "linked").symlink_to(tmp_path, target_is_directory=True)
    elif problem == "fifo":
        os.mkfifo(evidence / "pipe")
    elif problem == "newline":
        (evidence / "bad\nname").write_bytes(b"x")
    elif problem == "backslash":
        (evidence / "bad\\name").write_bytes(b"x")
    elif problem == "digest":
        (evidence / "image-digest.txt").write_text("sha256:" + "f" * 64)
    elif problem == "missing-manifest":
        (evidence / "manifest.json").unlink()
    elif problem == "size":
        monkeypatch.setattr(SCRIPT, "MAX_FILE_BYTES", 8)
    elif problem == "total":
        monkeypatch.setattr(SCRIPT, "MAX_TOTAL_BYTES", 80)
    elif problem == "entries":
        monkeypatch.setattr(SCRIPT, "MAX_ENTRIES", 2)
    elif problem == "existing":
        (evidence / SCRIPT.MANIFEST).write_bytes(b"keep")
    elif problem == "signature":
        (evidence / SCRIPT.BUNDLE).write_bytes(b"stale bundle")
    with pytest.raises(ValueError):
        SCRIPT.write_checksums(evidence)
    if problem == "existing":
        assert (evidence / SCRIPT.MANIFEST).read_bytes() == b"keep"
    else:
        assert not (evidence / SCRIPT.MANIFEST).exists()


def test_refused_internal_open_leaves_no_partial_manifest(evidence, monkeypatch):
    monkeypatch.setattr(SCRIPT, "open_regular_beneath", lambda *args: None)
    with pytest.raises(ValueError, match="safely"):
        SCRIPT.write_checksums(evidence)
    assert not (evidence / SCRIPT.MANIFEST).exists()


def test_attestation_uses_least_job_permissions_and_retains_bundle_before_upload():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    scope, build = workflow.split("  build-push:\n", 1)
    build, docs = build.split("  update-image-docs:\n", 1)
    assert "id-token: write" in build and "attestations: write" in build
    assert "id-token: write" not in scope + docs
    assert build.index("Make audit artifacts readable") < build.index("Hash retained container evidence")
    assert build.index("Hash retained container evidence") < build.index("Attest container evidence checksums")
    assert build.index("Retain evidence signature bundle") < build.index("Retain container SBOM and notice evidence")
    assert "steps.evidence_checksums.outcome == 'success'" in build
    assert "steps.evidence_attestation.outcome == 'success'" in build
    assert "subject-path: ${{ runner.temp }}/container-sbom/evidence-checksums.sha256" in build
    assert "push-to-registry: false" in build
    assert "Container evidence authentication unavailable" in build
    assert "steps.retain_attestation.outcome" in build
    # Authentication is visible but cannot turn coverage gaps into a publication gate.
    publishing = build.split("      - name: Publish verified image\n", 1)[1]
    assert "attestation" not in publishing


def test_uv_signature_result_is_required_before_reporting_authenticated_origin():
    workflow = (ROOT / ".github/workflows/dockerhub-publish.yml").read_text()
    binding = workflow.index("      - name: Bind installed uv to its publisher image")
    readable = workflow.index("      - name: Make audit artifacts readable")
    verify = workflow.index("      - name: Verify and retain uv publisher attestation")
    report = workflow.index("      - name: Report uv provenance status")
    checksums = workflow.index("      - name: Hash retained container evidence")
    assert binding < readable < verify < report < checksums
    block = workflow[verify:report]
    assert "steps.uv_binding.outcome == 'success'" in block
    assert "set -euo pipefail" in block and "continue-on-error: true" in block
    assert "gh attestation verify index.json --repo astral-sh/uv" in block
    assert "GH_TOKEN" not in block and "github.token" not in block
    assert "--signer-workflow astral-sh/uv/.github/workflows/build-docker.yml" in block
    assert "--deny-self-hosted-runners --bundle uv-publisher-attestation.jsonl" in block
    assert "steps.uv_attestation.outcome" in workflow[report:checksums]
    assert "::warning::uv publisher provenance unavailable" in workflow[report:checksums]

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / ".devcontainer" / "Dockerfile"
MANIFEST = ROOT / "containers" / "all-tools-manifest.json"
VERIFIER = ROOT / "containers" / "verify-all-tools.py"


def _manifest() -> dict:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def _verify_manifest(path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            str(VERIFIER),
            "--manifest",
            str(path),
            "--manifest-only",
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def test_bookworm_rr_is_amd64_only_and_fails_closed() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    rr_start = dockerfile.index("# RR DEBUGGER")
    rr_end = dockerfile.index("# Configure kernel for rr", rr_start)
    rr_block = dockerfile[rr_start:rr_end]

    assert 'case "${arch}" in' in rr_block
    assert "amd64)" in rr_block
    assert "rr=5.6.0-3+b1" in rr_block
    assert "rr=5.9.0-9" not in rr_block
    assert "||" not in rr_block
    assert '*) echo "rr is unavailable on ${arch}; skipping in the base image"' in (
        rr_block
    )


def test_all_tools_installs_unversioned_llvm_cov_provider() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    all_tools_start = dockerfile.index("FROM raptor-base AS raptor-all-tools")
    all_tools = dockerfile[all_tools_start:]

    assert "    llvm \\" in all_tools
    assert '"llvm-cov"' in MANIFEST.read_text(encoding="utf-8")


def test_rr_is_required_and_version_verified() -> None:
    manifest = _manifest()
    rr = manifest["tools"]["rr"]

    assert manifest["supported_architectures"] == ["amd64"]
    assert rr == {
        "version": "5.6.0",
        "package": "rr",
        "package_version": "5.6.0-3+b1",
        "version_command": ["rr", "--version"],
    }
    assert "rr" in manifest["required_binaries"]

    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    all_tools_start = dockerfile.index("FROM raptor-base AS raptor-all-tools")
    all_tools = dockerfile[all_tools_start:]
    assert all_tools.index("only linux/amd64 is published") < all_tools.index(
        "RUN raptor-verify-all-tools"
    )

    result = _verify_manifest(MANIFEST)
    assert result.returncode == 0, result.stderr


def test_manifest_verifier_rejects_missing_or_unpinned_rr(tmp_path: Path) -> None:
    manifest = _manifest()

    missing_rr = json.loads(json.dumps(manifest))
    del missing_rr["tools"]["rr"]
    missing_path = tmp_path / "missing-rr.json"
    missing_path.write_text(json.dumps(missing_rr), encoding="utf-8")
    missing_result = _verify_manifest(missing_path)
    assert missing_result.returncode == 2
    assert "manifest must define the Bookworm rr package" in missing_result.stderr

    wrong_package = json.loads(json.dumps(manifest))
    wrong_package["tools"]["rr"]["package_version"] = "5.6.0-3"
    wrong_path = tmp_path / "wrong-rr.json"
    wrong_path.write_text(json.dumps(wrong_package), encoding="utf-8")
    wrong_result = _verify_manifest(wrong_path)
    assert wrong_result.returncode == 2
    assert "rr Bookworm package version must be 5.6.0-3+b1" in wrong_result.stderr

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / ".devcontainer" / "Dockerfile"
DEVCONTAINER = ROOT / ".devcontainer" / "devcontainer.json"
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


def test_standard_target_precedes_all_tools_acceptance_gate() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    standard = dockerfile.index("FROM raptor-base AS raptor-devcontainer")
    all_tools = dockerfile.index("FROM raptor-base AS raptor-all-tools-build")
    acceptance = dockerfile.index("ARG ACCEPT_CODEQL_TERMS=0")

    assert standard < all_tools < acceptance
    assert dockerfile.count("FROM raptor-base AS raptor-devcontainer") == 1
    assert "always select one of the two named targets explicitly" in dockerfile

    devcontainer = DEVCONTAINER.read_text(encoding="utf-8")
    assert '"target": "raptor-devcontainer"' in devcontainer


def test_architecture_download_checksums_are_complete_and_exact() -> None:
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    expected = {
        "TEMURIN_AMD64_SHA256": (
            "ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94"
        ),
        "TEMURIN_ARM64_SHA256": (
            "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"
        ),
        "JOERN_AMD64_SHA256": (
            "d559b569b6180726c2b5b7a5b9b25753c1cbf42c8143ba11311df0d47b2a40a6"
        ),
        "JOERN_ARM64_SHA256": (
            "fceac538dfbc11b7833878532428bdd255ba2fc89762c98d99577edc4c780a1a"
        ),
        "GCLOUD_AMD64_SHA256": (
            "84c5e4798836bda13aa82c3e84fa1acd0c4e4ca5318f7141052e3a5a26a7cc97"
        ),
        "GCLOUD_ARM64_SHA256": (
            "8ce6287e01e54b53d2e9618d124b62ac85efe5a093904ae027b17f2057030662"
        ),
        "OLLAMA_AMD64_SHA256": (
            "c13cea8f3389db4145f8a6cb88d1747242a48639d7c13e3bda7c1ebdc6eebb2f"
        ),
        "OLLAMA_ARM64_SHA256": (
            "4425a112af999ae6572c1ce211fbabeaca7bab23ed5860972acdfc0cc2358420"
        ),
    }
    actual = dict(
        re.findall(r"^ARG ([A-Z]+_(?:AMD64|ARM64)_SHA256)=([0-9a-f]+)$", dockerfile, re.M)
    )

    assert actual == expected
    for argument in expected:
        assert f'"${{{argument}}}"' in dockerfile


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

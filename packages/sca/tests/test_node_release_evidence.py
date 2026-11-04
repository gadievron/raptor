"""Publisher release authentication must retain its build-provenance limitation."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("check_node_release", ROOT / ".github/scripts/check_node_release.py")
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


@pytest.fixture
def release_case(tmp_path, monkeypatch):
    raw = b"\x7fELF release executable fixture"
    name = "node-v24.21.0-linux-x64.tar.xz"
    with tarfile.open(tmp_path / name, "w:xz") as archive:
        member = tarfile.TarInfo("node-v24.21.0-linux-x64/bin/node")
        member.size = len(raw)
        archive.addfile(member, io.BytesIO(raw))
    (tmp_path / "keys.kbx").write_bytes(b"keyring fixture")
    (tmp_path / "inputs.json").write_text(json.dumps({
        "version": "24.21.0", "architecture": "x64", "keyring_url": "https://example.invalid/keys",
        "keyring_sha256": hashlib.sha256((tmp_path / "keys.kbx").read_bytes()).hexdigest()}))
    hashes = {name: hashlib.sha256((tmp_path / name).read_bytes()).hexdigest(), "node-v24.21.0.tar.xz": "b" * 64}
    monkeypatch.setattr(mod, "signed_checksums", lambda evidence: (hashes, "A" * 40))
    artifact = {"version": "24.21.0-1nodesource1", "metadata": {
        "maintainer": "NodeSource Support <support@nodesource.com>", "architecture": "amd64",
        "files": [{"path": "/usr/bin/node", "digest": {"algorithm": "md5", "value": hashlib.md5(raw, usedforsecurity=False).hexdigest()}}]}}
    files = [{"location": {"path": "/usr/bin/node"}, "digests": [{"algorithm": "sha256", "value": hashlib.sha256(raw).hexdigest()}]}]
    return artifact, files, tmp_path, hashes


def test_exact_publisher_binary_retains_source_build_warning(release_case):
    artifact, files, evidence, hashes = release_case
    proof = mod.verify(artifact, files, evidence)
    assert proof["status"] == "verified_publisher_release_binary"
    assert proof["binary"]["sha256"] == files[0]["digests"][0]["value"]
    assert proof["source"]["hashes"][0]["content"] == hashes["node-v24.21.0.tar.xz"]
    assert "not a binary-to-source build attestation" in proof["limitations"]


@pytest.mark.parametrize("fault", ["archive", "binary", "owner", "vendor", "duplicate", "source", "keyring", "version"])
def test_changed_or_unbound_release_evidence_is_refused(release_case, fault):
    artifact, files, evidence, hashes = release_case
    if fault == "archive":
        (evidence / "node-v24.21.0-linux-x64.tar.xz").write_bytes(b"changed")
    elif fault == "binary":
        files[0]["digests"][0]["value"] = "0" * 64
    elif fault == "owner":
        artifact["metadata"]["files"][0]["digest"]["value"] = "0" * 32
    elif fault == "vendor":
        artifact["metadata"]["maintainer"] = "Another distributor"
    elif fault == "duplicate":
        files.append(files[0])
    elif fault == "source":
        del hashes["node-v24.21.0.tar.xz"]
    elif fault == "keyring":
        (evidence / "keys.kbx").write_bytes(b"changed")
    else:
        artifact["version"] = "26.13.0-1nodesource1"
    with pytest.raises(ValueError):
        mod.verify(artifact, files, evidence)


def test_only_gpg_authenticated_plaintext_is_parsed(tmp_path, monkeypatch):
    calls = []
    (tmp_path / "SHASUMS256.txt.asc").write_text("0" * 64 + "  unsigned-source.tar.xz\n")
    def run(command, **kwargs):
        calls.append((command, kwargs))
        return SimpleNamespace(stdout="a" * 64 + "  signed-source.tar.xz\n", stderr="[GNUPG:] VALIDSIG " + "A" * 40 + " 0\n")
    monkeypatch.setattr(mod.subprocess, "run", run)
    hashes, fingerprint = mod.signed_checksums(tmp_path)
    assert hashes == {"signed-source.tar.xz": "a" * 64}
    assert fingerprint == "A" * 40
    command, options = calls[0]
    assert command[command.index("--output") + 1] == "-"
    assert command[command.index("--status-fd") + 1] == "2"
    assert options["check"] and options["timeout"] == 30


def test_invalid_release_signature_is_refused(tmp_path, monkeypatch):
    def fail(command, **kwargs):
        raise subprocess.CalledProcessError(1, command)
    monkeypatch.setattr(mod.subprocess, "run", fail)
    with pytest.raises(subprocess.CalledProcessError):
        mod.signed_checksums(tmp_path)

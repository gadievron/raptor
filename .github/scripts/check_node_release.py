#!/usr/bin/env python3
"""Authenticate a NodeSource node binary against Node's signed release.

A signed source/binary release association is not a build attestation. Keep
that distinction visible even when the installed binary matches exactly.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.request


def read(path: Path, limit: int) -> bytes:
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("release evidence exceeds its byte budget")
    return raw


def fetch(url: str, limit: int) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "raptor-sbom-source-check"})
    with urllib.request.urlopen(request, timeout=30) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("upstream evidence redirect must remain HTTPS")
        raw = response.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("release download exceeds its byte budget")
    return raw


def identity(artifact: dict) -> tuple[str, str]:
    metadata = artifact.get("metadata") or {}
    match = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+)-[A-Za-z0-9.+~_-]*nodesource[0-9]+", artifact.get("version", ""))
    architectures = {"amd64": "x64", "arm64": "arm64"}
    owners = [f for f in metadata.get("files", []) if f.get("path") == "/usr/bin/node"]
    if not match or metadata.get("maintainer") != "NodeSource Support <support@nodesource.com>" or len(owners) != 1:
        raise ValueError("installed vendor identity or binary ownership unavailable")
    return match[1], architectures[metadata["architecture"]]


def collect(artifact: dict, destination: Path) -> None:
    version, architecture = identity(artifact)
    destination.mkdir(parents=True, exist_ok=False)
    commit = json.loads(fetch("https://api.github.com/repos/nodejs/release-keys/commits/main", 1024 * 1024))["sha"]
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("release-key repository revision unavailable")
    key_url = f"https://raw.githubusercontent.com/nodejs/release-keys/{commit}/gpg/pubring.kbx"
    base = f"https://nodejs.org/dist/v{version}/"
    archive = f"node-v{version}-linux-{architecture}.tar.xz"
    (destination / "keys.kbx").write_bytes(fetch(key_url, 2 * 1024 * 1024))
    (destination / "release-keys-LICENSE.txt").write_bytes(fetch(
        f"https://raw.githubusercontent.com/nodejs/release-keys/{commit}/LICENSE.md", 1024 * 1024))
    (destination / "SHASUMS256.txt.asc").write_bytes(fetch(base + "SHASUMS256.txt.asc", 1024 * 1024))
    (destination / archive).write_bytes(fetch(base + archive, 100 * 1024 * 1024))
    (destination / "inputs.json").write_text(json.dumps({"version": version, "architecture": architecture,
        "key_repository_revision": commit, "keyring_url": key_url,
        "keyring_sha256": hashlib.sha256(read(destination / "keys.kbx", 2 * 1024 * 1024)).hexdigest()}, indent=2) + "\n")


def signed_checksums(evidence: Path) -> tuple[dict, str]:
    result = subprocess.run(["gpgv", "--homedir", str(evidence), "--output", "-", "--status-fd", "2",
                             "--keyring", str((evidence / "keys.kbx").resolve()),
                             str(evidence / "SHASUMS256.txt.asc")],
                            capture_output=True, text=True, timeout=30, check=True)
    fingerprints = re.findall(r"^\[GNUPG:\] VALIDSIG ([0-9A-F]{40}) ", result.stderr, re.MULTILINE)
    if len(fingerprints) != 1:
        raise ValueError("release signature did not identify a unique signing key")
    lines = result.stdout.splitlines()
    hashes = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_./-]+)", line)
        if match:
            if match[2] in hashes:
                raise ValueError("ambiguous signed release checksum")
            hashes[match[2]] = match[1]
    return hashes, fingerprints[0]


def verify(artifact: dict, files: list, evidence: Path) -> dict:
    version, architecture = identity(artifact)
    manifest = json.loads(read(evidence / "inputs.json", 1024 * 1024))
    if (manifest.get("version"), manifest.get("architecture")) != (version, architecture):
        raise ValueError("stale vendor release evidence")
    if hashlib.sha256(read(evidence / "keys.kbx", 2 * 1024 * 1024)).hexdigest() != manifest["keyring_sha256"]:
        raise ValueError("retained release-key ring changed")
    hashes, fingerprint = signed_checksums(evidence)
    name = f"node-v{version}-linux-{architecture}.tar.xz"
    archive = evidence / name
    if hashlib.sha256(read(archive, 100 * 1024 * 1024)).hexdigest() != hashes.get(name):
        raise ValueError("release archive differs from publisher-signed checksum")
    installed = [f for f in files if f.get("location", {}).get("path") == "/usr/bin/node"]
    if len(installed) != 1:
        raise ValueError("installed node binary is ambiguous")
    digests = [d.get("value") for d in installed[0].get("digests", []) if d.get("algorithm") == "sha256"]
    if len(digests) != 1:
        raise ValueError("installed node binary has no unique SHA-256")
    primary = f"node-v{version}-linux-{architecture}/bin/node"
    matches = []
    total = 0
    with tarfile.open(archive, mode="r|xz") as release:
        for index, member in enumerate(release):
            total += member.size
            if index >= 30000 or total > 512 * 1024 * 1024:
                raise ValueError("release exceeds expanded archive budget")
            if member.name != primary:
                continue
            if not member.isfile() or member.size > 256 * 1024 * 1024:
                raise ValueError("release binary is not a bounded regular file")
            binary = release.extractfile(member)
            assert binary is not None
            sha = hashlib.sha256()
            md5 = hashlib.md5(usedforsecurity=False)
            while chunk := binary.read(128 * 1024):
                sha.update(chunk)
                md5.update(chunk)
            matches.append((sha.hexdigest(), md5.hexdigest()))
    owned = next(f for f in artifact["metadata"]["files"] if f["path"] == "/usr/bin/node").get("digest", {})
    if len(matches) != 1 or matches[0][0] != digests[0] or owned != {"algorithm": "md5", "value": matches[0][1]}:
        raise ValueError("installed vendor binary differs from authenticated release or package ownership")
    source_name = f"node-v{version}.tar.xz"
    if source_name not in hashes:
        raise ValueError("publisher release has no signed source archive reference")
    base = f"https://nodejs.org/dist/v{version}/"
    return {"status": "verified_publisher_release_binary", "version": version,
            "binary": {"path": "/usr/bin/node", "sha256": digests[0], "archive_url": base + name,
                       "archive_sha256": hashes[name]},
            "source": {"type": "distribution", "url": base + source_name,
                       "status": "publisher_signed_source_reference",
                       "hashes": [{"alg": "SHA-256", "content": hashes[source_name]}]},
            "signing_key_fingerprint": fingerprint,
            "keyring_url": manifest["keyring_url"], "scope": "installed node executable only",
            "limitations": ["not a binary-to-source build attestation", "source archive bytes were not downloaded"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    native = json.loads(read(args.syft, 64 * 1024 * 1024))
    results = {}
    for artifact in native.get("artifacts", []):
        if (artifact.get("type"), artifact.get("name")) != ("deb", "nodejs"):
            continue
        identifier = artifact["id"]
        if not re.fullmatch(r"[0-9a-f]{16}", identifier):
            raise ValueError("invalid package occurrence")
        try:
            evidence = args.evidence / identifier
            if args.download:
                collect(artifact, evidence)
            else:
                results[identifier] = verify(artifact, native.get("files", []), evidence)
        except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, tarfile.TarError) as error:
            results[identifier] = {"status": "unverified", "gap": "Node publisher release verification unavailable or installed binary differs",
                                   "reason": str(error)[:400]}
    args.out.write_text(json.dumps(results, indent=2) + "\n")


if __name__ == "__main__":
    main()

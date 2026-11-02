#!/usr/bin/env python3
"""Retain the complete upstream notices for Playwright's bundled Node runtime.

Version metadata is read without executing Node. Unchanged verified evidence
needs no network; updates must match an official binary release before any
notice is installed.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import io
import json
import lzma
import os
from pathlib import Path
import platform
import posixpath
import re
import stat
import tarfile
import tempfile
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, build_opener

MAX_BINARY = 192 * 1024 * 1024
MAX_ARCHIVE = 96 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024
MAX_TEXT = 2 * 1024 * 1024


def regular_file(path, limit, *, digest_only=False):
    path = Path(path).absolute()
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in runtime or evidence path")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise ValueError("runtime or evidence is not a bounded regular file")
        digest, parts, total = hashlib.sha256(), [], 0
        for chunk in iter(lambda: stream.read(65536), b""):
            total += len(chunk)
            if total > limit:
                raise ValueError("runtime or evidence grew beyond its size limit")
            digest.update(chunk)
            if not digest_only:
                parts.append(chunk)
        if total != before.st_size or os.fstat(stream.fileno()).st_size != total:
            raise ValueError("runtime or evidence changed during reading")
    return digest.hexdigest() if digest_only else b"".join(parts)


def runtime_platform():
    if platform.system() != "Linux":
        raise ValueError("Node notice restoration supports Linux images only")
    architecture = {
        "x86_64": "x64",
        "amd64": "x64",
        "aarch64": "arm64",
        "arm64": "arm64",
    }.get(platform.machine().lower())
    if architecture is None:
        raise ValueError("unsupported Node runtime architecture")
    return "linux-" + architecture


def urls(version, target):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) or target not in {
        "linux-x64",
        "linux-arm64",
    }:
        raise ValueError("invalid Node release identity")
    base = "https://nodejs.org/dist/v" + version + "/"
    return base + "node-v" + version + "-" + target + ".tar.xz", base + "SHASUMS256.txt"


def checked_url(url):
    parsed = urlsplit(url)
    if (
        parsed.scheme != "https"
        or parsed.hostname != "nodejs.org"
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
        or not parsed.path.startswith("/dist/")
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("unsupported Node release URL")


class NodeRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        checked_url(newurl)
        return super().redirect_request(request, fp, code, message, headers, newurl)


def fetch(url, limit):
    checked_url(url)
    with build_opener(NodeRedirect()).open(url, timeout=60) as response:
        checked_url(response.geturl())
        data = response.read(limit + 1)
    if len(data) > limit:
        raise ValueError("Node release response exceeds size limit")
    return data


class ExpandedSource:
    def __init__(self, data):
        self.stream = lzma.LZMAFile(io.BytesIO(data))
        self.total = 0

    def read(self, size):
        data = self.stream.read(min(size, MAX_EXPANDED - self.total + 1))
        self.total += len(data)
        if self.total > MAX_EXPANDED:
            raise ValueError("expanded Node release exceeds size limit")
        return data


def release_evidence(data, version, target):
    source = ExpandedSource(data)
    prefix = "node-v" + version + "-" + target + "/"
    wanted = {prefix + "bin/node", prefix + "LICENSE"}
    selected = {}
    with tarfile.open(fileobj=source, mode="r|") as archive:
        for number, member in enumerate(archive):
            if number >= 50000:
                raise ValueError("Node release contains too many entries")
            canonical = posixpath.normpath(member.name.lstrip("/"))
            if canonical in wanted and member.name != canonical:
                raise ValueError("ambiguous Node release evidence path")
            if member.name not in wanted:
                continue
            if member.name in selected or not member.isfile() or member.size < 0:
                raise ValueError("duplicate or nonregular Node release evidence")
            limit = MAX_BINARY if member.name.endswith("/bin/node") else MAX_TEXT
            if member.size > limit:
                raise ValueError("Node release evidence exceeds size limit")
            stream = archive.extractfile(member)
            digest, parts, total = hashlib.sha256(), [], 0
            for chunk in iter(lambda: stream.read(65536), b""):
                total += len(chunk)
                if total > limit:
                    raise ValueError("Node release evidence grew beyond size limit")
                digest.update(chunk)
                if member.name.endswith("/LICENSE"):
                    parts.append(chunk)
            if total != member.size:
                raise ValueError("truncated Node release evidence")
            selected[member.name] = (
                digest.hexdigest()
                if member.name.endswith("/bin/node")
                else b"".join(parts)
            )
    while source.read(65536):
        pass  # Verify the complete compressed stream and expansion budget.
    if set(selected) != wanted:
        raise ValueError("Node release lacks required binary or complete LICENSE")
    notice = selected[prefix + "LICENSE"]
    if not notice.strip():
        raise ValueError("empty upstream Node license notice")
    return selected[prefix + "bin/node"], notice


def node_version(node):
    # This is a download selector, not a trusted version claim. The complete
    # binary must still match that official release before evidence is used.
    data = regular_file(node, MAX_BINARY)
    versions = set(
        re.findall(
            rb"https://nodejs\.org/(?:download/release|dist)/v([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/node-v\1\.tar\.gz\0",
            data,
        )
    )
    if len(versions) != 1:
        raise ValueError("missing or ambiguous bundled Node release metadata")
    return versions.pop().decode("ascii")


def atomic_write(path, data):
    path = Path(path)
    for parent in (path, *path.parents):
        if parent.is_symlink():
            raise ValueError("symlink in notice destination")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".node-notice-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), 0o644)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def refresh(node, evidence):
    node, evidence = Path(node).absolute(), Path(evidence).absolute()
    binary_sha = regular_file(node, MAX_BINARY, digest_only=True)
    target = runtime_platform()
    receipt = json.loads(regular_file(evidence / "provenance.json", MAX_TEXT))
    required = {
        "schema_version",
        "name",
        "version",
        "platform",
        "binary_sha256",
        "notice_sha256",
        "source_archive_url",
        "source_archive_sha256",
        "checksums_url",
    }
    if not isinstance(receipt, dict) or not required <= receipt.keys():
        raise ValueError("missing cached Node release identity")
    if (
        type(receipt.get("schema_version")) is not int
        or receipt["schema_version"] != 1
        or receipt.get("name") != "node"
        or receipt.get("platform") not in {"linux-x64", "linux-arm64"}
    ):
        raise ValueError("invalid cached Node release evidence")
    release_url, checksums_url = urls(receipt["version"], receipt["platform"])
    if (
        receipt["source_archive_url"] != release_url
        or receipt["checksums_url"] != checksums_url
        or any(
            not re.fullmatch(r"[0-9a-f]{64}", receipt[field])
            for field in ("binary_sha256", "notice_sha256", "source_archive_sha256")
        )
    ):
        raise ValueError("invalid cached Node release identity")
    notice = regular_file(evidence / "LICENSE", MAX_TEXT)
    if (
        hashlib.sha256(notice).hexdigest() != receipt["notice_sha256"]
        or not notice.strip()
    ):
        raise ValueError("cached Node LICENSE differs from reviewed evidence")
    cached_notice = notice
    status = "cached"
    if receipt["platform"] != target or receipt["binary_sha256"] != binary_sha:
        version = node_version(node)
        release_url, checksums_url = urls(version, target)
        filename = release_url.rsplit("/", 1)[-1]
        hashes = []
        for line in fetch(checksums_url, 256 * 1024).decode("ascii").splitlines():
            fields = line.split()
            if (
                len(fields) == 2
                and fields[1] == filename
                and re.fullmatch(r"[0-9a-f]{64}", fields[0])
            ):
                hashes.append(fields[0])
        if len(hashes) != 1:
            raise ValueError("missing or ambiguous Node release checksum")
        archive = fetch(release_url, MAX_ARCHIVE)
        if hashlib.sha256(archive).hexdigest() != hashes[0]:
            raise ValueError("Node release archive checksum mismatch")
        upstream_sha, notice = release_evidence(archive, version, target)
        if upstream_sha != binary_sha:
            raise ValueError("bundled Node differs from the official release binary")
        receipt = {
            **receipt,
            "version": version,
            "platform": target,
            "binary_sha256": binary_sha,
            "notice_sha256": hashlib.sha256(notice).hexdigest(),
            "source_archive_url": release_url,
            "source_archive_sha256": hashes[0],
            "checksums_url": checksums_url,
        }
        status = "refreshed"
    if regular_file(node, MAX_BINARY, digest_only=True) != binary_sha:
        raise ValueError("bundled Node changed before notice installation")
    destination = node.with_name("LICENSE." + node.name)
    if destination.is_symlink():
        raise ValueError("symlink at Node notice destination")
    if destination.exists() and regular_file(destination, MAX_TEXT) not in {
        notice,
        cached_notice,
    }:
        raise ValueError("conflicting installed Node notice")
    atomic_write(destination, notice)
    if status == "refreshed":
        atomic_write(evidence / "LICENSE", notice)
        atomic_write(
            evidence / "provenance.json",
            (json.dumps(receipt, indent=2) + "\n").encode(),
        )
    return status


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node", type=Path)
    parser.add_argument("--evidence", required=True, type=Path)
    args = parser.parse_args()
    node = args.node
    try:
        if node is None:
            distribution = importlib.metadata.distribution("playwright")
            node = distribution.locate_file("playwright/driver/node")
        status = refresh(node, args.evidence)
    except (
        OSError,
        ValueError,
        tarfile.TarError,
        lzma.LZMAError,
        importlib.metadata.PackageNotFoundError,
    ) as exc:
        parser.exit(1, "Node notice restoration failed: " + str(exc) + "\n")
    print(
        "Bundled Node notices "
        + status
        + ": "
        + str(node.with_name("LICENSE." + node.name))
    )


if __name__ == "__main__":
    main()

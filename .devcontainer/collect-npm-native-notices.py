#!/usr/bin/env python3
"""Verify installed native npm payloads against integrity-checked publisher archives."""
from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import urllib.error
import urllib.parse
import urllib.request

MAX_METADATA = 512 * 1024
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
NOTICE = re.compile(r"(?:licen[cs]e|copying|notice)(?:[._-].*)?\Z", re.I)


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate package metadata field")
        result[key] = value
    return result


def read_metadata(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_METADATA:
            raise ValueError("package metadata is not a bounded regular file")
        data = stream.read(MAX_METADATA + 1)
    if len(data) != info.st_size:
        raise ValueError("package metadata changed or exceeded byte budget")
    result = json.loads(data, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("package metadata must be an object")
    return result


def metadata(url):
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read(MAX_METADATA + 1)
    if len(data) > MAX_METADATA:
        raise ValueError("registry metadata exceeds byte budget")
    result = json.loads(data, object_pairs_hook=unique)
    if not isinstance(result, dict):
        raise ValueError("registry metadata must be an object")
    return result


class HashedSource:
    def __init__(self, source):
        self.source = source
        self.sha512 = hashlib.sha512()
        self.sha256 = hashlib.sha256()
        self.size = 0

    def read(self, size):
        if size < 0:
            raise ValueError("unbounded archive read refused")
        data = self.source.read(min(size, 1024 * 1024))
        self.size += len(data)
        if self.size > MAX_ARCHIVE:
            raise ValueError("native npm archive exceeds byte budget")
        self.sha512.update(data)
        self.sha256.update(data)
        return data


def release(source, integrity):
    match = re.fullmatch(r"sha512-([A-Za-z0-9+/]+={0,2})", integrity)
    if not match:
        raise ValueError("native npm release requires SHA-512 integrity")
    expected = base64.b64decode(match[1], validate=True)
    if len(expected) != 64:
        raise ValueError("invalid native npm SHA-512 digest")
    hashed = HashedSource(source)
    files, notices, package = {}, {}, None
    total = 0
    with tarfile.open(fileobj=hashed, mode="r|gz") as archive:
        seen = set()
        for count, member in enumerate(archive):
            if count >= 10000 or len(member.name) > 1024:
                raise ValueError("native npm archive exceeds entry budget")
            path = PurePosixPath(member.name)
            if (path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "package"
                    or member.name in seen or member.issym() or member.islnk()):
                raise ValueError("ambiguous native npm archive path")
            seen.add(member.name)
            if member.isdir():
                continue
            if not member.isfile():
                raise ValueError("unsupported native npm archive member")
            total += member.size
            if total > MAX_EXPANDED:
                raise ValueError("native npm archive exceeds expansion budget")
            keep = member.name == "package/package.json" or bool(NOTICE.fullmatch(path.name))
            if keep and member.size > MAX_METADATA:
                raise ValueError("native npm notice exceeds byte budget")
            digest = hashlib.sha256()
            body = bytearray()
            header = b""
            size = 0
            with archive.extractfile(member) as stream:
                while block := stream.read(1024 * 1024):
                    if not header:
                        header = block[:4]
                    size += len(block)
                    if size > member.size:
                        raise ValueError("native npm archive size mismatch")
                    digest.update(block)
                    if keep:
                        body.extend(block)
            if size != member.size:
                raise ValueError("truncated native npm archive member")
            relative = str(PurePosixPath(*path.parts[1:]))
            files[relative] = {"sha256": digest.hexdigest(), "size": size, "elf": header == b"\x7fELF"}
            if member.name == "package/package.json":
                package = json.loads(body, object_pairs_hook=unique)
            elif keep:
                text = bytes(body)
                text.decode("utf-8")
                if not text.strip() or b"\x00" in text:
                    raise ValueError("invalid native npm notice text")
                notices[relative] = text
    # The gzip/tar readers may stop before HTTP EOF. Verify all compressed
    # bytes, including any prefetched or trailing bytes, before returning.
    while hashed.read(1024 * 1024):
        pass
    if hashed.sha512.digest() != expected:
        raise ValueError("native npm release integrity mismatch")
    if not isinstance(package, dict) or not notices:
        raise ValueError("native npm release lacks identity or notices")
    return files, notices, package, hashed.sha256.hexdigest()


def file_sha256(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_EXPANDED:
            raise ValueError("native npm payload is not a bounded regular file")
        digest = hashlib.sha256()
        size = 0
        while data := stream.read(1024 * 1024):
            size += len(data)
            if size > MAX_EXPANDED:
                raise ValueError("native npm payload exceeds byte budget")
            digest.update(data)
    if size != info.st_size:
        raise ValueError("native npm payload changed while hashing")
    return digest.hexdigest()


def collect(root, output):
    record = {"name": root.name, "status": "unavailable", "files": [],
              "limitations": ["Publisher archive integrity and installed bytes are checked; exact build-source correspondence is separate."]}
    contents = {}
    try:
        installed = read_metadata(root / "package.json")
        name, version = installed["name"], installed["version"]
        if (not isinstance(name, str) or not re.fullmatch(r"@[a-z0-9_.-]+/[a-z0-9_.-]+", name)
                or not isinstance(version, str) or not re.fullmatch(r"[0-9][A-Za-z0-9.+_-]*", version)):
            raise ValueError("invalid native npm package identity")
        record.update(name=name, version=version)
        url = "https://registry.npmjs.org/" + urllib.parse.quote(name, safe="@") + "/" + version
        upstream = metadata(url)
        if (upstream.get("name"), upstream.get("version"), upstream.get("license")) != (name, version, installed.get("license")):
            raise ValueError("native npm registry identity or license differs from installation")
        tarball = upstream["dist"]["tarball"]
        parsed = urllib.parse.urlsplit(tarball)
        if parsed.scheme != "https" or parsed.netloc != "registry.npmjs.org" or parsed.query or parsed.fragment:
            raise ValueError("native npm tarball must come from the npm registry")
        with urllib.request.urlopen(tarball, timeout=45) as response:
            files, notices, archived, archive_sha = release(response, upstream["dist"]["integrity"])
        if (archived.get("name"), archived.get("version"), archived.get("license")) != (name, version, installed.get("license")):
            raise ValueError("native npm archive identity differs from installation")
        native = [path for path, item in files.items() if item["elf"]]
        if len(native) != 1:
            raise ValueError("native npm release requires exactly one ELF payload")
        relative = native[0]
        binary = root / relative
        actual = file_sha256(binary)
        if actual != files[relative]["sha256"]:
            raise ValueError("installed native npm binary differs from integrity-checked release")
        record.update(binary=str(binary), binary_sha256=actual, source_url=tarball,
                      release_integrity=upstream["dist"]["integrity"], source_archive_sha256=archive_sha,
                      release_member="package/" + relative)
        for path, text in notices.items():
            sha = hashlib.sha256(text).hexdigest()
            filename = "LICENSE-" + sha + ".txt"
            contents[filename] = text
            record["files"].append({"file": filename, "sha256": sha, "source_member": "package/" + path})
        registry = json.dumps(upstream, sort_keys=True, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
        sha = hashlib.sha256(registry).hexdigest()
        filename = "NOTICE-REGISTRY-METADATA-" + sha + ".json"
        contents[filename] = registry
        record["files"].append({"file": filename, "sha256": sha, "content_kind": "registry_metadata"})
        record["status"] = "release_notice_candidates_captured"
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, EOFError, RecursionError, tarfile.TarError, urllib.error.URLError, http.client.HTTPException) as exc:
        contents = {}
        record["files"] = []
        record["error"] = type(exc).__name__ + ": " + str(exc)[:500]
        print("Native npm evidence unavailable; inspect /usr/share/doc/raptor-native-notices.")
    destination = output / root.name
    destination.mkdir(parents=True, exist_ok=True)
    for pattern in ("LICENSE-*.txt", "NOTICE-REGISTRY-METADATA-*.json"):
        for old in destination.glob(pattern):
            old.unlink()
    for name, data in contents.items():
        (destination / name).write_bytes(data)
    (destination / "NOTICE-PROVENANCE.json").write_text(json.dumps(record, indent=2, ensure_ascii=True) + "\n")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, default=Path("/usr/lib/node_modules/@anthropic-ai/claude-code"))
    parser.add_argument("--output", type=Path, default=Path("/usr/share/doc/raptor-native-notices"))
    args = parser.parse_args()
    roots = sorted((args.package_root / "node_modules/@anthropic-ai").glob("claude-code-linux-*/package.json"))
    if not roots:
        print("Native npm package layout unavailable; executable ownership remains unresolved.")
    for package in roots:
        collect(package.parent, args.output)


if __name__ == "__main__":
    main()

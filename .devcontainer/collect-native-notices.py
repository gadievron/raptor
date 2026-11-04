#!/usr/bin/env python3
"""Retain release notice candidates for native tools omitted by package cataloguers."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.error
import urllib.request

MAX_ARCHIVE = 32 * 1024 * 1024
MAX_SOURCE_SBOM = 4 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_TOTAL = 8 * 1024 * 1024
NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|authors)(?:[._-].*)?\Z", re.I)


def download(url, *, max_bytes=MAX_ARCHIVE):
    with urllib.request.urlopen(url, timeout=45) as response:
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("release archive exceeds byte budget")
    return data


def release_notices(data):
    """Inspect bounded regular files without extracting upstream paths."""
    records = []
    contents = {}
    seen = set()
    total = 0
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
        for index, member in enumerate(archive):
            if index >= 100000:
                raise ValueError("release archive exceeds entry budget")
            expanded += member.size
            if expanded > 256 * 1024 * 1024:
                raise ValueError("release archive exceeds expansion budget")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.name in seen:
                raise ValueError("ambiguous release archive path")
            seen.add(member.name)
            if not NOTICE.fullmatch(path.name):
                continue
            if not member.isfile() or member.size > MAX_TEXT:
                raise ValueError("release notice is not a bounded regular file")
            total += member.size
            if total > MAX_TOTAL:
                raise ValueError("release notices exceed byte budget")
            with archive.extractfile(member) as stream:
                text = stream.read(MAX_TEXT + 1)
            if len(text) != member.size or not text.strip() or b"\x00" in text:
                raise ValueError("invalid release notice text")
            text.decode("utf-8")
            digest = hashlib.sha256(text).hexdigest()
            filename = "LICENSE-" + digest + ".txt"
            contents[filename] = text
            records.append({"source_member": member.name, "file": filename, "sha256": digest})
    if not records:
        raise ValueError("release has no notice candidates")
    return records, contents


def identify(binary, args, pattern):
    result = subprocess.run([str(binary), *args], capture_output=True, text=True,
                            timeout=15, check=True)
    match = re.fullmatch(pattern, result.stdout.strip())
    if not match:
        raise ValueError("unrecognised installed tool version")
    return match[1]


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate source SBOM field")
        result[key] = value
    return result


def verify_python_source(sbom, version, archive_url, archive_sha):
    """Bind notices to the exact release archive described by python.org."""
    document = json.loads(sbom, object_pairs_hook=_unique)
    if not isinstance(document, dict) or document.get("spdxVersion") != "SPDX-2.3":
        raise ValueError("unsupported Python source SBOM")
    packages = document.get("packages")
    if not isinstance(packages, list) or any(not isinstance(row, dict) for row in packages):
        raise ValueError("invalid Python source package inventory")
    matches = [row for row in packages if row.get("name") == "CPython"]
    if len(matches) != 1:
        raise ValueError("ambiguous Python source identity")
    package = matches[0]
    checksums = package.get("checksums", [])
    if not isinstance(checksums, list) or any(
            not isinstance(row, dict) or not isinstance(row.get("algorithm"), str)
            or not isinstance(row.get("checksumValue"), str) for row in checksums):
        raise ValueError("invalid Python source checksums")
    described = document.get("documentDescribes", [])
    if not isinstance(described, list) or any(not isinstance(value, str) for value in described):
        raise ValueError("invalid Python source document identity")
    described = set(described)
    relationships = document.get("relationships", [])
    if not isinstance(relationships, list) or any(not isinstance(row, dict) for row in relationships):
        raise ValueError("invalid Python source relationships")
    for row in relationships:
        if (row.get("relationshipType") == "DESCRIBES"
                and row.get("spdxElementId") == document.get("SPDXID", "SPDXRef-DOCUMENT")):
            target = row.get("relatedSpdxElement")
            if not isinstance(target, str):
                raise ValueError("invalid Python source relationship target")
            described.add(target)
    sha256 = {row.get("checksumValue") for row in checksums if row.get("algorithm") == "SHA256"}
    if (package.get("versionInfo") != version or package.get("downloadLocation") != archive_url
            or package.get("SPDXID") not in described
            or sha256 != {archive_sha}):
        raise ValueError("Python source SBOM does not match the selected release archive")


def collect(name, binary, args, pattern, repository, tag_prefix, output, *, python_source=False):
    record = {"name": name, "binary": str(binary), "status": "unavailable", "files": [],
              "limitations": ["Release notice candidates do not prove exact build-source correspondence.",
                              "Statically linked and bundled dependency completeness is not established."]}
    contents = {}
    try:
        if not binary.is_file():
            raise ValueError("expected native tool is absent")
        with binary.open("rb") as stream:
            record["binary_sha256"] = hashlib.file_digest(stream, "sha256").hexdigest()
        version = identify(binary, args, pattern)
        record["version"] = version
        url = (f"https://www.python.org/ftp/python/{version}/Python-{version}.tgz" if python_source else
               f"https://codeload.github.com/{repository}/tar.gz/refs/tags/{tag_prefix}{version}")
        record["source_url"] = url
        archive = download(url)
        record["source_archive_sha256"] = hashlib.sha256(archive).hexdigest()
        sbom = None
        if python_source:
            record["source_sbom_url"] = url + ".spdx.json"
            sbom = download(record["source_sbom_url"], max_bytes=MAX_SOURCE_SBOM)
            verify_python_source(sbom, version, url, record["source_archive_sha256"])
        record["files"], contents = release_notices(archive)
        if sbom is not None:
            sha = hashlib.sha256(sbom).hexdigest()
            filename = "NOTICE-SOURCE-SBOM-" + sha + ".json"
            record["source_sbom_sha256"] = sha
            record["files"].append({"file": filename, "sha256": sha,
                                    "source_url": record["source_sbom_url"], "content_kind": "source_sbom"})
            contents[filename] = sbom
        record["status"] = "release_notice_candidates_captured"
    except (OSError, ValueError, UnicodeError, RecursionError, tarfile.TarError, EOFError,
            subprocess.SubprocessError, urllib.error.URLError) as exc:
        record["error"] = type(exc).__name__ + ": " + str(exc)[:500]
        print("Native notice collection warning; inspect /usr/share/doc/raptor-native-notices.")
    destination = output / name
    destination.mkdir(parents=True, exist_ok=True)
    # This directory belongs only to this collector. Never leave old texts
    # looking current after a version change or failed retrieval.
    for pattern in ("LICENSE-*.txt", "NOTICE-SOURCE-SBOM-*.json"):
        for old in destination.glob(pattern):
            old.unlink()
    for filename, text in contents.items():
        (destination / filename).write_bytes(text)
    (destination / "NOTICE-PROVENANCE.json").write_text(
        json.dumps(record, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return record


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("/usr/share/doc/raptor-native-notices"))
    args = parser.parse_args()
    collect("uv", Path("/usr/local/bin/uv"), ["--version"],
            r"uv ([0-9]+\.[0-9]+\.[0-9]+)(?: \([^\r\n]*\))?", "astral-sh/uv", "", args.output)
    collect("git", Path("/usr/local/bin/git"), ["--version"],
            r"git version ([0-9]+\.[0-9]+\.[0-9]+)", "git/git", "v", args.output)
    collect("subversion", Path("/usr/bin/svn"), ["--version", "--quiet"],
            r"([0-9]+\.[0-9]+\.[0-9]+)", "apache/subversion", "", args.output)
    collect("cpython", Path("/usr/local/bin/python3"), ["--version"],
            r"Python ([0-9]+\.[0-9]+\.[0-9]+)", "python/cpython", "v", args.output,
            python_source=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Retain release notice candidates for native tools omitted by package cataloguers."""
from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import tarfile
import urllib.error
import urllib.request

MAX_ARCHIVE = 64 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_SOURCE_SBOM = 4 * 1024 * 1024
MAX_TEXT = 512 * 1024
MAX_TOTAL = 8 * 1024 * 1024
NOTICE = re.compile(r"(?:licen[cs]e|copying|copyright|notice|authors)(?:[._-].*)?\Z", re.I)


def download(url, *, max_bytes=MAX_ARCHIVE):
    with urllib.request.urlopen(url, timeout=45) as response:
        if not response.geturl().startswith("https://"):
            raise ValueError("release evidence redirect must remain HTTPS")
        data = response.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError("release archive exceeds byte budget")
    return data



def python_notice_sources(sbom, version):
    """Use the release SBOM's ownership and SHA-256, never a version path guess."""
    document = json.loads(sbom, object_pairs_hook=_unique)
    packages = {row["SPDXID"]: row for row in document["packages"] if row["name"] != "CPython"}
    if len(packages) != sum(row["name"] != "CPython" for row in document["packages"]):
        raise ValueError("duplicate third-party source package identity")
    files = {row["SPDXID"]: row for row in document.get("files", [])}
    if len(files) != len(document.get("files", [])):
        raise ValueError("duplicate Python source file identity")
    owners = {}
    for relation in document.get("relationships", []):
        owner, target = relation.get("spdxElementId"), relation.get("relatedSpdxElement")
        if relation.get("relationshipType") == "CONTAINS" and owner in packages and target in files:
            owners.setdefault(target, set()).add(owner)
    selected = {}
    used_packages = set()
    for identifier, owner_ids in owners.items():
        file = files[identifier]
        name = file["fileName"]
        path = PurePosixPath(name)
        if path.is_absolute() or ".." in path.parts or str(path) != name:
            raise ValueError("unsafe Python SBOM source path")
        if path.suffix.lower() not in {".c", ".h", ".cc", ".cpp", ".hpp", ".py", ".s", ".asm"}:
            continue
        hashes = [row["checksumValue"] for row in file.get("checksums", []) if row.get("algorithm") == "SHA256"]
        if len(hashes) != 1 or not re.fullmatch(r"[a-f0-9]{64}", hashes[0]):
            raise ValueError("third-party source file has no unique SHA-256")
        key = f"Python-{version}/" + name
        if key in selected:
            raise ValueError("duplicate Python SBOM source path")
        selected[key] = {"sha256": hashes[0], "packages": sorted(owner_ids)}
        used_packages.update(owner_ids)
    return selected, [packages[key] for key in sorted(used_packages)]


def source_header(raw, python=False):
    """Retain exact leading comments/docstrings containing notice language."""
    position = 3 if raw.startswith(b"\xef\xbb\xbf") else 0
    end = 0
    while position < len(raw):
        while position < len(raw) and raw[position] in b" \t\r\n":
            position += 1
        if raw.startswith(b"/*", position):
            stop = raw.find(b"*/", position + 2)
            if stop < 0:
                raise ValueError("source comment exceeds header budget")
            position = stop + 2
        elif raw.startswith(b"//", position) or (python and raw.startswith(b"#", position)):
            stop = raw.find(b"\n", position)
            position = len(raw) if stop < 0 else stop + 1
        elif python and raw[position:position + 3] in (b'"""', b"'''"):
            delimiter = raw[position:position + 3]
            stop = raw.find(delimiter, position + 3)
            if stop < 0:
                raise ValueError("source docstring exceeds header budget")
            position = stop + 3
        else:
            break
        end = position
    header = raw[:end]
    if not re.search(rb"copyright|licen[cs]e|permission is hereby|redistribution and use", header, re.I):
        return None
    if b"\x00" in header:
        raise ValueError("invalid source notice header")
    header.decode("utf-8")
    return header


def upstream_commit_notices(packages):
    """Retain publisher-authored root texts for SBOM-pinned GitHub commits."""
    records, contents, seen = [], {}, set()
    for package in packages:
        match = re.fullmatch(r"https://github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/archive/([a-f0-9]{40})\.(?:zip|tar\.gz)", package.get("downloadLocation", ""))
        if not match or match.groups() in seen:
            continue
        repository, revision = match.groups()
        seen.add(match.groups())
        listing = json.loads(download(f"https://api.github.com/repos/{repository}/contents?ref={revision}", max_bytes=MAX_SOURCE_SBOM), object_pairs_hook=_unique)
        if not isinstance(listing, list) or len(listing) > 1000:
            raise ValueError("invalid upstream root notice inventory")
        for item in listing:
            if not isinstance(item, dict):
                raise ValueError("invalid upstream root notice entry")
            name = item.get("name", "")
            if item.get("type") != "file" or not NOTICE.fullmatch(name):
                continue
            if PurePosixPath(name).name != name or not re.fullmatch(r"[a-f0-9]{40}", item.get("sha", "")):
                raise ValueError("invalid upstream notice identity")
            url = f"https://raw.githubusercontent.com/{repository}/{revision}/{name}"
            text = download(url, max_bytes=MAX_TEXT)
            git_blob = b"blob " + str(len(text)).encode() + b"\x00" + text
            if hashlib.sha1(git_blob, usedforsecurity=False).hexdigest() != item["sha"] or not text.strip() or b"\x00" in text:
                raise ValueError("upstream notice content differs from pinned Git blob")
            text.decode("utf-8")
            digest = hashlib.sha256(text).hexdigest()
            filename = "LICENSE-" + digest + ".txt"
            contents[filename] = text
            records.append({"file": filename, "sha256": digest, "source_url": url,
                            "upstream_revision": revision, "source_package": package["SPDXID"],
                            "git_blob_sha1": item["sha"]})
    return records, contents


def release_notices(data, definitions=(), source_members=None):
    """Inspect bounded regular files without extracting upstream paths."""
    records = []
    contents = {}
    seen = set()
    total = 0
    expanded = 0
    source_members = source_members or {}
    seen_sources = set()
    with tarfile.open(fileobj=io.BytesIO(data), mode="r|gz") as archive:
        for index, member in enumerate(archive):
            if index >= 100000:
                raise ValueError("release archive exceeds entry budget")
            expanded += member.size
            if expanded > MAX_EXPANDED:
                raise ValueError("release archive exceeds expansion budget")
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or member.name in seen:
                raise ValueError("ambiguous release archive path")
            seen.add(member.name)
            declaration = len(path.parts) == 2 and path.parts[1] in definitions
            source = source_members.get(member.name)
            if source is not None:
                if not member.isfile() or member.size > 8 * 1024 * 1024:
                    raise ValueError("third-party source is not a bounded regular file")
                with archive.extractfile(member) as stream:
                    head = stream.read(min(member.size, 64 * 1024))
                    hasher = hashlib.sha256(head)
                    while chunk := stream.read(128 * 1024):
                        hasher.update(chunk)
                if hasher.hexdigest() != source["sha256"]:
                    raise ValueError("third-party source differs from release SBOM")
                seen_sources.add(member.name)
                text = source_header(head, path.suffix == ".py")
                if text is None:
                    continue
                total += len(text)
                if total > MAX_TOTAL:
                    raise ValueError("release notices exceed byte budget")
                digest = hashlib.sha256(text).hexdigest()
                filename = "LICENSE-" + digest + ".txt"
                contents[filename] = text
                records.append({"source_member": member.name, "source_sha256": source["sha256"],
                                "source_packages": source["packages"], "file": filename,
                                "sha256": digest, "notice_origin": "source_header"})
                continue
            if not NOTICE.fullmatch(path.name) and not declaration:
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
            filename = ("NOTICE-BUILD-DECLARATION-" if declaration else "LICENSE-") + digest + ".txt"
            contents[filename] = text
            record = {"source_member": member.name, "file": filename, "sha256": digest}
            if declaration:
                record["content_kind"] = "build_declaration"
            records.append(record)
    if seen_sources != set(source_members):
        raise ValueError("release archive omits declared third-party source files")
    if not any(row.get("content_kind") != "build_declaration" for row in records):
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


def collect(name, binary, args, pattern, repository, tag_prefix, output, *, python_source=False, build_inventory=False, cargo_dependencies=False):
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
        definitions = (("Cargo.lock",) if cargo_dependencies else ("Makefile",) if name == "git"
                       else ("build.conf",) if name == "subversion" else ())
        members, dependencies = python_notice_sources(sbom, version) if sbom is not None else ({}, [])
        record["files"], contents = release_notices(archive, definitions if build_inventory or cargo_dependencies else (), members)
        extra_records, extra_contents = upstream_commit_notices(dependencies)
        record["files"].extend(extra_records)
        contents.update(extra_contents)
        if sum(len(text) for text in contents.values()) > MAX_TOTAL:
            raise ValueError("release notices exceed byte budget")
        if cargo_dependencies:
            from cargo_notice_inventory import collect_cargo_notices
            lock = next(contents[row["file"]] for row in record["files"]
                        if row.get("content_kind") == "build_declaration" and PurePosixPath(row["source_member"]).name == "Cargo.lock")
            cargo = collect_cargo_notices(lock, download, source_header)
            record["dependency_notices"] = cargo.summary
            record["files"].extend(cargo.records)
            contents.update(cargo.contents)
            sha = hashlib.sha256(cargo.inventory).hexdigest()
            filename = "NOTICE-SOURCE-SBOM-" + sha + ".json"
            record["files"].append({"file": filename, "sha256": sha, "content_kind": "source_sbom",
                                    "scope": "Cargo.lock source candidates, not installed components"})
            contents[filename] = cargo.inventory
            if sum(len(text) for name, text in contents.items() if name.startswith("LICENSE-")) > MAX_TOTAL:
                raise ValueError("release notices exceed byte budget")
        if sbom is not None:
            sha = hashlib.sha256(sbom).hexdigest()
            filename = "NOTICE-SOURCE-SBOM-" + sha + ".json"
            record["source_sbom_sha256"] = sha
            record["files"].append({"file": filename, "sha256": sha,
                                    "source_url": record["source_sbom_url"], "content_kind": "source_sbom"})
            contents[filename] = sbom
        if build_inventory:
            try:
                from native_build_inventory import collect_build_inventory
                sources = {PurePosixPath(row["source_member"]).name: contents[row["file"]].decode("utf-8")
                           for row in record["files"] if row.get("content_kind") == "build_declaration"}
                inventory = collect_build_inventory(name, binary, version, sources)
                source_hashes = [row["sha256"] for row in record["files"] if row.get("content_kind") == "build_declaration"]
                for claim in inventory.claims:
                    claim["source_definition_sha256"] = source_hashes
                record["declared_files"] = inventory.claims
                record["inventory_gaps"] = inventory.gaps
                record["files"].extend(inventory.records)
                contents.update(inventory.contents)
            except (OSError, ValueError, KeyError, TypeError, UnicodeError, subprocess.SubprocessError) as exc:
                record["declared_files"] = []
                record["inventory_gaps"] = [type(exc).__name__ + ": " + str(exc)[:500]]
        record["status"] = "release_notice_candidates_captured"
    except (OSError, ValueError, KeyError, TypeError, UnicodeError, RecursionError, tarfile.TarError, EOFError,
            subprocess.SubprocessError, urllib.error.URLError, http.client.HTTPException, StopIteration) as exc:
        record["error"] = type(exc).__name__ + ": " + str(exc)[:500]
        print("Native notice collection warning; inspect /usr/share/doc/raptor-native-notices.")
    destination = output / name
    destination.mkdir(parents=True, exist_ok=True)
    # This directory belongs only to this collector. Never leave old texts
    # looking current after a version change or failed retrieval.
    for pattern in ("LICENSE-*.txt", "NOTICE-SOURCE-SBOM-*.json", "NOTICE-BUILD-DECLARATION-*.txt", "NOTICE-INSTALLED-METADATA-*.txt"):
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
            r"uv ([0-9]+\.[0-9]+\.[0-9]+)(?: \([^\r\n]*\))?", "astral-sh/uv", "", args.output, cargo_dependencies=True)
    collect("git", Path("/usr/local/bin/git"), ["--version"],
            r"git version ([0-9]+\.[0-9]+\.[0-9]+)", "git/git", "v", args.output, build_inventory=True)
    collect("subversion", Path("/usr/bin/svn"), ["--version", "--quiet"],
            r"([0-9]+\.[0-9]+\.[0-9]+)", "apache/subversion", "", args.output, build_inventory=True)
    collect("cpython", Path("/usr/local/bin/python3"), ["--version"],
            r"Python ([0-9]+\.[0-9]+\.[0-9]+)", "python/cpython", "v", args.output,
            python_source=True, build_inventory=True)


if __name__ == "__main__":
    main()

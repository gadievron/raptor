#!/usr/bin/env python3
"""Refresh reviewed npm, pnpm and Corepack notices after installation.

Example: python .devcontainer/refresh-npm-notices.py --package-root /usr/lib/node_modules/pnpm --evidence .devcontainer/pnpm-notices
Reads package files and upstream archives without executing package code.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import tarfile
from urllib.parse import quote, urlparse
from urllib.request import urlopen


SPEC = importlib.util.spec_from_file_location("install_npm_notices", Path(__file__).with_name("install-npm-notices.py"))
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
regular_path = INSTALLER.regular_path
MAX_DOWNLOAD = 96 * 1024 * 1024
MAX_TEXT = 1024 * 1024


def fetch(url):
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in {"registry.npmjs.org", "raw.githubusercontent.com"}:
        raise ValueError("unsupported upstream URL")
    with urlopen(url, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("upstream response exceeds size limit")
    return data


def read_metadata(path):
    with path.open("rb") as stream:
        data = stream.read(MAX_TEXT + 1)
    if len(data) > MAX_TEXT:
        raise ValueError("package metadata exceeds size limit")
    return json.loads(data)


def metadata_identity(metadata):
    return tuple(metadata.get(key) for key in ("name", "version", "license"))


class LimitedSource:
    def __init__(self, data):
        self.stream = gzip.GzipFile(fileobj=io.BytesIO(data))
        self.total = 0

    def read(self, size):
        data = self.stream.read(min(size, 256 * 1024 * 1024 - self.total + 1))
        self.total += len(data)
        if self.total > 256 * 1024 * 1024:
            raise ValueError("expanded release exceeds size limit")
        return data


def release_files(data):
    files = {}
    total = 0
    with tarfile.open(fileobj=LimitedSource(data), mode="r|") as archive:
        for number, member in enumerate(archive):
            if number >= 50000:
                raise ValueError("release contains too many entries")
            parts = Path(member.name).parts
            if not parts or parts[0] != "package" or ".." in parts or member.name.startswith("/"):
                raise ValueError("unsafe release path")
            if member.isdir():
                continue
            if (not member.isfile() or member.name in files or member.name != Path(member.name).as_posix()
                    or member.size > 64 * 1024 * 1024):
                raise ValueError("unsafe or ambiguous release member")
            total += member.size
            if total > 128 * 1024 * 1024:
                raise ValueError("release payload exceeds size limit")
            files[member.name] = archive.extractfile(member).read(member.size + 1)
    return files


def checked_release(metadata):
    dist = metadata["dist"]
    if not isinstance(dist.get("integrity"), str):
        raise ValueError("release has no supported integrity digest")
    integrity = dist["integrity"].split()
    supported = []
    for token in integrity:
        algorithm, separator, encoded = token.partition("-")
        if separator and algorithm in {"sha512", "sha384", "sha256"}:
            supported.append((algorithm, base64.b64decode(encoded, validate=True)))
    if not supported:
        raise ValueError("release has no supported integrity digest")
    data = fetch(dist["tarball"])
    strongest = max(supported, key=lambda value: hashlib.new(value[0]).digest_size)[0]
    if not any(hashlib.new(algorithm, data).digest() == expected for algorithm, expected in supported if algorithm == strongest):
        raise ValueError("release integrity mismatch")
    return data, release_files(data)


def verify_payload(package, files, entry):
    count = 0
    for parent, directories, filenames in os.walk(package, followlinks=False):
        directories[:] = [name for name in directories if name != "node_modules"]
        for name in directories:
            if (Path(parent) / name).is_symlink():
                raise ValueError("symlink in installed payload")
        for name in filenames:
            path = Path(parent) / name
            relative = path.relative_to(package).as_posix()
            if relative == entry.get("installed_filename"):
                continue
            path = regular_path(package, relative)
            if not path.is_file() or path.stat().st_size > 64 * 1024 * 1024:
                raise ValueError("unsafe installed payload")
            source = files.get("package/" + relative)
            if source is None:
                raise ValueError("installed payload absent from release; review required")
            data = path.read_bytes()
            if relative == "package.json":
                # Installation may add registry bookkeeping fields; identity and
                # licence must still match. Other payload files match verbatim.
                if metadata_identity(json.loads(data)) != metadata_identity(json.loads(source)):
                    raise ValueError("installed and release package metadata disagree")
            elif data != source:
                raise ValueError("installed payload differs from release; review required")
            count += 1
    if not count:
        raise ValueError("no installed payload verified")
    return count


def licensing_section(data):
    headings = list(re.finditer(rb"(?m)^(#{1,6})[ \t]+([^\r\n]+)", data))
    for index, heading in enumerate(headings):
        if not re.search(rb"licen[cs]|copyright", heading[2], re.I):
            continue
        end = len(data)
        for following in headings[index + 1:]:
            if len(following[1]) <= len(heading[1]):
                end = following.start()
                break
        return b" ".join(data[heading.start():end].split())
    raise ValueError("README licensing section missing; review required")


def refresh_entry(entry, package, installed, previous_notice=None):
    if installed.get("license") != entry["license"]:
        raise ValueError("licence declaration changed; review required")
    version = installed["version"]
    url = "https://registry.npmjs.org/" + quote(entry["name"], safe="") + "/" + quote(version, safe="")
    metadata = json.loads(fetch(url))
    if metadata_identity(metadata) != metadata_identity(installed):
        raise ValueError("registry and installed package metadata disagree")
    raw, files = checked_release(metadata)
    archived = json.loads(files["package/package.json"])
    if metadata_identity(archived) != metadata_identity(installed):
        raise ValueError("archive and installed package metadata disagree")
    updated = dict(entry)
    updated.pop("absent", None)
    updated.update(version=version, registry_metadata_url=url, release_url=metadata["dist"]["tarball"],
                   release_integrity=metadata["dist"]["integrity"], release_sha256=hashlib.sha256(raw).hexdigest())
    if metadata.get("gitHead"):
        updated["source_commit"] = metadata["gitHead"]
    else:
        updated.pop("source_commit", None)
    if entry["status"] == "unresolved":
        # Do not turn known evidence gaps into an inferred licence grant.
        for key in ("notice_file", "sha256", "source_kind", "source_url", "source_path", "installed_filename", "verified_installed_files"):
            updated.pop(key, None)
        updated["scope"] = "Release identity and integrity refreshed; no applicable notice has been established."
        return updated, None
    if entry["source_kind"] not in {"pinned_upstream_repository", "integrity_checked_package_release"}:
        raise ValueError("unsupported notice recipe")
    verified = verify_payload(package, files, entry)
    if entry["source_kind"] == "pinned_upstream_repository":
        commit = metadata.get("gitHead", "")
        if not re.fullmatch(r"[0-9a-f]{40}", commit):
            raise ValueError("release lacks a pinned repository commit")
        source_url = entry["source_url"]
        parsed = urlparse(source_url)
        parts = parsed.path.strip("/").split("/")
        if parsed.hostname != "raw.githubusercontent.com" or len(parts) < 4 or parts[2] != entry["source_commit"]:
            raise ValueError("repository fallback needs a reviewed recipe")
        parts[2] = commit
        source_url = "https://raw.githubusercontent.com/" + "/".join(parts)
        notice = fetch(source_url)
        updated["source_url"] = source_url
    else:
        if entry["source_path"] not in files:
            raise ValueError("notice source layout changed; review required")
        notice = files[entry["source_path"]]
        updated["source_url"] = metadata["dist"]["tarball"]
    if not notice or len(notice) > MAX_TEXT:
        raise ValueError("missing or oversized notice")
    if Path(entry["source_path"]).name.lower().startswith("readme"):
        if previous_notice is None or licensing_section(previous_notice) != licensing_section(notice):
            raise ValueError("README licensing section changed; review required")
    updated["sha256"] = hashlib.sha256(notice).hexdigest()
    updated["verified_installed_files"] = verified
    updated["scope"] = "Installed payload files match the integrity-checked release; package.json identity and licence match. Notice evidence does not establish complete licence coverage."
    return updated, notice


def refresh(root, evidence, *, force=False, check=False):
    path = regular_path(evidence, "provenance.json")
    manifest = read_metadata(path)
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported evidence manifest")
    manager = manifest.get("package_manager") or {
        "name": "npm", "version": manifest["npm_version"], "dependency_directory": "node_modules",
    }
    installed_manager = read_metadata(regular_path(root, "package.json"))
    if installed_manager.get("name") != manager["name"]:
        raise ValueError("unexpected package manager")
    manager_changed = installed_manager.get("version") != manager["version"]
    pending = []
    refreshed = False
    if any(not entry.get("at_root") for entry in manifest["packages"]):
        if not regular_path(root, manager["dependency_directory"]).is_dir():
            raise ValueError("bundled dependency layout changed; review required")
    for index, entry in enumerate(manifest["packages"]):
        package = root if entry.get("at_root") is True else regular_path(regular_path(root, manager["dependency_directory"]), entry["name"])
        if not package.exists():
            entry["absent"] = True
            continue
        installed = read_metadata(regular_path(package, "package.json"))
        if installed.get("name") != entry["name"]:
            raise ValueError("unexpected bundled package identity")
        if installed.get("license") != entry["license"]:
            raise ValueError("licence declaration changed; review required")
        changed = manager_changed or installed.get("version") != entry["version"] or entry.get("absent")
        if force or changed:
            refreshed = True
            previous_notice = None
            if entry["status"] != "unresolved" and Path(entry["source_path"]).name.lower().startswith("readme"):
                previous_notice = regular_path(evidence, entry["notice_file"]).read_bytes()
                if len(previous_notice) > MAX_TEXT or hashlib.sha256(previous_notice).hexdigest() != entry["sha256"]:
                    raise ValueError("reviewed README checksum mismatch")
            updated, notice = refresh_entry(entry, package, installed, previous_notice)
            manifest["packages"][index] = updated
            if notice is not None:
                pending.append((regular_path(evidence, entry["notice_file"]), notice))
    manager["version"] = installed_manager["version"]
    if "package_manager" in manifest:
        manifest["package_manager"] = manager
    else:
        manifest["npm_version"] = manager["version"]
    if refreshed or manager_changed:
        manifest["scope"] = "Version-scoped upstream notice evidence. Release integrity is a publisher claim; per-package entries record payload checks. Unresolved entries remain gaps. Complete licence coverage is unverified."
    if len({target for target, _ in pending}) != len(pending):
        raise ValueError("duplicate notice evidence target")
    encoded = json.dumps(manifest, indent=2) + "\n"
    changed = encoded != path.read_text() or any(target.read_bytes() != data for target, data in pending)
    if check and changed:
        raise ValueError("notice evidence needs refreshing; rerun without --check")
    if not check:
        for target, data in pending:
            target.write_bytes(data)
        if changed:
            path.write_text(encoded)
    return changed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", type=Path, required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--force", action="store_true", help="also recheck unchanged versions against upstream")
    parser.add_argument("--check", action="store_true", help="verify without modifying evidence")
    args = parser.parse_args()
    try:
        changed = refresh(args.package_root, args.evidence, force=args.force, check=args.check)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError) as exc:
        parser.exit(1, f"npm notice refresh failed: {exc}\n")
    print("Notice evidence refreshed." if changed else "Notice evidence is current.")


if __name__ == "__main__":
    main()

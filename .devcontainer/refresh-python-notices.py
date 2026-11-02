#!/usr/bin/env python3
"""Refresh a retained Python notice for a version bump.

Example: python .devcontainer/refresh-python-notices.py --package semgrep --version 1.178.0
Run from a checkout, then review and commit the resulting notice/provenance diff.
Only reads release archives; never installs or executes package code.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import sysconfig
import tarfile
import tomllib
from urllib.parse import quote, urlparse
from urllib.request import urlopen
import zipfile


ROOT = Path(__file__).resolve().parent
MAX_DOWNLOAD = 96 * 1024 * 1024
MAX_TEXT = 1024 * 1024
OTEL_REPO = "open-telemetry/opentelemetry-python-contrib"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def fetch(url):
    if urlparse(url).scheme != "https" or urlparse(url).hostname not in {
        "pypi.org", "files.pythonhosted.org", "api.github.com", "raw.githubusercontent.com",
    }:
        raise ValueError("unsupported upstream URL")
    with urlopen(url, timeout=60) as response:
        data = response.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise ValueError("upstream response exceeds download limit")
    return data


def name_key(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def checked_download(distribution):
    data = fetch(distribution["url"])
    if digest(data) != distribution["digests"]["sha256"]:
        raise ValueError("release checksum mismatch")
    return data


class LimitedSource:
    def __init__(self, data):
        self.stream = gzip.GzipFile(fileobj=io.BytesIO(data))
        self.total = 0

    def read(self, size):
        remaining = 256 * 1024 * 1024 - self.total
        data = self.stream.read(min(size, remaining + 1))
        self.total += len(data)
        if self.total > 256 * 1024 * 1024:
            raise ValueError("expanded source archive exceeds size limit")
        return data


def tar_files(data, wanted):
    result = {}
    with tarfile.open(fileobj=LimitedSource(data), mode="r|") as archive:
        for number, member in enumerate(archive):
            if number >= 50000:
                raise ValueError("source archive has too many entries")
            if member.name not in wanted:
                continue
            if member.name in result or not member.isfile() or member.size > MAX_TEXT:
                raise ValueError("unsafe or ambiguous source archive member")
            result[member.name] = archive.extractfile(member).read(MAX_TEXT + 1)
    if set(result) != set(wanted):
        raise ValueError("source layout changed; review notice selection")
    return result


def identity(data):
    metadata = BytesParser().parsebytes(data)
    expression = metadata.get_all("License-Expression", [])
    legacy = metadata.get_all("License", [])
    if expression and legacy:
        raise ValueError("conflicting licence declarations")
    header = "License-Expression" if expression else "License"
    result = {}
    for field in ("Name", "Version", header):
        values = metadata.get_all(field, [])
        if len(values) != 1:
            raise ValueError("missing or ambiguous release metadata")
        result[field] = values[0].strip()
    return result, header


def wheel_metadata(distribution):
    data = checked_download(distribution)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        entries = [x for x in archive.infolist() if x.filename.endswith(".dist-info/METADATA")]
        if len(entries) != 1 or entries[0].file_size > MAX_TEXT:
            raise ValueError("ambiguous wheel metadata")
        member = entries[0]
        directory = Path(member.filename).parent.name
        if Path(member.filename).parent.parent != Path("."):
            raise ValueError("unexpected wheel metadata directory")
        return archive.read(member), directory


def repository_notice(entry, version, source, source_root):
    # The reviewed fallback is specific to this project, not inferred inheritance.
    if entry["name"] != "opentelemetry-util-http":
        raise ValueError("repository fallback needs an explicit reviewed recipe")
    tag = "v" + version
    base = "https://api.github.com/repos/" + OTEL_REPO
    ref = json.loads(fetch(base + "/git/ref/tags/" + quote(tag, safe="")))["object"]
    if ref["type"] == "tag":
        ref = json.loads(fetch(base + "/git/tags/" + ref["sha"]))["object"]
    if ref["type"] != "commit" or not re.fullmatch(r"[0-9a-f]{40}", ref["sha"]):
        raise ValueError("release tag does not resolve to a commit")
    commit = ref["sha"]
    raw = "https://raw.githubusercontent.com/" + OTEL_REPO + "/" + commit + "/"
    project_path = "util/opentelemetry-util-http/"
    project = fetch(raw + project_path + "pyproject.toml")
    if tomllib.loads(project.decode())["project"]["license"] != entry["license_spdx"]:
        raise ValueError("upstream project licence changed; review required")
    paths = ["src/opentelemetry/util/http/" + x for x in
             ("__init__.py", "httplib.py", "py.typed", "version.py")]
    archived = tar_files(source, {source_root + "/" + x for x in paths})
    for path in paths:
        if fetch(raw + project_path + path) != archived[source_root + "/" + path]:
            raise ValueError("release source differs from repository fallback")
    notice = fetch(raw + "LICENSE")
    return notice, {
        "source_kind": "pinned_upstream_repository", "source_url": raw + "LICENSE",
        "source_commit": commit, "source_tag": tag, "source_path": "LICENSE",
        "project_url": raw + project_path + "pyproject.toml", "project_sha256": digest(project),
    }


def refresh_entry(entry, version):
    url = "https://pypi.org/pypi/" + quote(entry["name"], safe="") + "/" + quote(version, safe="") + "/json"
    release = json.loads(fetch(url))
    sdists = [x for x in release["urls"] if x["packagetype"] == "sdist" and x["filename"].endswith(".tar.gz")]
    wheels = [x for x in release["urls"] if x["packagetype"] == "bdist_wheel"]
    if len(sdists) != 1 or not wheels:
        raise ValueError("release requires one source archive and a wheel")
    preferred = [x for x in wheels if x["filename"].endswith("none-any.whl")]
    if not preferred:
        preferred = [x for x in wheels if "manylinux" in x["filename"] and x["filename"].endswith("x86_64.whl")]
    if not preferred:
        raise ValueError("no supported wheel for metadata verification")
    wheel = min(preferred, key=lambda x: x["filename"])
    data, directory = wheel_metadata(wheel)
    values, header = identity(data)
    if name_key(values["Name"]) != name_key(entry["name"]) or values["Version"] != version:
        raise ValueError("release identity mismatch")
    if values[header] not in {entry["license"], entry["license_spdx"]}:
        raise ValueError("licence declaration changed; review required")
    source = checked_download(sdists[0]); source_root = sdists[0]["filename"][:-7]
    pkginfo = tar_files(source, {source_root + "/PKG-INFO"})[source_root + "/PKG-INFO"]
    source_values, source_header = identity(pkginfo)
    if (name_key(source_values["Name"]), source_values["Version"], source_values[source_header]) != (
        name_key(entry["name"]), version, values[header],
    ):
        raise ValueError("wheel and source metadata disagree")
    updated = dict(entry)
    if entry["source_kind"] == "pinned_upstream_repository":
        notice, provenance = repository_notice(entry, version, source, source_root)
        provenance.update(source_archive_url=sdists[0]["url"], source_archive_sha256=sdists[0]["digests"]["sha256"])
    else:
        relative = entry["source_path"].split("/", 1)[1]
        path = source_root + "/" + relative
        notice = tar_files(source, {path})[path]
        provenance = {"source_url": sdists[0]["url"], "source_sha256": sdists[0]["digests"]["sha256"], "source_path": path}
    if not notice or len(notice) > MAX_TEXT:
        raise ValueError("missing or oversized notice")
    updated.update(provenance)
    updated.update(version=version, license=values[header], license_header=header,
                   metadata_directory=directory, sha256=digest(notice), registry_metadata_url=url,
                   wheel_url=wheel["url"], wheel_sha256=wheel["digests"]["sha256"])
    return updated, notice


def plan_refresh(root, package, version):
    matches = []
    for path in root.glob("*-notices/provenance.json"):
        manifest = json.loads(path.read_text())
        if manifest.get("schema_version") != 1:
            continue
        for index, entry in enumerate(manifest.get("packages", [])):
            if "metadata_directory" in entry and name_key(entry["name"]) == name_key(package):
                matches.append((path, manifest, index, entry))
    if len(matches) != 1:
        raise ValueError("expected one reviewed Python notice recipe for this package")
    path, manifest, index, entry = matches[0]
    target = path.parent / entry["notice_file"]
    if target.parent != path.parent or target.is_symlink() or path.is_symlink():
        raise ValueError("unsafe evidence target")
    updated, notice = refresh_entry(entry, version)
    manifest["packages"][index] = updated
    encoded = json.dumps(manifest, indent=2) + "\n"
    changed = path.read_text() != encoded or target.read_bytes() != notice
    return path, target, encoded, notice, changed


def apply_plans(plans, check=False):
    if check and any(plan[4] for plan in plans):
        raise ValueError("notice evidence needs refreshing; rerun without --check")
    if not check:
        for path, target, encoded, notice, changed in plans:
            if changed:
                target.write_bytes(notice)
                path.write_text(encoded)
    return any(plan[4] for plan in plans)


def refresh(root, package, version, check=False):
    return apply_plans([plan_refresh(root, package, version)], check)


def installed_versions(root, site):
    recipes = {}
    for path in root.glob("*-notices/provenance.json"):
        for entry in json.loads(path.read_text()).get("packages", []):
            if "metadata_directory" in entry:
                recipes[name_key(entry["name"])] = entry["name"]
    found = {}
    for path in site.glob("*.dist-info/METADATA"):
        metadata = BytesParser().parsebytes(path.read_bytes())
        names = metadata.get_all("Name", [])
        if len(names) != 1 or name_key(names[0]) not in recipes:
            continue
        values, _ = identity(path.read_bytes())
        name = recipes[name_key(values["Name"])]
        if name in found:
            raise ValueError("ambiguous installed distribution")
        found[name] = values["Version"]
    return found


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package")
    parser.add_argument("--evidence-root", type=Path, default=ROOT, help="directory containing notice evidence directories")
    parser.add_argument("--if-version-changed", action="store_true", help="keep reviewed evidence for versions already current")
    parser.add_argument("--version")
    parser.add_argument("--site-packages", type=Path, help="refresh all reviewed notices present in this environment")
    parser.add_argument("--check", action="store_true", help="verify reproducibility without writing files")
    parser.add_argument("--installed-environment", action="store_true", help="use this interpreter's site-packages")
    args = parser.parse_args()
    if args.installed_environment:
        if args.site_packages:
            parser.error("choose --site-packages or --installed-environment")
        args.site_packages = Path(sysconfig.get_paths()["purelib"])
    if bool(args.package) != bool(args.version) or bool(args.package) == bool(args.site_packages):
        parser.error("supply --package and --version, or --site-packages")
    try:
        versions = installed_versions(args.evidence_root, args.site_packages) if args.site_packages else {args.package: args.version}
        plans = []
        for package, version in versions.items():
            if args.if_version_changed:
                current = [entry for path in args.evidence_root.glob("*-notices/provenance.json")
                           for entry in json.loads(path.read_text()).get("packages", [])
                           if "metadata_directory" in entry and name_key(entry["name"]) == name_key(package)]
                if len(current) == 1 and current[0]["version"] == version:
                    continue
            plans.append(plan_refresh(args.evidence_root, package, version))
        changed = apply_plans(plans, args.check)
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError, zipfile.BadZipFile) as exc:
        parser.exit(1, f"Notice refresh failed: {exc}\n")
    print("Notice evidence refreshed; review the diff." if changed else "Notice evidence is current.")


if __name__ == "__main__":
    main()

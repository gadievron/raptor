#!/usr/bin/env python3
"""Retain reviewed upstream notices beside installed Python metadata.

Run in the same container build step that installs the distributions, so the
metadata and added notices share an image layer. No package modules are imported.
"""
from __future__ import annotations

import argparse
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sysconfig


def regular_path(root: Path, relative: str) -> Path:
    parts = Path(relative).parts
    if not parts or Path(relative).is_absolute() or any(p in {".", ".."} for p in parts):
        raise ValueError("invalid evidence path")
    path = root
    for part in parts:
        path = path / part
        if path.is_symlink():
            raise ValueError("symlink in evidence path")
    return path


def read_regular(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("evidence must be a regular file")
        data = stream.read(1024 * 1024 + 1)
        if len(data) > 1024 * 1024:
            raise ValueError("evidence exceeds the size limit")
        return data


def canonical_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def install(site_packages: Path, evidence: Path) -> int:
    manifest = json.loads(read_regular(regular_path(evidence, "provenance.json")))
    if manifest.get("schema_version") != 1:
        raise ValueError("unsupported evidence manifest")
    pending = []
    targets = set()
    for entry in manifest["packages"]:
        directory = entry["metadata_directory"]
        if not directory.endswith(".dist-info"):
            raise ValueError("expected a dist-info metadata directory")
        package = regular_path(site_packages, directory)
        metadata = BytesParser().parsebytes(read_regular(regular_path(package, "METADATA")))
        license_header = entry.get("license_header", "License")
        if license_header not in {"License", "License-Expression"}:
            raise ValueError("unsupported licence metadata header")
        other_header = "License" if license_header == "License-Expression" else "License-Expression"
        if metadata.get_all(other_header, []):
            raise ValueError("ambiguous licence metadata")
        values = {}
        for header in ("Name", "Version", license_header):
            fields = metadata.get_all(header, [])
            if len(fields) != 1:
                raise ValueError("missing or ambiguous distribution identity")
            values[header] = fields[0].strip()
        if (canonical_name(values["Name"]), values["Version"], values[license_header]) != (
            canonical_name(entry["name"]), entry["version"], entry["license"],
        ):
            raise ValueError("installed distribution changed; review notice evidence")
        data = read_regular(regular_path(evidence, entry["notice_file"]))
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("upstream notice checksum mismatch")
        target = regular_path(package, entry["installed_filename"])
        if target in targets:
            raise ValueError("duplicate notice target")
        targets.add(target)
        if target.exists() and read_regular(target) != data:
            raise ValueError("refusing to overwrite different existing notice")
        pending.append((target, data))
    # A changed distribution or evidence file must leave all notices untouched.
    for target, data in pending:
        target.write_bytes(data)
    return len(pending)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site-packages", type=Path,
                        default=Path(sysconfig.get_paths()["purelib"]))
    parser.add_argument("--evidence", type=Path,
                        default=Path("/usr/share/doc/raptor-python-notices"))
    args = parser.parse_args()
    try:
        count = install(args.site_packages, args.evidence)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"Python notice installation failed: {exc}\n")
    print(f"Retained {count} reviewed upstream Python notice files")

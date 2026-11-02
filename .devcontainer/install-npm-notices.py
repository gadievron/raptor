#!/usr/bin/env python3
"""Retain reviewed upstream evidence for bundled npm package notice omissions.

The JSON manifest records original sources; these are additions to future
images, not files recovered from previously published images. It intentionally
does not synthesize licence text for unresolved packages.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


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


def install(root: Path, evidence: Path) -> int:
    manifest = json.loads((evidence / "provenance.json").read_text())
    manager = manifest.get("package_manager") or {
        "name": "npm", "version": manifest["npm_version"],
        "dependency_directory": "node_modules",
    }
    metadata = json.loads(regular_path(root, "package.json").read_text())
    if (metadata.get("name"), metadata.get("version")) != (manager["name"], manager["version"]):
        raise ValueError("package manager version changed; run refresh-npm-notices.py for this package root and evidence directory")
    pending = []
    unresolved = []
    # Validate every entry before writing any additions.
    for entry in manifest["packages"]:
        if entry.get("at_root") is True:
            package = root
        else:
            dependencies = regular_path(root, manager["dependency_directory"])
            package = regular_path(dependencies, entry["name"])
        if entry.get("absent") is True:
            if package.exists():
                raise ValueError("bundled package changed; refresh notice evidence")
            continue
        metadata = json.loads(regular_path(package, "package.json").read_text())
        expected = (entry["name"], entry["version"], entry["license"])
        if (metadata.get("name"), metadata.get("version"), metadata.get("license")) != expected:
            raise ValueError("bundled package changed; run refresh-npm-notices.py")
        if entry["status"] == "unresolved":
            unresolved.append(entry["name"])
            continue
        data = regular_path(evidence, entry["notice_file"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            raise ValueError("upstream notice checksum mismatch")
        target = regular_path(package, entry["installed_filename"])
        if target.exists() and target.read_bytes() != data:
            raise ValueError("refusing to overwrite different existing notice")
        pending.append((target, data))
    for target, data in pending:
        target.write_bytes(data)
    for name in unresolved:
        print(f"Unresolved bundled npm notice: {name}; see provenance.json", file=sys.stderr)
    return len(pending)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package-root", "--npm-root", dest="package_root", type=Path,
                        default=Path("/usr/lib/node_modules/npm"))
    parser.add_argument("--evidence", type=Path, default=Path("/usr/share/doc/raptor-npm-notices"))
    args = parser.parse_args()
    try:
        count = install(args.package_root, args.evidence)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"npm notice installation failed: {exc}\n")
    print(f"Retained {count} reviewed upstream npm notice files")

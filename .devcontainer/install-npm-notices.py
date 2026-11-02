#!/usr/bin/env python3
"""Retain reviewed upstream evidence for npm's bundled notice omissions.

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
    npm = json.loads(regular_path(root, "package.json").read_text())
    if (npm.get("name"), npm.get("version")) != ("npm", manifest["npm_version"]):
        raise ValueError("npm version changed; review bundled notice evidence")
    pending = []
    unresolved = []
    # Validate every entry before writing any additions.
    for entry in manifest["packages"]:
        package = regular_path(root, "node_modules/" + entry["name"])
        metadata = json.loads(regular_path(package, "package.json").read_text())
        expected = (entry["name"], entry["version"], entry["license"])
        if (metadata.get("name"), metadata.get("version"), metadata.get("license")) != expected:
            raise ValueError("bundled package changed; review notice evidence")
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
    parser.add_argument("--npm-root", type=Path, default=Path("/usr/lib/node_modules/npm"))
    parser.add_argument("--evidence", type=Path, default=Path("/usr/share/doc/raptor-npm-notices"))
    args = parser.parse_args()
    try:
        count = install(args.npm_root, args.evidence)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(1, f"npm notice installation failed: {exc}\n")
    print(f"Retained {count} reviewed upstream npm notice files")

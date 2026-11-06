#!/usr/bin/env python3
"""Stream a portable checksum manifest for a completed container evidence download."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import re
import stat
import sys

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from core.atomic_fs import write_text_atomically
from core.security.log_sanitisation import sanitise_for_terminal
from core.source.beneath import open_regular_beneath

MANIFEST = "evidence-checksums.sha256"
BUNDLE = "evidence-attestation.jsonl"
MAX_ENTRIES = 30_000
MAX_FILE_BYTES = 2 * 1024 ** 3
MAX_TOTAL_BYTES = 8 * 1024 ** 3


def write_checksums(directory: Path) -> int:
    """Refuse foreign paths and special files; publish only a complete manifest."""
    if directory.is_symlink() or not directory.is_dir():
        raise ValueError("evidence root must be a regular directory")
    root = directory.resolve()
    paths = []
    for index, path in enumerate(root.rglob("*")):
        if index >= MAX_ENTRIES:
            raise ValueError("evidence inventory exceeds its entry budget")
        relative = path.relative_to(root).as_posix()
        if any(char in relative for char in "\\\r\n") or any(ord(char) < 32 or ord(char) == 127 for char in relative):
            raise ValueError("evidence filenames cannot contain checksum control characters")
        mode = path.lstat().st_mode
        if stat.S_ISDIR(mode):
            continue
        if not stat.S_ISREG(mode):
            raise ValueError("evidence must not contain symlinks or special files")
        if relative in {MANIFEST, BUNDLE}:
            raise ValueError("evidence already contains a checksum manifest or signature bundle")
        paths.append(relative)
    hashes, total = {}, 0
    image_digest = None
    for relative in sorted(paths):
        stream = open_regular_beneath(root, relative, "rb")
        if stream is None:
            raise ValueError("evidence file changed or could not be opened safely")
        with stream:
            size = os.fstat(stream.fileno()).st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                raise ValueError("evidence exceeds its byte budget")
            digest, count = hashlib.sha256(), 0
            if relative == "image-digest.txt":
                raw = stream.read(257)
                if len(raw) > 256 or not re.fullmatch(rb"sha256:[0-9a-f]{64}\n?", raw):
                    raise ValueError("invalid image digest")
                image_digest = raw.decode("ascii").strip()
                digest.update(raw)
                count = len(raw)
            while chunk := stream.read(1024 * 1024):
                count += len(chunk)
                if count > MAX_FILE_BYTES or total + count > MAX_TOTAL_BYTES:
                    raise ValueError("evidence grew beyond its byte budget")
                digest.update(chunk)
            if count != size:
                raise ValueError("evidence changed while hashing")
            total += count
            hashes[relative] = digest.hexdigest()
    if image_digest is None or hashes.get("manifest.json") != image_digest[7:]:
        raise ValueError("image digest does not match the retained OCI manifest")
    text = "# OCI image: " + image_digest + "\n"
    text += "".join(digest + "  " + name + "\n" for name, digest in hashes.items())
    write_text_atomically(root / MANIFEST, text, replace=False)
    return len(hashes)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--audit-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        write_checksums(args.audit_dir)
    except (OSError, ValueError) as error:
        parser.exit(1, "SBOM checksum manifest unavailable: " + sanitise_for_terminal(str(error)) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Capture original container notice bytes without running or publishing an image."""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import stat
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from core.json import save_json
from core.oci.evidence import capture, read_catalogue, subject
from core.oci.image_ref import parse_image_ref
from core.security.capped_read import read_capped

MAX_CATALOGUE_BYTES = 50 * 1024 * 1024


def layout_reader(layout: Path):
    """Stream regular blobs via directory FDs; never follow store symlinks."""
    def read(layer):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        directories = []
        try:
            directories.append(os.open(layout, flags | os.O_DIRECTORY))
            for component in ("blobs", "sha256"):
                directories.append(os.open(component, flags | os.O_DIRECTORY, dir_fd=directories[-1]))
            fd = os.open(layer.digest.removeprefix("sha256:"), flags, dir_fd=directories[-1])
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise ValueError("OCI blob is not a regular file")
                while chunk := stream.read(65536):
                    yield chunk
        finally:
            for directory in reversed(directories):
                os.close(directory)
    return read


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--syft", type=Path, required=True, help="native Syft 16.x image JSON")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--oci-layout", type=Path, help="offline OCI blob store")
    source.add_argument("--registry-ref", help="explicit single-platform IMAGE@sha256:DIGEST")
    parser.add_argument("--identify", action="append", default=[], help="hash a catalogued file without saving executable bytes")
    parser.add_argument("--out", type=Path, required=True, help="new evidence directory")
    args = parser.parse_args(argv)
    if args.out.exists() or args.out.is_symlink():
        parser.error("output must be a new directory")
    raw = read_capped(args.syft, MAX_CATALOGUE_BYTES, follow_symlinks=True, raise_on_refusal=True)
    catalogue = read_catalogue(raw)
    image, _ = subject(catalogue)
    if args.oci_layout:
        reader = layout_reader(args.oci_layout)
    else:
        ref = parse_image_ref(args.registry_ref)
        if ref.digest != image["manifest_digest"]:
            raise ValueError("registry reference must pin the catalogue platform manifest digest")
        # Offline imports and pytest-only CI do not require HTTP dependencies.
        from core.http.urllib_backend import UrllibClient
        from core.oci.client import OciRegistryClient
        client = OciRegistryClient(UrllibClient(user_agent="raptor-container-evidence/1"))
        reader = lambda layer: client.stream_blob(ref, layer.digest)
    report, blobs = capture(catalogue, reader, identify=tuple(args.identify))
    report["catalogue_sha256"] = hashlib.sha256(raw).hexdigest()
    # All required layer/file checks complete before creating output. evidence.json
    # is written last; its absence means a write failed and capture is incomplete.
    args.out.mkdir(parents=True, exist_ok=False)
    notice_dir = args.out / "notices" / "sha256"
    notice_dir.mkdir(parents=True)
    for sha, data in sorted(blobs.items()):
        with (notice_dir / sha).open("xb") as stream:
            stream.write(data)
    save_json(args.out / "evidence.json", report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

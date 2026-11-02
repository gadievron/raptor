"""Explicit sources for digest-pinned OCI evidence; offline imports stay light."""
from __future__ import annotations

import os
from pathlib import Path
import stat

from core.oci.image_ref import parse_image_ref

def layout_reader(layout: Path):
    """Stream regular blobs via directory FDs; never follow store symlinks."""
    def read(layer):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
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


def registry_reader(manifest_digest: str, reference: str):
    """Read only the explicitly selected image, with no catalogue-derived URLs."""
    ref = parse_image_ref(reference)
    if not ref.digest or ref.digest != manifest_digest:
        raise ValueError("registry reference must pin the catalogue platform manifest digest")
    # Only the explicit online path imports HTTP dependencies or creates a client.
    from core.http.urllib_backend import UrllibClient
    from core.oci.client import OciRegistryClient
    client = OciRegistryClient(UrllibClient(user_agent="raptor-container-evidence/1"))
    return lambda layer: client.stream_blob(ref, layer.digest)

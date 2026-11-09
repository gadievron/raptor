"""Explicit sources for digest-pinned OCI evidence; offline imports stay light."""
from __future__ import annotations

import os
from contextlib import ExitStack
from pathlib import Path
import stat

from core.oci.image_ref import parse_image_ref
from core.source.streams import open_owned_fd, preserving_stream_error

def layout_reader(layout: Path):
    """Stream regular blobs via directory FDs; never follow store symlinks."""
    def read(layer):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        early_exit = None
        with preserving_stream_error(ExitStack()) as owned:
            directory = os.open(layout, flags | os.O_DIRECTORY)
            owned.callback(os.close, directory)
            for component in ("blobs", "sha256"):
                directory = os.open(component, flags | os.O_DIRECTORY, dir_fd=directory)
                owned.callback(os.close, directory)
            fd = os.open(layer.digest.removeprefix("sha256:"), flags, dir_fd=directory)
            stream = owned.enter_context(open_owned_fd(fd, "rb"))
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                raise ValueError("OCI blob is not a regular file")
            try:
                while chunk := stream.read(65536):
                    yield chunk
            except GeneratorExit as exc:
                # Explicit iterator close is normal teardown, so cleanup
                # errors must surface instead of being hidden by GeneratorExit.
                early_exit = exc
        if early_exit is not None:
            try:
                raise early_exit
            finally:
                early_exit = None
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

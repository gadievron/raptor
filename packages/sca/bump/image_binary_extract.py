"""Extract a single binary from an OCI image to a local path.

Companion to :mod:`packages.sca.bump.binary_capability_delta` — the
detector compares two binaries, but doesn't know how to pull them
out of container images. This module owns that path:

  1. Resolve the image ref → manifest → (if multi-arch) drill
     platform → single-platform manifest.
  2. Fetch the image config blob, parse its ``Entrypoint`` /
     ``Cmd`` to identify the main binary path inside the image.
  3. Walk layers in order, ``extract_files_from_layer`` for the
     target path. Later layers override earlier ones (overlay-fs
     semantics) — exactly the same pattern as
     ``fetch_image_sbom`` for package-state files.
  4. Write the resulting bytes to ``out_dir`` (or a system
     tempfile) and return the local ``Path``.

The detector then receives two such local paths and runs the
capability diff.

Failure modes are routine when scanning multi-image-source
projects (private registries, missing tags, malformed configs,
rate-limited anonymous pulls). Every failure returns ``None`` with
a debug-level log — the caller (bump orchestrator) treats it as
"no binary-tier signal for this bump", which is the right verdict
because we have no evidence to escalate on.

Caller-supplied ``binary_path`` (absolute path inside the image)
overrides the entrypoint-auto-detection step. Useful for images
where ``Entrypoint`` is a shell wrapper but the load-bearing
binary is e.g. ``/usr/local/bin/server`` (operator knows; we
don't).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from pathlib import Path
from typing import List, Optional

from core.oci.blob import extract_files_from_layer
from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref
from core.oci.manifest import (
    is_image_index,
    is_image_manifest,
    parse_image_index,
    parse_image_manifest,
)

logger = logging.getLogger(__name__)


# Maximum compressed bytes of any single layer we'll stream when
# looking for the binary. Same cap as ``fetch_image_sbom``'s
# default — base images are small (alpine ~5 MB, debian-slim
# ~30 MB); a multi-GB layer is almost always an app blob that
# wouldn't carry the entrypoint binary anyway.
DEFAULT_MAX_LAYER_BYTES = 256 * 1024 * 1024


def fetch_image_binary(
    image_ref_str: str,
    *,
    client: OciRegistryClient,
    binary_path: Optional[str] = None,
    platform_os: str = "linux",
    platform_arch: str = "amd64",
    out_dir: Optional[Path] = None,
    max_layer_bytes: int = DEFAULT_MAX_LAYER_BYTES,
) -> Optional[Path]:
    """Pull one binary out of ``image_ref_str``.

    ``binary_path`` is an absolute in-image path. When ``None``,
    we read the image config's ``Entrypoint`` / ``Cmd`` and use
    the first absolute path we find there.

    Returns the local ``Path`` containing the extracted bytes
    (under ``out_dir`` or a system tempdir), or ``None`` on any
    resolution / extraction failure.
    """
    try:
        ref = parse_image_ref(image_ref_str)
    except Exception as e:                            # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: cannot parse %r: %s",
            image_ref_str, e,
        )
        return None

    try:
        manifest_resp = client.fetch_manifest(ref)
    except (RegistryError, Exception) as e:           # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: manifest fetch failed "
            "for %s: %s", image_ref_str, e,
        )
        return None

    # Multi-arch index → drill to the platform.
    parsed = manifest_resp.parsed
    if is_image_index(manifest_resp.content_type):
        entries = parse_image_index(parsed)
        target = _select_platform(entries, platform_os, platform_arch)
        if target is None:
            logger.debug(
                "sca.bump.image_binary_extract: no %s/%s entry in "
                "index for %s",
                platform_os, platform_arch, image_ref_str,
            )
            return None
        try:
            manifest_resp = client.fetch_manifest(
                ref, reference=target.digest,
            )
        except (RegistryError, Exception) as e:       # noqa: BLE001
            logger.debug(
                "sca.bump.image_binary_extract: platform manifest "
                "fetch failed for %s@%s: %s",
                image_ref_str, target.digest, e,
            )
            return None
        parsed = manifest_resp.parsed

    if not is_image_manifest(manifest_resp.content_type):
        logger.debug(
            "sca.bump.image_binary_extract: unexpected manifest "
            "media type %s for %s",
            manifest_resp.content_type, image_ref_str,
        )
        return None

    try:
        image_manifest = parse_image_manifest(parsed)
    except ValueError as e:
        logger.debug(
            "sca.bump.image_binary_extract: manifest parse failed "
            "for %s: %s", image_ref_str, e,
        )
        return None

    if binary_path is None:
        binary_path = _resolve_entrypoint_path(
            client=client, ref=ref,
            config_digest=image_manifest.config_digest,
        )
        if binary_path is None:
            logger.debug(
                "sca.bump.image_binary_extract: could not resolve "
                "entrypoint path for %s",
                image_ref_str,
            )
            return None

    # Layers in order — earliest first. Later layers can replace
    # the same file (overlay-fs semantics); take whichever the
    # final-state path resolves to.
    wanted_path = binary_path.lstrip("/")
    final_bytes: Optional[bytes] = None
    for layer in image_manifest.layers:
        if layer.size and layer.size > max_layer_bytes:
            continue
        try:
            chunks = client.stream_blob(ref, layer.digest)
            files = extract_files_from_layer(chunks, {wanted_path})
        except Exception as e:                        # noqa: BLE001
            logger.debug(
                "sca.bump.image_binary_extract: layer %s extract "
                "failed for %s: %s",
                layer.digest, image_ref_str, e,
            )
            continue
        if wanted_path in files:
            final_bytes = files[wanted_path]
        elif binary_path in files:
            # Tolerate both leading-/ and stripped forms — the tar
            # entry-name normaliser in core/oci/blob already
            # canonicalises but the dict key reflects what the
            # caller asked for.
            final_bytes = files[binary_path]

    if final_bytes is None:
        logger.debug(
            "sca.bump.image_binary_extract: %s not found in any "
            "layer of %s", binary_path, image_ref_str,
        )
        return None

    if out_dir is None:
        out_dir = Path(tempfile.gettempdir())
    out_dir.mkdir(parents=True, exist_ok=True)
    # Name the file by the image's digest + the basename so two
    # different versions of the same image can coexist on disk
    # without collision when the same out_dir is reused.
    safe_digest = (manifest_resp.digest or "nodigest").replace(":", "_")
    basename = os.path.basename(binary_path) or "binary"
    out_path = out_dir / f"{safe_digest}-{basename}"
    out_path.write_bytes(final_bytes)
    return out_path


def _select_platform(
    entries: List, platform_os: str, platform_arch: str,
):
    """Pick the index entry matching ``(platform_os,
    platform_arch)``. Ignores variant — first match wins."""
    for e in entries:
        if e.os == platform_os and e.architecture == platform_arch:
            return e
    return None


def _resolve_entrypoint_path(
    *, client: OciRegistryClient, ref, config_digest: str,
) -> Optional[str]:
    """Fetch the image config blob and read ``Entrypoint`` /
    ``Cmd`` to find the main binary's in-image path.

    OCI image config shape:
        {"config": {"Entrypoint": ["/usr/bin/foo", "--flag"],
                    "Cmd": ["--default"], ...}, ...}

    Returns the first absolute path found in Entrypoint, or the
    first absolute path in Cmd, or None if neither yields one.
    """
    try:
        chunks = client.stream_blob(ref, config_digest)
        # Config blobs are JSON, not gzipped tar — read raw bytes.
        blob = b"".join(chunks)
        config = json.loads(blob.decode("utf-8", errors="replace"))
    except Exception as e:                            # noqa: BLE001
        logger.debug(
            "sca.bump.image_binary_extract: config blob fetch / "
            "parse failed for digest %s: %s",
            config_digest, e,
        )
        return None

    inner = config.get("config") if isinstance(config, dict) else None
    if not isinstance(inner, dict):
        return None
    for key in ("Entrypoint", "Cmd"):
        seq = inner.get(key)
        if not isinstance(seq, list):
            continue
        for item in seq:
            if isinstance(item, str) and item.startswith("/"):
                return item
    return None


__all__ = [
    "DEFAULT_MAX_LAYER_BYTES",
    "fetch_image_binary",
]

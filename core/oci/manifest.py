"""Manifest + image-index parsing for OCI / Docker registries.

Two manifest shapes register to consume:

  1. **Image manifest** (single platform) — points at a config blob
     and a list of layer descriptors. The ``mediaType`` is one of:
       * ``application/vnd.oci.image.manifest.v1+json``
       * ``application/vnd.docker.distribution.manifest.v2+json``

  2. **Image index** (multi-platform) — points at a list of child
     manifests, each tagged with a platform (os + architecture).
     Pulling a multi-arch image involves fetching the index, picking
     a platform, then fetching THAT platform's manifest. The
     ``mediaType`` is one of:
       * ``application/vnd.oci.image.index.v1+json``
       * ``application/vnd.docker.distribution.manifest.list.v2+json``

This module discriminates between them and provides helpers for
the platform selection. The default platform is ``linux/amd64`` —
matches raptor's host arch and the dominant target. Operators
running on Apple Silicon or scanning ARM64-only deployments
override via ``--platform``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Optional

logger = logging.getLogger(__name__)


# Known media types — used to discriminate manifest vs index, and
# OCI vs Docker schema. The set is exhaustive for what registries
# serve today; new variants (e.g. cosign attestations) are added
# only when needed.

_IMAGE_MANIFEST_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
})

_IMAGE_INDEX_MEDIA_TYPES = frozenset({
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
})


# Default platform when the caller doesn't specify. Linux/amd64 is
# the dominant deployment target and the host arch raptor itself
# supports. Operators running ARM64-only deployments or scanning
# Apple Silicon images override.
DEFAULT_PLATFORM_OS = "linux"
DEFAULT_PLATFORM_ARCH = "amd64"


@dataclass(frozen=True)
class LayerDescriptor:
    """One layer in an image manifest.

    ``size`` is the compressed byte count; the tar inside is
    typically larger. We use it to gate streaming reads and to
    surface "image too big to bother scanning" to operators.
    """
    digest: str
    size: int
    media_type: str


@dataclass(frozen=True)
class ImageManifest:
    """Single-platform manifest result.

    ``config_digest`` points at the image config blob (which
    carries env, cmd, exposed ports, etc. — not what we need for
    SBOM, but sometimes consumers want it). ``layers`` is the
    ordered list — earlier layers are deeper in the file system,
    so package state from later layers wins on path collisions.
    """
    config_digest: str
    layers: List[LayerDescriptor]
    media_type: str


@dataclass(frozen=True)
class IndexEntry:
    """One entry in an image index. Points at a per-platform
    manifest digest with the platform tags set."""
    digest: str
    size: int
    media_type: str
    os: Optional[str]
    architecture: Optional[str]
    variant: Optional[str]              # e.g. "v8" for arm64v8


def is_image_index(media_type: str) -> bool:
    return media_type in _IMAGE_INDEX_MEDIA_TYPES


def is_image_manifest(media_type: str) -> bool:
    return media_type in _IMAGE_MANIFEST_MEDIA_TYPES


def parse_image_manifest(parsed: dict) -> ImageManifest:
    """Convert a parsed manifest JSON into an :class:`ImageManifest`.

    Tolerates both OCI and Docker schemas — they have nearly
    identical shapes (``config: {...}``, ``layers: [{...}, ...]``)
    and we surface the original ``mediaType`` so callers can
    distinguish if they care.
    """
    media_type = parsed.get("mediaType") or ""
    config = parsed.get("config") or {}
    config_digest = config.get("digest") or ""
    if not config_digest:
        raise ValueError(
            "manifest missing config.digest — cannot identify image",
        )
    layers_raw = parsed.get("layers") or []
    layers: List[LayerDescriptor] = []
    for layer in layers_raw:
        if not isinstance(layer, dict):
            continue
        digest = layer.get("digest")
        size = layer.get("size")
        ltype = layer.get("mediaType") or ""
        if not isinstance(digest, str) or not isinstance(size, int):
            continue
        layers.append(LayerDescriptor(
            digest=digest, size=int(size), media_type=ltype,
        ))
    return ImageManifest(
        config_digest=config_digest,
        layers=layers,
        media_type=media_type,
    )


def parse_image_index(parsed: dict) -> List[IndexEntry]:
    """Convert a parsed image-index JSON into a list of
    :class:`IndexEntry`. Caller picks one and fetches that
    manifest separately."""
    out: List[IndexEntry] = []
    for entry in parsed.get("manifests") or []:
        if not isinstance(entry, dict):
            continue
        digest = entry.get("digest")
        size = entry.get("size", 0)
        ltype = entry.get("mediaType") or ""
        platform = entry.get("platform") or {}
        if not isinstance(digest, str):
            continue
        out.append(IndexEntry(
            digest=digest, size=int(size), media_type=ltype,
            os=platform.get("os"),
            architecture=platform.get("architecture"),
            variant=platform.get("variant"),
        ))
    return out


def select_platform(
    entries: List[IndexEntry],
    *,
    os: str = DEFAULT_PLATFORM_OS,
    architecture: str = DEFAULT_PLATFORM_ARCH,
    variant: Optional[str] = None,
) -> Optional[IndexEntry]:
    """Pick the entry matching ``(os, architecture[, variant])``.

    Behaviour:
      * Exact match on os + architecture (+ variant if given) wins.
      * If no exact match, returns the first entry whose os matches
        (gives operators a useful fallback when they scan an image
        with platforms they didn't expect).
      * Skips ``os == "unknown"`` entries — those are typically
        attestations (cosign signatures, SBOM artefacts) attached
        to the index, not real platforms.
      * Returns ``None`` when nothing matches at all (caller surfaces
        as a "no compatible platform" error).
    """
    real = [e for e in entries if e.os and e.os != "unknown"]
    # Exact match.
    for e in real:
        if e.os == os and e.architecture == architecture and (
            variant is None or e.variant == variant
        ):
            return e
    # Variant-relaxed match.
    if variant is not None:
        for e in real:
            if e.os == os and e.architecture == architecture:
                return e
    # OS-only fallback — gives operators something workable when
    # we don't have an exact arch match.
    for e in real:
        if e.os == os:
            return e
    return None


__all__ = [
    "DEFAULT_PLATFORM_OS",
    "DEFAULT_PLATFORM_ARCH",
    "LayerDescriptor",
    "ImageManifest",
    "IndexEntry",
    "is_image_index",
    "is_image_manifest",
    "parse_image_manifest",
    "parse_image_index",
    "select_platform",
]

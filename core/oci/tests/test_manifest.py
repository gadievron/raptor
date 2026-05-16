"""Tests for ``core.oci.manifest`` — parsers + platform selection."""

from __future__ import annotations

from core.oci.manifest import (
    IndexEntry,
    LayerDescriptor,
    is_image_index,
    is_image_manifest,
    parse_image_index,
    parse_image_manifest,
    select_platform,
)


# ---------------------------------------------------------------------------
# Discrimination
# ---------------------------------------------------------------------------


def test_is_image_manifest_recognises_oci_and_docker():
    assert is_image_manifest("application/vnd.oci.image.manifest.v1+json")
    assert is_image_manifest(
        "application/vnd.docker.distribution.manifest.v2+json",
    )
    assert not is_image_manifest("application/vnd.oci.image.index.v1+json")


def test_is_image_index_recognises_oci_and_docker():
    assert is_image_index("application/vnd.oci.image.index.v1+json")
    assert is_image_index(
        "application/vnd.docker.distribution.manifest.list.v2+json",
    )
    assert not is_image_index(
        "application/vnd.oci.image.manifest.v1+json",
    )


# ---------------------------------------------------------------------------
# Image manifest parsing
# ---------------------------------------------------------------------------


def test_parse_image_manifest_oci_shape():
    """OCI image manifest: ``config`` + ``layers`` + ``mediaType``."""
    parsed = parse_image_manifest({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": "sha256:" + "c" * 64, "size": 100},
        "layers": [
            {"digest": "sha256:" + "a" * 64, "size": 1000,
             "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"},
            {"digest": "sha256:" + "b" * 64, "size": 2000,
             "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip"},
        ],
    })
    assert parsed.config_digest == "sha256:" + "c" * 64
    assert len(parsed.layers) == 2
    assert parsed.layers[0].digest == "sha256:" + "a" * 64
    assert parsed.layers[0].size == 1000


def test_parse_image_manifest_docker_v2_shape():
    """Docker schema-2 manifest has the same shape modulo media
    types. Both must round-trip through the same parser."""
    parsed = parse_image_manifest({
        "mediaType":
            "application/vnd.docker.distribution.manifest.v2+json",
        "config": {"digest": "sha256:" + "1" * 64},
        "layers": [
            {"digest": "sha256:" + "2" * 64, "size": 500,
             "mediaType":
                 "application/vnd.docker.image.rootfs.diff.tar.gzip"},
        ],
    })
    assert parsed.config_digest == "sha256:" + "1" * 64
    assert parsed.layers == [LayerDescriptor(
        digest="sha256:" + "2" * 64, size=500,
        media_type="application/vnd.docker.image.rootfs.diff.tar.gzip",
    )]


def test_parse_image_manifest_skips_malformed_layers():
    """A layer entry missing ``digest`` or with a non-int size is
    skipped silently — broken layers shouldn't crash the parser
    but the consumer should still see the well-formed ones."""
    parsed = parse_image_manifest({
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"digest": "sha256:" + "c" * 64},
        "layers": [
            {"digest": "sha256:" + "a" * 64, "size": 100},
            "this-is-not-a-dict",
            {"digest": "sha256:" + "b" * 64},   # missing size
            {"size": 500},                       # missing digest
            {"digest": "sha256:" + "d" * 64, "size": 999},
        ],
    })
    digests = [l.digest for l in parsed.layers]
    assert digests == ["sha256:" + "a" * 64, "sha256:" + "d" * 64]


def test_parse_image_manifest_missing_config_digest_raises():
    """The config blob digest is the image's identity — without it
    we can't proceed. Surface clearly rather than emitting a
    half-formed manifest."""
    import pytest
    with pytest.raises(ValueError, match="config.digest"):
        parse_image_manifest({
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {},
            "layers": [],
        })


# ---------------------------------------------------------------------------
# Image index parsing
# ---------------------------------------------------------------------------


def test_parse_image_index_with_multiple_platforms():
    """Multi-arch ``python:3.11`` typically has 5+ platform
    variants; the parser surfaces all of them with their platform
    metadata so the caller can pick."""
    entries = parse_image_index({
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [
            {"digest": "sha256:" + "a" * 64, "size": 100,
             "mediaType":
                 "application/vnd.oci.image.manifest.v1+json",
             "platform": {"os": "linux", "architecture": "amd64"}},
            {"digest": "sha256:" + "b" * 64, "size": 100,
             "mediaType":
                 "application/vnd.oci.image.manifest.v1+json",
             "platform": {"os": "linux", "architecture": "arm64",
                          "variant": "v8"}},
            # Cosign attestation — has os="unknown".
            {"digest": "sha256:" + "c" * 64, "size": 100,
             "mediaType":
                 "application/vnd.oci.image.manifest.v1+json",
             "platform": {"os": "unknown", "architecture": "unknown"}},
        ],
    })
    assert len(entries) == 3
    assert entries[0].os == "linux"
    assert entries[0].architecture == "amd64"
    assert entries[1].variant == "v8"


# ---------------------------------------------------------------------------
# select_platform
# ---------------------------------------------------------------------------


def _entry(os, arch, variant=None):
    return IndexEntry(
        digest="sha256:" + os[0] * 64,
        size=100, media_type="x",
        os=os, architecture=arch, variant=variant,
    )


def test_select_platform_exact_match():
    entries = [
        _entry("linux", "amd64"),
        _entry("linux", "arm64", "v8"),
    ]
    pick = select_platform(entries)            # default linux/amd64
    assert pick == entries[0]


def test_select_platform_with_variant():
    entries = [
        _entry("linux", "arm64", "v7"),
        _entry("linux", "arm64", "v8"),
    ]
    pick = select_platform(
        entries, os="linux", architecture="arm64", variant="v8",
    )
    assert pick.variant == "v8"


def test_select_platform_falls_back_when_no_exact_match():
    """Os-only fallback: if no entry has the requested arch, return
    the first one with the requested os. Better than nothing —
    operators get usable signal even when their requested arch
    isn't in the image."""
    entries = [
        _entry("linux", "ppc64le"),
        _entry("linux", "s390x"),
    ]
    pick = select_platform(entries)            # default linux/amd64
    assert pick == entries[0]                   # first os=linux


def test_select_platform_skips_attestation_entries():
    """``os: "unknown"`` entries are typically cosign attestations
    or SBOM artefacts — pulling them as "the image" produces
    nonsense. Always skipped."""
    entries = [
        IndexEntry(digest="sha256:" + "z" * 64, size=100,
                   media_type="x",
                   os="unknown", architecture="unknown",
                   variant=None),
        _entry("linux", "amd64"),
    ]
    pick = select_platform(entries)
    assert pick.os == "linux"


def test_select_platform_returns_none_when_nothing_matches():
    """Windows-only image scanned without a ``--platform windows``
    override → no match → None."""
    entries = [_entry("windows", "amd64")]
    pick = select_platform(entries)            # default linux/amd64
    assert pick is None

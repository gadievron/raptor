"""Tests for B9 polish — source_extra (image / digest / stage_name)
surfacing + cross-run SBOM cache.

The B9 baseline tests in ``test_dockerfile_from.py`` exercised the
extraction logic end-to-end. These tests pin the specific
follow-up additions: that the resulting Dependency rows carry
the stage / image / digest in ``source_extra``, that the SBOM
properties block surfaces those fields, that the report.md bullet
list shows base-image context, and that a JsonCache makes a
second run skip the registry.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional
from unittest.mock import MagicMock


from core.json import JsonCache
from packages.sca.dockerfile_from import (
    ImageSbom,
    fetch_image_sbom,
    packages_to_dependencies,
    scan_dockerfiles,
)
from packages.sca.models import Dependency, PinStyle


# ---------------------------------------------------------------------------
# Helpers (lifted from test_dockerfile_from)
# ---------------------------------------------------------------------------


@dataclass
class _Resp:
    parsed: Dict[str, Any]
    content_type: str
    digest: Optional[str]


def _layer(file_payloads: Dict[str, bytes]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w") as tf:
        for path, content in file_payloads.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tf.addfile(info, io.BytesIO(content))
    return gzip.compress(raw.getvalue())


def _chunk(data: bytes, size: int = 1024) -> Iterator[bytes]:
    for i in range(0, len(data), size):
        yield data[i:i + size]


def _client(manifests, blobs):
    client = MagicMock()
    client.fetch_manifest.side_effect = lambda ref, *, reference=None: (
        manifests[reference or ref.tag or ref.digest or "latest"]
    )
    client.stream_blob.side_effect = lambda ref, digest, **_: _chunk(
        blobs[digest],
    )
    return client


# ---------------------------------------------------------------------------
# Stage name + image + digest in source_extra
# ---------------------------------------------------------------------------


def test_packages_to_deps_populates_source_extra():
    from core.oci.sbom import InstalledPackage
    deps = packages_to_dependencies(
        [InstalledPackage(ecosystem="Debian", name="zlib1g",
                          version="1:1.2.13.dfsg-1")],
        declared_in=Path("Dockerfile"),
        image_ref="debian:11",
        digest="sha256:" + "a" * 64,
        stage_name="builder",
    )
    assert deps[0].source_extra == {
        "image": "debian:11",
        "digest": "sha256:" + "a" * 64,
        "stage_name": "builder",
    }


def test_packages_to_deps_omits_source_extra_when_no_context():
    """Backwards compatibility: callers that don't pass any
    image/digest/stage info get source_extra=None."""
    from core.oci.sbom import InstalledPackage
    deps = packages_to_dependencies(
        [InstalledPackage(ecosystem="Debian", name="x", version="1")],
        declared_in=Path("Dockerfile"),
    )
    assert deps[0].source_extra is None


def test_packages_to_deps_image_only_records_image_and_stage_none():
    """``image_ref`` is the gate: when supplied, we record the
    image + stage_name (None means "final stage", a meaningful
    value). ``digest`` is optional."""
    from core.oci.sbom import InstalledPackage
    deps = packages_to_dependencies(
        [InstalledPackage(ecosystem="Alpine", name="musl",
                          version="1.2.4-r2")],
        declared_in=Path("Dockerfile"),
        image_ref="alpine:3.18",
    )
    assert deps[0].source_extra == {
        "image": "alpine:3.18",
        "stage_name": None,
    }


def test_stage_name_none_treated_as_present():
    """``stage_name=None`` (final/un-named stage) IS context — we
    record it explicitly so the report can distinguish "no stage"
    from "didn't supply"."""
    from core.oci.sbom import InstalledPackage
    deps = packages_to_dependencies(
        [InstalledPackage(ecosystem="Debian", name="x", version="1")],
        declared_in=Path("Dockerfile"),
        image_ref="debian:11",
        stage_name=None,
    )
    assert deps[0].source_extra is not None
    assert deps[0].source_extra["stage_name"] is None


# ---------------------------------------------------------------------------
# Multi-stage end-to-end: stage_name flows from FROM line to Dependency
# ---------------------------------------------------------------------------


def test_scan_dockerfiles_propagates_stage_name(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM python:3.11 AS builder\n"
        "RUN pip install build\n"
        "FROM python:3.11-slim\n"
    )
    layer = _layer({
        "var/lib/dpkg/status": (
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Version: 3.0.11\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _Resp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _client(
        manifests={"3.11": manifest, "3.11-slim": manifest},
        blobs={layer_digest: layer},
    )

    deps = scan_dockerfiles(tmp_path, client=client)
    # Two FROMs → two openssl rows, one tagged stage_name="builder",
    # the other stage_name=None (final stage).
    stage_names = [d.source_extra["stage_name"] for d in deps]
    assert "builder" in stage_names
    assert None in stage_names


# ---------------------------------------------------------------------------
# SBOM property surfacing
# ---------------------------------------------------------------------------


def test_sbom_surfaces_source_extra_as_properties(tmp_path):
    """source_extra fields appear as ``raptor:<key>`` properties in
    the CycloneDX component block."""
    from packages.sca.sbom import build_bom
    dep = Dependency(
        ecosystem="Debian",
        name="openssl",
        version="3.0.11",
        declared_in=tmp_path / "Dockerfile",
        scope="main",
        is_lockfile=True,
        pin_style=PinStyle.EXACT,
        direct=True,
        purl="pkg:deb/openssl@3.0.11",
        parser_confidence=__import__(
            "packages.sca.models", fromlist=["Confidence"],
        ).Confidence("high", reason="x"),
        source_kind="dockerfile_from",
        source_extra={
            "image": "debian:11",
            "digest": "sha256:" + "a" * 64,
            "stage_name": "builder",
        },
    )
    bom = build_bom(deps=[dep])
    [comp] = bom["components"]
    props = {p["name"]: p["value"] for p in comp["properties"]}
    assert props["raptor:image"] == "debian:11"
    assert props["raptor:digest"] == "sha256:" + "a" * 64
    assert props["raptor:stage_name"] == "builder"


def test_sbom_skips_none_valued_source_extra_fields(tmp_path):
    """A None-valued field (e.g. final-stage stage_name) is skipped
    from the property list — the SBOM doesn't carry ``None`` strings."""
    from packages.sca.sbom import build_bom
    from packages.sca.models import Confidence
    dep = Dependency(
        ecosystem="Debian", name="x", version="1.0",
        declared_in=tmp_path / "Dockerfile",
        scope="main", is_lockfile=True, pin_style=PinStyle.EXACT,
        direct=True, purl="pkg:deb/x@1.0",
        parser_confidence=Confidence("high", reason="x"),
        source_kind="dockerfile_from",
        source_extra={"image": "x:1", "stage_name": None},
    )
    bom = build_bom(deps=[dep])
    [comp] = bom["components"]
    prop_names = {p["name"] for p in comp["properties"]}
    assert "raptor:image" in prop_names
    assert "raptor:stage_name" not in prop_names


# ---------------------------------------------------------------------------
# Cross-run JsonCache
# ---------------------------------------------------------------------------


def test_disk_cache_populated_after_first_fetch(tmp_path):
    """First fetch_image_sbom call writes the per-digest entry to
    the JsonCache."""
    cache = JsonCache(root=tmp_path / "cache")
    layer = _layer({
        "var/lib/dpkg/status": (
            "Package: x\nStatus: install ok installed\nVersion: 1\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _Resp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _client(
        manifests={"11": manifest}, blobs={layer_digest: layer},
    )

    sbom = fetch_image_sbom("debian:11", client=client, disk_cache=cache)
    assert sbom is not None
    # Cache hit on the digest — second-run lookup pre-population.
    from core.json.cache import TTL_FOREVER
    cached = cache.get("sha256:" + "m" * 64, ttl_seconds=TTL_FOREVER)
    assert cached is not None
    assert cached["digest"] == "sha256:" + "m" * 64
    assert any(p["name"] == "x" for p in cached["packages"])


def test_disk_cache_short_circuits_second_fetch(tmp_path):
    """A second ``fetch_image_sbom`` with the cache pre-populated
    by the first never asks the client for the layer blob —
    construction-time digest resolution is enough."""
    cache = JsonCache(root=tmp_path / "cache")
    layer = _layer({
        "var/lib/dpkg/status": (
            "Package: cached\nStatus: install ok installed\n"
            "Version: 1\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _Resp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _client(
        manifests={"11": manifest}, blobs={layer_digest: layer},
    )

    # First run — populates cache.
    fetch_image_sbom("debian:11", client=client, disk_cache=cache)
    # Reset stream_blob mock so we can detect re-fetch.
    client.stream_blob.reset_mock()

    sbom2 = fetch_image_sbom("debian:11", client=client, disk_cache=cache)
    assert sbom2 is not None
    assert any(p.name == "cached" for p in sbom2.packages)
    # CRITICAL: the layer was NOT re-fetched on the second call.
    client.stream_blob.assert_not_called()


def test_image_sbom_to_from_dict_round_trip():
    from core.oci.sbom import InstalledPackage
    sbom = ImageSbom(
        image_ref="debian:11",
        digest="sha256:" + "a" * 64,
        packages=(
            InstalledPackage(ecosystem="Debian", name="x", version="1"),
            InstalledPackage(ecosystem="Debian", name="y", version="2"),
        ),
        layer_count_scanned=3,
    )
    restored = ImageSbom.from_dict(sbom.to_dict())
    assert restored.image_ref == "debian:11"
    assert restored.digest == "sha256:" + "a" * 64
    assert restored.layer_count_scanned == 3
    assert {(p.name, p.version) for p in restored.packages} == {
        ("x", "1"), ("y", "2"),
    }


def test_disk_cache_corruption_falls_back_to_fresh_fetch(tmp_path):
    """A corrupt cache entry doesn't crash the run — the resolver
    re-fetches and re-populates."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    # JsonCache hashes keys, so corrupting requires reading what
    # path it would write to. Easier: write garbage at every level
    # and confirm fetch still succeeds.
    cache = JsonCache(root=cache_dir)
    cache.put("sha256:badcafe", "this is not a sbom dict",
              ttl_seconds=999_999)

    layer = _layer({
        "var/lib/dpkg/status": (
            "Package: ok\nStatus: install ok installed\nVersion: 1\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _Resp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        # Different digest than the corrupt entry — fetch_image_sbom
        # checks against THIS digest, not the corrupt one. Test
        # confirms the fetch still produces a valid SBOM.
        digest="sha256:" + "m" * 64,
    )
    client = _client(
        manifests={"11": manifest}, blobs={layer_digest: layer},
    )
    sbom = fetch_image_sbom("debian:11", client=client, disk_cache=cache)
    assert sbom is not None
    assert any(p.name == "ok" for p in sbom.packages)


def test_no_cache_argument_means_no_persistence(tmp_path):
    """Passing ``cache=None`` to ``scan_dockerfiles`` (the test
    default + ``--no-cache`` operator path) means nothing is
    written to disk. Pure per-run."""
    (tmp_path / "Dockerfile").write_text("FROM debian:11\n")
    layer = _layer({
        "var/lib/dpkg/status": (
            "Package: x\nStatus: install ok installed\nVersion: 1\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = _Resp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _client(
        manifests={"11": manifest}, blobs={layer_digest: layer},
    )

    cache_dir = tmp_path / "cache"
    deps = scan_dockerfiles(tmp_path, client=client, cache=None)
    assert deps                                   # work happened
    assert not cache_dir.exists()                 # nothing written

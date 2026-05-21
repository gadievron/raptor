"""Tests for :mod:`packages.sca.dockerfile_from`.

Network is fully mocked — tests inject a fake :class:`OciRegistryClient`
that returns canned manifest + blob responses. The aim is to pin
the wiring (FROM extraction, multi-arch handling, multi-stage
filtering, failure paths, SBOM → Dependency mapping), not to
hit a real registry.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterator, Optional
from unittest.mock import MagicMock


from packages.sca.dockerfile_from import (
    FromEntry,
    _is_dockerfile,
    extract_from_lines,
    fetch_image_sbom,
    find_dockerfiles,
    packages_to_dependencies,
    scan_dockerfiles,
)
from packages.sca.models import PinStyle


# ---------------------------------------------------------------------------
# Helpers — synthesize manifests + layer tarballs
# ---------------------------------------------------------------------------


@dataclass
class FakeManifestResp:
    """Mimic ``ManifestResponse`` for the bits we read."""
    parsed: Dict[str, Any]
    content_type: str
    digest: Optional[str]


def _make_layer_blob(file_payloads: Dict[str, bytes]) -> bytes:
    """Build a gzipped tar layer containing the given files."""
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


def _make_client(
    manifests: Dict[str, FakeManifestResp],
    blobs: Dict[str, bytes],
) -> MagicMock:
    """Build a fake OCI client. ``manifests`` is keyed by reference
    (tag or digest) used in fetch_manifest; ``blobs`` is keyed by
    digest used in stream_blob."""
    client = MagicMock()

    def _fetch_manifest(ref, *, reference=None):
        key = reference or ref.tag or ref.digest or "latest"
        if key not in manifests:
            raise RuntimeError(f"no fake manifest for {key}")
        return manifests[key]

    def _stream_blob(ref, digest, **_):
        if digest not in blobs:
            raise RuntimeError(f"no fake blob for {digest}")
        return _chunk(blobs[digest])

    client.fetch_manifest.side_effect = _fetch_manifest
    client.stream_blob.side_effect = _stream_blob
    return client


# ---------------------------------------------------------------------------
# _is_dockerfile / find_dockerfiles
# ---------------------------------------------------------------------------


def test_is_dockerfile_canonical_names():
    assert _is_dockerfile(Path("Dockerfile"))
    assert _is_dockerfile(Path("Containerfile"))


def test_is_dockerfile_dotted_variants():
    assert _is_dockerfile(Path("Dockerfile.alpine"))
    assert _is_dockerfile(Path("prod.Dockerfile"))


def test_is_dockerfile_dotsuffix():
    assert _is_dockerfile(Path("app.dockerfile"))


def test_is_dockerfile_rejects_non_dockerfile():
    assert not _is_dockerfile(Path("Makefile"))
    assert not _is_dockerfile(Path("docker-compose.yml"))
    assert not _is_dockerfile(Path("script.sh"))


def test_find_dockerfiles_walks_and_skips_excluded(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine\n")
    (tmp_path / "subdir").mkdir()
    (tmp_path / "subdir" / "Dockerfile.api").write_text("FROM debian\n")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "Dockerfile").write_text("FROM x\n")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "Dockerfile").write_text("FROM y\n")

    found = find_dockerfiles(tmp_path)
    found_rel = {p.relative_to(tmp_path).as_posix() for p in found}
    assert found_rel == {"Dockerfile", "subdir/Dockerfile.api"}


# ---------------------------------------------------------------------------
# extract_from_lines
# ---------------------------------------------------------------------------


def test_extract_simple_from():
    [entry] = extract_from_lines("FROM python:3.11\n")
    assert entry == FromEntry(
        image="python:3.11", stage_name=None, line=1,
    )


def test_extract_strips_platform_flag():
    [entry] = extract_from_lines(
        "FROM --platform=linux/amd64 alpine:3.18\n"
    )
    assert entry.image == "alpine:3.18"


def test_extract_multi_stage_with_as():
    src = (
        "FROM python:3.11 AS builder\n"
        "RUN pip install build\n"
        "FROM python:3.11-slim\n"
        "COPY --from=builder /app /app\n"
    )
    entries = extract_from_lines(src)
    assert len(entries) == 2
    assert entries[0].image == "python:3.11"
    assert entries[0].stage_name == "builder"
    assert entries[1].image == "python:3.11-slim"
    assert entries[1].stage_name is None


def test_extract_skips_scratch():
    src = "FROM scratch\nFROM alpine:3\n"
    entries = extract_from_lines(src)
    images = [e.image for e in entries]
    assert images == ["alpine:3"]


def test_extract_skips_intra_stage_reuse():
    """``FROM builder`` after a ``FROM x AS builder`` is intra-
    Dockerfile reuse, not a registry pull. Skipped — the base
    image was already scanned via the AS stage's own FROM."""
    src = (
        "FROM debian:11 AS builder\n"
        "RUN echo build\n"
        "FROM builder\n"
        "RUN echo also-build\n"
    )
    entries = extract_from_lines(src)
    images = [e.image for e in entries]
    assert images == ["debian:11"]


def test_extract_no_from_returns_empty():
    """A Dockerfile-shaped file with no FROM (e.g. a fragment
    being included via a frontend) shouldn't crash."""
    src = "RUN echo hi\nCOPY . /app\n"
    assert extract_from_lines(src) == []


# ---------------------------------------------------------------------------
# fetch_image_sbom
# ---------------------------------------------------------------------------


def test_fetch_single_platform_manifest_with_dpkg(tmp_path):
    """Single-platform manifest pointing at one layer that
    contains a dpkg status file."""
    dpkg_status = (
        "Package: zlib1g\n"
        "Status: install ok installed\n"
        "Version: 1:1.2.13.dfsg-1\n"
        "Architecture: amd64\n"
        "\n"
        "Package: openssl\n"
        "Status: install ok installed\n"
        "Version: 3.0.11-1~deb12u2\n"
        "\n"
    ).encode()
    layer_blob = _make_layer_blob({"var/lib/dpkg/status": dpkg_status})
    layer_digest = "sha256:" + "a" * 64

    manifest = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _make_client(
        manifests={"11": manifest},
        blobs={layer_digest: layer_blob},
    )

    sbom = fetch_image_sbom("debian:11", client=client)
    assert sbom is not None
    names = {p.name for p in sbom.packages}
    assert names == {"zlib1g", "openssl"}
    assert all(p.ecosystem == "Debian" for p in sbom.packages)


def test_fetch_image_index_picks_linux_amd64():
    """Multi-arch image: index → pick linux/amd64 → fetch sub-
    manifest → fetch layers."""
    layer_blob = _make_layer_blob({
        "lib/apk/db/installed": b"P:musl\nV:1.2.4-r2\n\n",
    })
    layer_digest = "sha256:" + "a" * 64
    sub_digest = "sha256:" + "s" * 64

    index = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:" + "x" * 64,
                 "mediaType":
                     "application/vnd.oci.image.manifest.v1+json",
                 "platform": {"os": "linux", "architecture": "arm64"}},
                {"digest": sub_digest,
                 "mediaType":
                     "application/vnd.oci.image.manifest.v1+json",
                 "platform": {"os": "linux", "architecture": "amd64"}},
            ],
        },
        content_type="application/vnd.oci.image.index.v1+json",
        digest="sha256:" + "i" * 64,
    )
    sub = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest=sub_digest,
    )
    client = _make_client(
        manifests={"3.18": index, sub_digest: sub},
        blobs={layer_digest: layer_blob},
    )

    sbom = fetch_image_sbom("alpine:3.18", client=client)
    assert sbom is not None
    names = {p.name for p in sbom.packages}
    assert "musl" in names
    # Caller asked for linux/amd64 (the default) — must have
    # selected the correct sub-manifest.
    assert sbom.digest == sub_digest


def test_fetch_returns_none_on_manifest_error():
    """Network errors / HTTP 5xx surface as None, not as a
    crash."""
    client = MagicMock()
    client.fetch_manifest.side_effect = RuntimeError("boom")
    sbom = fetch_image_sbom("debian:11", client=client)
    assert sbom is None


def test_find_dockerfiles_excludes_test_ci_parents(tmp_path: Path):
    """Dockerfiles under test/ ci/ tests/ fixtures/ examples/ etc.
    parents are skipped — they're integration-test setup or CI
    infrastructure, not the project's runtime image. Caught the
    spring-boot-2.1 ``ci/images/...-ci-image/Dockerfile`` family
    that referenced long-purged JDK early-access tags."""
    from packages.sca.dockerfile_from import find_dockerfiles
    # Production Dockerfile (kept)
    (tmp_path / "Dockerfile").write_text("FROM alpine:3.18\n")
    # Test-fixture Dockerfile (skipped)
    fix_dir = tmp_path / "tests" / "integration"
    fix_dir.mkdir(parents=True)
    (fix_dir / "Dockerfile").write_text("FROM ubuntu:22.04\n")
    # CI infrastructure Dockerfile (skipped)
    ci_dir = tmp_path / "ci" / "images" / "build-image"
    ci_dir.mkdir(parents=True)
    (ci_dir / "Dockerfile").write_text("FROM openjdk:8u181-jdk\n")
    # Examples (skipped)
    ex_dir = tmp_path / "examples" / "tutorial"
    ex_dir.mkdir(parents=True)
    (ex_dir / "Dockerfile").write_text("FROM python:3.6-slim\n")

    found = find_dockerfiles(tmp_path)
    found_names = {p.parent.name + "/" + p.name for p in found}
    assert found_names == {tmp_path.name + "/Dockerfile"}, (
        f"expected only the root Dockerfile, got: {found_names}"
    )


def test_fetch_tag_digest_cache_skips_network_on_rerun(tmp_path: Path):
    """Once ``ubuntu:24.04 → sha256:abc...`` is cached, a re-scan
    must skip the manifest+platform-drill HTTP round-trips entirely
    and return the cached SBOM directly. TTL_FOREVER so CI loops
    that scan the same Dockerfile every build save the OCI fetch
    cost on the second build onwards."""
    from core.json.cache import JsonCache
    cache = JsonCache(root=tmp_path)

    # First call: real fetch + extract. Use the existing fixture
    # plumbing for a single-platform manifest with a dpkg layer.
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            b"Package: alpine-base\nVersion: 3.18.0\n"
            b"Status: install ok installed\n"
        ),
    })
    layer_digest = "sha256:" + "1" * 64
    target_digest = "sha256:" + "9" * 64
    manifest = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest=target_digest,
    )
    client = _make_client(
        manifests={"24.04": manifest, target_digest: manifest},
        blobs={layer_digest: layer_blob},
    )
    sbom1 = fetch_image_sbom(
        "ubuntu:24.04", client=client, disk_cache=cache,
    )
    assert sbom1 is not None
    first_call_count = client.fetch_manifest.call_count

    # Second call: must skip the manifest fetch entirely — both
    # the tag → digest and SBOM-by-digest caches are warm.
    sbom2 = fetch_image_sbom(
        "ubuntu:24.04", client=client, disk_cache=cache,
    )
    assert sbom2 is not None
    assert sbom2.digest == target_digest
    assert sbom2.packages == sbom1.packages
    # No new fetch_manifest invocations.
    assert client.fetch_manifest.call_count == first_call_count, (
        "tag → digest + SBOM-by-digest caches must short-circuit "
        "all network calls on re-scan"
    )


def test_fetch_negative_caches_failed_lookups(tmp_path: Path):
    """Once a manifest fetch fails, subsequent fetches for the same
    image ref must short-circuit on the disk cache rather than
    repeating the full auth-dance + retry budget. Saves ~15-20s per
    deleted-tag Dockerfile FROM (e.g. spring-boot-2.1's openjdk
    early-access tags purged from Docker Hub) on every re-scan."""
    from core.json.cache import JsonCache
    cache = JsonCache(root=tmp_path)
    client = MagicMock()
    client.fetch_manifest.side_effect = RuntimeError("404 not found")

    # First call: actually invokes the client, fails.
    sbom1 = fetch_image_sbom(
        "openjdk:11-ea-28-jdk", client=client, disk_cache=cache,
    )
    assert sbom1 is None
    assert client.fetch_manifest.call_count == 1

    # Second call: must hit the negative cache and NOT re-invoke
    # the client.
    sbom2 = fetch_image_sbom(
        "openjdk:11-ea-28-jdk", client=client, disk_cache=cache,
    )
    assert sbom2 is None
    assert client.fetch_manifest.call_count == 1, (
        "negative cache must short-circuit the client call"
    )

    # A DIFFERENT image ref (one that hasn't failed) must still
    # invoke the client — the negative cache is keyed per-ref.
    fetch_image_sbom(
        "alpine:3.18", client=client, disk_cache=cache,
    )
    assert client.fetch_manifest.call_count == 2


def test_fetch_returns_none_on_unknown_media_type():
    """A manifest with an unrecognised media type — bail rather
    than guess."""
    weird = FakeManifestResp(
        parsed={"mediaType": "application/x-unknown"},
        content_type="application/x-unknown",
        digest="sha256:" + "z" * 64,
    )
    client = _make_client(manifests={"11": weird}, blobs={})
    sbom = fetch_image_sbom("debian:11", client=client)
    assert sbom is None


def test_fetch_index_with_no_amd64_returns_none():
    """An image whose only platforms are foreign archs and the
    caller didn't override platform — expected behaviour: skip."""
    index = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {"digest": "sha256:" + "x" * 64,
                 "mediaType":
                     "application/vnd.oci.image.manifest.v1+json",
                 "platform": {"os": "windows", "architecture": "amd64"}},
            ],
        },
        content_type="application/vnd.oci.image.index.v1+json",
        digest="sha256:" + "i" * 64,
    )
    client = _make_client(manifests={"latest": index}, blobs={})
    sbom = fetch_image_sbom("foo/win:latest", client=client)
    assert sbom is None


# ---------------------------------------------------------------------------
# packages_to_dependencies
# ---------------------------------------------------------------------------


def test_packages_to_deps_emits_correct_shape():
    from core.oci.sbom import InstalledPackage
    pkgs = [
        InstalledPackage(ecosystem="Debian", name="zlib1g",
                         version="1:1.2.13.dfsg-1"),
        InstalledPackage(ecosystem="Alpine", name="musl",
                         version="1.2.4-r2"),
    ]
    deps = packages_to_dependencies(
        pkgs, declared_in=Path("Dockerfile"),
    )
    assert len(deps) == 2
    assert all(d.source_kind == "dockerfile_from" for d in deps)
    assert all(d.is_lockfile for d in deps)
    assert all(d.pin_style == PinStyle.EXACT for d in deps)
    assert all(d.parser_confidence.level == "high" for d in deps)
    assert {d.purl for d in deps} == {
        "pkg:deb/zlib1g@1:1.2.13.dfsg-1",
        "pkg:apk/musl@1.2.4-r2",
    }


def test_packages_with_missing_version_skipped():
    from core.oci.sbom import InstalledPackage
    pkgs = [
        InstalledPackage(ecosystem="Debian", name="ok",
                         version="1.0"),
        InstalledPackage(ecosystem="Debian", name="broken",
                         version=""),
    ]
    deps = packages_to_dependencies(
        pkgs, declared_in=Path("Dockerfile"),
    )
    assert len(deps) == 1
    assert deps[0].name == "ok"


# ---------------------------------------------------------------------------
# scan_dockerfiles — end-to-end
# ---------------------------------------------------------------------------


def test_scan_dockerfiles_end_to_end(tmp_path):
    (tmp_path / "Dockerfile").write_text(
        "FROM debian:11\n"
        "RUN apt-get update\n"
    )
    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: openssl\n"
            "Status: install ok installed\n"
            "Version: 3.0.11-1~deb12u2\n"
            "\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _make_client(
        manifests={"11": manifest},
        blobs={layer_digest: layer_blob},
    )

    deps = scan_dockerfiles(tmp_path, client=client)
    assert len(deps) == 1
    assert deps[0].name == "openssl"
    assert deps[0].source_kind == "dockerfile_from"
    assert deps[0].declared_in.name == "Dockerfile"


def test_scan_dockerfiles_returns_empty_when_no_dockerfiles(tmp_path):
    """No Dockerfiles → empty list, never tries the client."""
    client = MagicMock()
    deps = scan_dockerfiles(tmp_path, client=client)
    assert deps == []
    client.fetch_manifest.assert_not_called()


def test_scan_dockerfiles_continues_after_image_failure(tmp_path):
    """One Dockerfile FROM fails (registry unreachable); the
    other still produces deps."""
    (tmp_path / "Dockerfile.bad").write_text("FROM doesnotexist:1\n")
    (tmp_path / "Dockerfile.good").write_text("FROM debian:11\n")

    layer_blob = _make_layer_blob({
        "var/lib/dpkg/status": (
            "Package: ok\nStatus: install ok installed\n"
            "Version: 1.0\n\n"
        ).encode(),
    })
    layer_digest = "sha256:" + "a" * 64
    good = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = MagicMock()

    def _fetch(ref, *, reference=None):
        if ref.repository.endswith("doesnotexist"):
            raise RuntimeError("404")
        return good

    def _blob(ref, digest, **_):
        return _chunk(layer_blob)

    client.fetch_manifest.side_effect = _fetch
    client.stream_blob.side_effect = _blob

    deps = scan_dockerfiles(tmp_path, client=client)
    assert len(deps) == 1
    assert deps[0].name == "ok"


def test_scan_dockerfiles_distroless_yields_no_deps(tmp_path):
    """An image with no recognised package db (e.g. distroless)
    is fetched, scanned, and returns no Deps. Not an error —
    just no findings to emit."""
    (tmp_path / "Dockerfile").write_text("FROM gcr.io/distroless/static\n")
    layer_blob = _make_layer_blob({
        "etc/passwd": b"root:x:0:0::/root:/bin/sh\n",
    })
    layer_digest = "sha256:" + "a" * 64
    manifest = FakeManifestResp(
        parsed={
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"digest": "sha256:" + "c" * 64},
            "layers": [{
                "digest": layer_digest, "size": len(layer_blob),
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
            }],
        },
        content_type="application/vnd.oci.image.manifest.v1+json",
        digest="sha256:" + "m" * 64,
    )
    client = _make_client(
        manifests={"latest": manifest},
        blobs={layer_digest: layer_blob},
    )
    deps = scan_dockerfiles(tmp_path, client=client)
    assert deps == []


# ---------------------------------------------------------------------------
# _is_unresolvable_image_ref — pre-fetch filter (istio-1.4 perf fix)
# ---------------------------------------------------------------------------


def test_unresolvable_image_helm_template():
    from packages.sca.dockerfile_from import _is_unresolvable_image_ref
    assert _is_unresolvable_image_ref("{{ .Values.global.hub }}")
    assert _is_unresolvable_image_ref("{{$.Values.image}}")
    assert _is_unresolvable_image_ref(
        "{{ .Values.image.repository }}:{{ .Values.image.tag }}"
    )


def test_unresolvable_image_env_substitution():
    from packages.sca.dockerfile_from import _is_unresolvable_image_ref
    assert _is_unresolvable_image_ref("${IMAGE}")
    assert _is_unresolvable_image_ref(
        "docker.io/istio/base:${BASE_VERSION}"
    )


def test_unresolvable_image_test_stub_hosts():
    from packages.sca.dockerfile_from import _is_unresolvable_image_ref
    assert _is_unresolvable_image_ref("fake.docker.io/repo:tag")
    assert _is_unresolvable_image_ref("example.com/myimage:1.0")
    assert _is_unresolvable_image_ref("FAKE.DOCKER.IO/x")


def test_unresolvable_image_empty_or_whitespace():
    from packages.sca.dockerfile_from import _is_unresolvable_image_ref
    assert _is_unresolvable_image_ref("")
    assert _is_unresolvable_image_ref("   ")
    assert _is_unresolvable_image_ref(None)  # type: ignore[arg-type]


def test_resolvable_image_real_refs():
    """Real registry refs must NOT be flagged unresolvable."""
    from packages.sca.dockerfile_from import _is_unresolvable_image_ref
    for img in [
        "alpine",
        "alpine:3.18",
        "docker.io/library/postgres:16",
        "gcr.io/distroless/static:latest",
        "registry.k8s.io/pause:3.9",
        "ghcr.io/owner/repo:v1.2",
    ]:
        assert not _is_unresolvable_image_ref(img), img


def test_scan_image_sources_skips_unresolvable_refs(tmp_path):
    """Helm-template + ${VAR} + test-stub-host refs must NOT reach
    the OCI client. This is the istio-1.4 perf fix — 16+ Helm
    placeholders in istio's deployment YAMLs were generating
    retry-storm 401/429s against docker.io."""
    (tmp_path / "deploy.yaml").write_text(
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata: {name: x}\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      containers:\n"
        "        - name: a\n"
        "          image: '{{ .Values.global.hub }}/x:latest'\n"
        "        - name: b\n"
        "          image: docker.io/istio/proxy:${VERSION}\n"
        "        - name: c\n"
        "          image: fake.docker.io/test:tag\n"
    )
    fetched: list = []

    class _RecordingClient:
        def fetch_manifest(self, ref, reference=None):
            fetched.append(ref)
            raise AssertionError(
                f"OCI client must not be invoked for {ref!r}"
            )

    from packages.sca.dockerfile_from import scan_image_sources
    deps = scan_image_sources(tmp_path, client=_RecordingClient())
    assert deps == []
    assert fetched == [], (
        f"OCI client invoked for filtered refs: {fetched}"
    )


# ---------------------------------------------------------------------------
# Malformed @-tag refs (image@<tag> instead of image:<tag>)
# ---------------------------------------------------------------------------

def test_at_tag_ref_demoted_to_debug(tmp_path: Path, caplog) -> None:
    """``bitnami/kafka@3.7.0`` is a common operator typo: ``@`` was
    used in place of ``:`` for the tag separator. The parser
    correctly rejects it (digest must be ``<algorithm>:<hex>``), but
    the dockerfile_from scanner should log at DEBUG level — not
    WARNING — because it's noise from upstream-authored files the
    operator may not control (vendored compose / helm-rendered YAML).

    Surfaced by the May 2026 200-project sweep: one project emitted
    multiple WARN-level lines for this exact pattern.
    """
    import logging
    from packages.sca.dockerfile_from import fetch_image_sbom

    class _UnusedClient:
        def fetch_manifest(self, ref, reference=None):
            raise AssertionError("client must not be invoked")

    with caplog.at_level(logging.WARNING):
        out = fetch_image_sbom(
            "index.docker.io/bitnami/kafka@3.7.0",
            client=_UnusedClient(),
        )
    assert out is None
    warning_records = [
        r for r in caplog.records
        if r.levelno >= logging.WARNING
        and "cannot parse image ref" in r.getMessage()
    ]
    assert warning_records == [], (
        f"@<tag> noise should be at DEBUG, not WARNING; got "
        f"{[r.getMessage() for r in warning_records]}"
    )

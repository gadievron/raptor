"""Tests for ``packages.sca.bump.image_binary_extract``.

The extractor pulls one binary out of an OCI image. Tests use a
stub ``OciRegistryClient`` so they don't require network /
registry access. The full flow exercised:

  * manifest fetch (single-platform vs image-index drill)
  * config blob parse (Entrypoint / Cmd resolution)
  * layer streaming (mocked gzipped-tar bytes)
  * extracted-bytes round-trip to a tempfile

Each stage has a failure-mode test asserting the extractor
returns ``None`` rather than crashing.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from core.oci.manifest import IndexEntry
from packages.sca.bump.image_binary_extract import (
    _resolve_entrypoint_path,
    _select_platform,
    fetch_image_binary,
)

# ---------------------------------------------------------------------------
# Stub OCI client
# ---------------------------------------------------------------------------


@dataclass
class _StubResp:
    parsed: dict[str, Any]
    content_type: str
    digest: str | None = None
    raw: bytes = b""


class _StubClient:
    """Minimal OciRegistryClient stand-in.

    ``manifests`` maps ``"<repository>:<reference>"`` keys to
    ``_StubResp`` instances; the ``ref`` plus optional
    ``reference`` override produces the key.

    ``blobs`` maps digest keys to iterables of byte chunks. Used
    for both config-blob fetches (JSON bytes) and layer streams
    (gzipped tar bytes).
    """

    def __init__(self):
        self.manifests: dict[str, _StubResp] = {}
        self.blobs: dict[str, bytes] = {}
        self.calls: list[str] = []  # diagnostics

    def fetch_manifest(self, ref, *, reference=None):
        key = f"{ref.repository}:{reference or ref.reference}"
        self.calls.append(f"manifest:{key}")
        if key not in self.manifests:
            from core.oci.client import RegistryError
            raise RegistryError(404, f"no stub for {key}")
        return self.manifests[key]

    def stream_blob(self, ref, digest) -> Iterable[bytes]:
        self.calls.append(f"blob:{digest}")
        if digest not in self.blobs:
            raise RuntimeError(f"no blob stub for {digest}")
        return [self.blobs[digest]]


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_layer_tar(files: dict[str, bytes]) -> bytes:
    """Build a gzipped tar with the supplied (path, content)
    entries. Matches the layer format ``extract_files_from_layer``
    expects."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz, \
            tarfile.open(fileobj=gz, mode="w") as tar:
        for path, content in files.items():
            info = tarfile.TarInfo(name=path)
            info.size = len(content)
            tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_manifest_resp(config_digest: str, layers: list[dict]) -> _StubResp:
    return _StubResp(
        parsed={
            "mediaType":
                "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": config_digest, "size": 1000,
            },
            "layers": layers,
        },
        content_type=(
            "application/vnd.docker.distribution.manifest.v2+json"
        ),
        digest="sha256:fakeManifestDigest",
    )


def _make_config_blob(entrypoint: list[str] | None = None,
                      cmd: list[str] | None = None) -> bytes:
    config: dict[str, Any] = {"config": {}}
    if entrypoint is not None:
        config["config"]["Entrypoint"] = entrypoint
    if cmd is not None:
        config["config"]["Cmd"] = cmd
    return json.dumps(config).encode("utf-8")


# ---------------------------------------------------------------------------
# _select_platform
# ---------------------------------------------------------------------------


class TestSelectPlatform:
    def test_picks_matching_os_arch(self):
        entries = [
            IndexEntry(digest="sha256:a", size=1, media_type="m",
                       os="linux", architecture="arm64", variant="v8"),
            IndexEntry(digest="sha256:b", size=1, media_type="m",
                       os="linux", architecture="amd64", variant=None),
        ]
        pick = _select_platform(entries, "linux", "amd64")
        assert pick is not None and pick.digest == "sha256:b"

    def test_no_match_returns_none(self):
        entries = [
            IndexEntry(digest="sha256:a", size=1, media_type="m",
                       os="linux", architecture="arm64", variant=None),
        ]
        assert _select_platform(entries, "linux", "amd64") is None


# ---------------------------------------------------------------------------
# _resolve_entrypoint_path
# ---------------------------------------------------------------------------


class TestResolveEntrypointPath:
    def test_entrypoint_absolute_path_wins(self):
        client = _StubClient()
        client.blobs["sha256:cfg"] = _make_config_blob(
            entrypoint=["/usr/bin/foo", "--flag"],
            cmd=["--default"],
        )
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        path = _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:cfg",
        )
        assert path == "/usr/bin/foo"

    def test_falls_back_to_cmd(self):
        """No Entrypoint → use Cmd."""
        client = _StubClient()
        client.blobs["sha256:cfg"] = _make_config_blob(
            cmd=["/bin/server"],
        )
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        assert _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:cfg",
        ) == "/bin/server"

    def test_relative_paths_skipped(self):
        """``["foo", "--bar"]`` is a relative-name entrypoint —
        we don't try to resolve via PATH. Returns None."""
        client = _StubClient()
        client.blobs["sha256:cfg"] = _make_config_blob(
            entrypoint=["foo", "--bar"],
            cmd=["baz"],
        )
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        assert _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:cfg",
        ) is None

    def test_blob_fetch_failure_returns_none(self):
        client = _StubClient()
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        # No blob stubbed → stream_blob raises
        assert _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:missing",
        ) is None

    def test_malformed_json_returns_none(self):
        client = _StubClient()
        client.blobs["sha256:bad"] = b"not json {"
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        assert _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:bad",
        ) is None

    def test_oversize_config_blob_refused_without_buffering(self):
        """A hostile / compromised registry serving a huge "config"
        blob (real ones are a few KB) must degrade to None at the
        cap — pre-fix the only bound was the client's 2 GiB LAYER
        budget and the blob was fully buffered twice (join + decoded
        copy) per image ref."""
        from packages.sca.bump.image_binary_extract import (
            _MAX_CONFIG_BLOB_BYTES,
        )

        consumed = {"chunks": 0}
        chunk = b"A" * (1024 * 1024)

        class _FloodClient:
            def stream_blob(self, ref, digest):
                for _ in range(64):
                    consumed["chunks"] += 1
                    yield chunk

        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        assert _resolve_entrypoint_path(
            client=_FloodClient(), ref=ref,
            config_digest="sha256:flood",
        ) is None
        # The stream stops at the cap — the flood is never drained.
        cap_chunks = _MAX_CONFIG_BLOB_BYTES // len(chunk)
        assert consumed["chunks"] <= cap_chunks + 1

    def test_no_config_block_returns_none(self):
        client = _StubClient()
        client.blobs["sha256:cfg"] = json.dumps({"other": "data"}).encode()
        from core.oci.image_ref import parse_image_ref
        ref = parse_image_ref("docker.io/library/test:1")
        assert _resolve_entrypoint_path(
            client=client, ref=ref, config_digest="sha256:cfg",
        ) is None


# ---------------------------------------------------------------------------
# fetch_image_binary — end-to-end
# ---------------------------------------------------------------------------


class TestFetchImageBinary:
    def test_single_layer_extraction(self, tmp_path):
        """Image with one layer containing the entrypoint binary
        → extracted to a local file with the expected bytes."""
        client = _StubClient()
        binary_bytes = b"\x7fELF" + b"x" * 200
        layer_bytes = _make_layer_tar({"usr/bin/foo": binary_bytes})
        client.blobs["sha256:layer1"] = layer_bytes
        client.blobs["sha256:cfg"] = _make_config_blob(
            entrypoint=["/usr/bin/foo"],
        )
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer_bytes),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )

        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            out_dir=tmp_path,
        )
        assert out is not None
        assert out.parent == tmp_path
        assert out.read_bytes() == binary_bytes

    def test_explicit_binary_path_overrides_entrypoint(self, tmp_path):
        """Caller-supplied ``binary_path`` bypasses entrypoint
        detection. Lets operators target a non-entrypoint binary
        when the image's entrypoint is a shell wrapper."""
        client = _StubClient()
        layer = _make_layer_tar({"usr/local/bin/server": b"server-bytes"})
        client.blobs["sha256:layer1"] = layer
        # config_blob never gets read because binary_path is supplied
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/local/bin/server",
            out_dir=tmp_path,
        )
        assert out is not None
        assert out.read_bytes() == b"server-bytes"

    def test_later_layer_overrides_earlier(self, tmp_path):
        """``/usr/bin/foo`` in layer 1 overwritten by layer 2 →
        final file is layer 2's content (overlay-fs semantics)."""
        client = _StubClient()
        layer1 = _make_layer_tar({"usr/bin/foo": b"old-version"})
        layer2 = _make_layer_tar({"usr/bin/foo": b"new-version"})
        client.blobs["sha256:layer1"] = layer1
        client.blobs["sha256:layer2"] = layer2
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[
                {"digest": "sha256:layer1", "size": len(layer1),
                 "mediaType": "application/vnd.docker.image."
                              "rootfs.diff.tar.gzip"},
                {"digest": "sha256:layer2", "size": len(layer2),
                 "mediaType": "application/vnd.docker.image."
                              "rootfs.diff.tar.gzip"},
            ],
        )
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
        )
        assert out is not None
        assert out.read_bytes() == b"new-version"

    def test_binary_not_in_any_layer_returns_none(self, tmp_path):
        client = _StubClient()
        layer = _make_layer_tar({"etc/passwd": b"unrelated"})
        client.blobs["sha256:layer1"] = layer
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
        )
        assert out is None

    def test_manifest_fetch_failure_returns_none(self, tmp_path):
        client = _StubClient()
        # No manifest registered → fetch_manifest raises
        assert fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
        ) is None

    def test_unparseable_image_ref_returns_none(self, tmp_path):
        client = _StubClient()
        # Garbage ref → parse_image_ref raises
        assert fetch_image_binary(
            "::::::not-a-ref::::", client=client, out_dir=tmp_path,
        ) is None

    def test_entrypoint_resolution_failure_returns_none(self, tmp_path):
        """Image with no Entrypoint / Cmd absolute paths → can't
        decide which binary to extract → returns None."""
        client = _StubClient()
        client.blobs["sha256:cfg"] = _make_config_blob(
            entrypoint=["foo"], cmd=["bar"],   # both relative
        )
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg", layers=[],
        )
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            out_dir=tmp_path,
        )
        assert out is None

    def test_oversized_layers_skipped(self, tmp_path):
        """Layer above ``max_layer_bytes`` is skipped — small cap
        in the test lets us simulate the trip without actually
        building a huge layer."""
        client = _StubClient()
        layer = _make_layer_tar({"usr/bin/foo": b"x"})
        client.blobs["sha256:layer1"] = layer
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": 999_999_999,
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        # max_layer_bytes set below the (faked) reported size →
        # layer skipped → binary not found → None
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
            max_layer_bytes=1024,
        )
        assert out is None

    def test_output_filename_derived_from_content_hash(self, tmp_path):
        """Two different binary versions reusing the same out_dir
        produce different filenames (content-hash-prefixed). The
        registry-supplied manifest digest never feeds the name."""
        import hashlib

        client = _StubClient()
        layer = _make_layer_tar({"usr/bin/foo": b"data"})
        client.blobs["sha256:layer1"] = layer
        mr = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        mr.digest = "sha256:abc123"
        client.manifests["library/test:1"] = mr
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
        )
        assert out is not None
        expected = hashlib.sha256(b"data").hexdigest()[:32]
        assert out.name == f"{expected}-foo"
        assert "abc123" not in out.name

    def test_output_filename_independent_of_hostile_digest(self, tmp_path):
        """A crafted manifest digest carrying ``/`` and ``..`` must
        never influence the written path — the file lands inside
        out_dir under a content-hash name."""
        client = _StubClient()
        layer = _make_layer_tar({"usr/bin/foo": b"payload"})
        client.blobs["sha256:layer1"] = layer
        mr = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        mr.digest = "sha256:../../../../tmp/evil"
        client.manifests["library/test:1"] = mr
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/usr/bin/foo", out_dir=tmp_path,
        )
        assert out is not None
        assert out.parent == tmp_path
        assert ".." not in out.name and "/" not in out.name
        assert out.read_bytes() == b"payload"

    def test_output_basename_sanitised(self, tmp_path):
        """Basename characters outside ``[A-Za-z0-9._-]`` are replaced
        and the component is length-capped."""
        client = _StubClient()
        weird = "usr/bin/we ird$name" + "x" * 100
        layer = _make_layer_tar({weird: b"bin"})
        client.blobs["sha256:layer1"] = layer
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client,
            binary_path="/" + weird, out_dir=tmp_path,
        )
        assert out is not None
        assert out.parent == tmp_path
        basename = out.name.split("-", 1)[1]
        assert all(
            c.isalnum() or c in "._-" for c in basename
        ), f"unsanitised char in {basename!r}"
        assert len(basename) <= 64


# ---------------------------------------------------------------------------
# Shared-tempdir hardening: owned dir, O_EXCL writes, cleanup
# ---------------------------------------------------------------------------

def _stub_client_with_binary(binary_bytes: bytes) -> "_StubClient":
    client = _StubClient()
    layer_bytes = _make_layer_tar({"usr/bin/foo": binary_bytes})
    client.blobs["sha256:layer1"] = layer_bytes
    client.blobs["sha256:cfg"] = _make_config_blob(
        entrypoint=["/usr/bin/foo"],
    )
    client.manifests["library/test:1"] = _make_manifest_resp(
        config_digest="sha256:cfg",
        layers=[{
            "digest": "sha256:layer1", "size": len(layer_bytes),
            "mediaType":
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
        }],
    )
    return client


class TestSharedTempdirHardening:
    def test_default_out_dir_is_private_per_extraction(self) -> None:
        """No out_dir → the file must NOT land directly in the shared
        system tempdir (predictable name, multi-user host): it goes
        in a fresh mode-0700 directory owned by us."""
        import os
        import stat
        import tempfile
        from pathlib import Path

        from packages.sca.bump.image_binary_extract import (
            cleanup_extracted_binary,
        )
        client = _stub_client_with_binary(b"\x7fELF" + b"y" * 64)
        out = fetch_image_binary("docker.io/library/test:1", client=client)
        try:
            assert out is not None
            assert out.parent != Path(tempfile.gettempdir())
            assert out.parent.name.startswith("raptor-sca-bump-")
            mode = stat.S_IMODE(out.parent.stat().st_mode)
            assert mode & 0o077 == 0, oct(mode)
            assert out.parent.stat().st_uid == os.getuid()
        finally:
            cleanup_extracted_binary(out)
        assert out is not None and not out.exists()
        assert not out.parent.exists()

    def test_pre_created_plant_is_not_truncated_or_followed(
        self, tmp_path,
    ) -> None:
        """An attacker pre-creating the predicted content-hash name in
        a shared out_dir must not win: the extractor refuses to reuse
        a file whose bytes differ (O_EXCL — no truncate-over, no
        follow), so the plant can never become the diffed binary."""
        import hashlib

        binary_bytes = b"\x7fELF" + b"z" * 64
        content_hash = hashlib.sha256(binary_bytes).hexdigest()[:32]
        plant = tmp_path / f"{content_hash}-foo"
        plant.write_bytes(b"ATTACKER")

        client = _stub_client_with_binary(binary_bytes)
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client, out_dir=tmp_path,
        )
        # Refused (plant bytes differ) — never silently overwritten,
        # never returned as if it were our extraction.
        assert out is None
        assert plant.read_bytes() == b"ATTACKER"

    def test_symlink_plant_is_refused(self, tmp_path) -> None:
        import hashlib

        binary_bytes = b"\x7fELF" + b"w" * 64
        content_hash = hashlib.sha256(binary_bytes).hexdigest()[:32]
        victim = tmp_path / "victim"
        victim.write_bytes(b"precious")
        (tmp_path / f"{content_hash}-foo").symlink_to(victim)

        client = _stub_client_with_binary(binary_bytes)
        out = fetch_image_binary(
            "docker.io/library/test:1", client=client, out_dir=tmp_path,
        )
        assert out is None
        assert victim.read_bytes() == b"precious"

    def test_own_identical_extraction_is_reused(self, tmp_path) -> None:
        """Idempotent re-run against the same operator out_dir: our
        own earlier extraction (same bytes, our uid, tight mode) is
        reused rather than erroring."""
        client = _stub_client_with_binary(b"\x7fELF" + b"v" * 64)
        first = fetch_image_binary(
            "docker.io/library/test:1", client=client, out_dir=tmp_path,
        )
        assert first is not None
        second = fetch_image_binary(
            "docker.io/library/test:1",
            client=_stub_client_with_binary(b"\x7fELF" + b"v" * 64),
            out_dir=tmp_path,
        )
        assert second == first


class TestOwnedDirFailureCleanup:
    def test_write_failure_removes_owned_dir(self, monkeypatch,
                                             tmp_path):
        """out_dir=None mode creates an owned mkdtemp dir; when the
        subsequent write fails (ENOSPC-class OSError) the caller
        gets None and never receives a path to hand to
        cleanup_extracted_binary — the dir must be removed on the
        failure path, or one empty dir leaks per failed
        extraction."""
        import packages.sca.bump.image_binary_extract as mod

        client = _StubClient()
        binary_bytes = b"\x7fELF" + b"x" * 200
        layer_bytes = _make_layer_tar({"usr/bin/foo": binary_bytes})
        client.blobs["sha256:layer1"] = layer_bytes
        client.blobs["sha256:cfg"] = _make_config_blob(
            entrypoint=["/usr/bin/foo"],
        )
        client.manifests["library/test:1"] = _make_manifest_resp(
            config_digest="sha256:cfg",
            layers=[{
                "digest": "sha256:layer1", "size": len(layer_bytes),
                "mediaType":
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
            }],
        )

        created: list[str] = []
        real_mkdtemp = mod.tempfile.mkdtemp

        def _tracking_mkdtemp(*a, **kw):
            d = real_mkdtemp(*a, dir=str(tmp_path), **kw)
            created.append(d)
            return d

        def _failing_open(*a, **kw):
            raise OSError(28, "No space left on device")

        monkeypatch.setattr(mod.tempfile, "mkdtemp",
                            _tracking_mkdtemp)
        monkeypatch.setattr(mod.os, "open", _failing_open)

        out = fetch_image_binary(
            "docker.io/library/test:1", client=client, out_dir=None,
        )
        assert out is None
        assert len(created) == 1
        from pathlib import Path as _P
        assert not _P(created[0]).exists()   # no leaked owned dir

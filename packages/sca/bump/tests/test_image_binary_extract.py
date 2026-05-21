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
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional


from packages.sca.bump.image_binary_extract import (
    _resolve_entrypoint_path,
    _select_platform,
    fetch_image_binary,
)
from core.oci.manifest import IndexEntry


# ---------------------------------------------------------------------------
# Stub OCI client
# ---------------------------------------------------------------------------


@dataclass
class _StubResp:
    parsed: Dict[str, Any]
    content_type: str
    digest: Optional[str] = None
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
        self.manifests: Dict[str, _StubResp] = {}
        self.blobs: Dict[str, bytes] = {}
        self.calls: List[str] = []  # diagnostics

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


def _make_layer_tar(files: Dict[str, bytes]) -> bytes:
    """Build a gzipped tar with the supplied (path, content)
    entries. Matches the layer format ``extract_files_from_layer``
    expects."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        with tarfile.open(fileobj=gz, mode="w") as tar:
            for path, content in files.items():
                info = tarfile.TarInfo(name=path)
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _make_manifest_resp(config_digest: str, layers: List[Dict]) -> _StubResp:
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


def _make_config_blob(entrypoint: Optional[List[str]] = None,
                      cmd: Optional[List[str]] = None) -> bytes:
    config: Dict[str, Any] = {"config": {}}
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

    def test_output_filename_includes_digest(self, tmp_path):
        """Two different image versions reusing the same out_dir
        produce different filenames (digest-prefixed)."""
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
        assert "sha256_abc123" in out.name
        assert out.name.endswith("foo")

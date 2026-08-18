"""Tests for the client's content-address discipline.

``fetch_manifest`` reports a digest COMPUTED from the response bytes
and cross-checks it against both the ``Docker-Content-Digest`` header
and any digest-shaped reference the caller fetched by; ``stream_blob``
hashes the stream and verifies on exhaustion. These pins keep the
"digest is provably the sha256 of the content stored under it"
invariant that downstream forever-caches and filename derivations
rely on.
"""

from __future__ import annotations

import hashlib
import json

import pytest

from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref


class _StubResponse:
    def __init__(self, status_code: int, body: bytes,
                 headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.content = body
        self.text = body.decode("utf-8", errors="replace")
        self.headers = headers or {}

    def iter_content(self, chunk_size: int = 65536):
        for i in range(0, len(self.content), chunk_size):
            yield self.content[i:i + chunk_size]

    def close(self):
        pass


class _StubHttp:
    def __init__(self, responses: dict[str, _StubResponse]):
        self._responses = responses
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({"method": method, "url": url})
        if url not in self._responses:
            return _StubResponse(404, b'{"errors": []}')
        return self._responses[url]


_MANIFEST = json.dumps({"schemaVersion": 2, "layers": []}).encode()
_MANIFEST_DIGEST = "sha256:" + hashlib.sha256(_MANIFEST).hexdigest()
_URL = "https://ghcr.io/v2/acme/app/manifests/latest"


def _client(headers: dict[str, str] | None = None,
            body: bytes = _MANIFEST,
            url: str = _URL) -> OciRegistryClient:
    return OciRegistryClient(_StubHttp({
        url: _StubResponse(200, body, headers=headers),
    }))


def test_fetch_manifest_digest_is_computed_from_body() -> None:
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    resp = _client(headers={}).fetch_manifest(ref)
    assert resp.digest == _MANIFEST_DIGEST


def test_fetch_manifest_agreeing_header_passes() -> None:
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    resp = _client(
        headers={"Docker-Content-Digest": _MANIFEST_DIGEST},
    ).fetch_manifest(ref)
    assert resp.digest == _MANIFEST_DIGEST


def test_fetch_manifest_disagreeing_header_is_integrity_failure() -> None:
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    lying = "sha256:" + "0" * 64
    with pytest.raises(RegistryError, match="digest mismatch"):
        _client(
            headers={"Docker-Content-Digest": lying},
        ).fetch_manifest(ref)


def test_fetch_manifest_pathological_header_never_becomes_digest() -> None:
    # A header value with path syntax must not surface as the digest
    # consumers key caches / filenames on — the computed value wins.
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    resp = _client(
        headers={"Docker-Content-Digest": "../../../etc/passwd"},
    ).fetch_manifest(ref)
    assert resp.digest == _MANIFEST_DIGEST


def test_fetch_by_digest_verifies_body_against_reference() -> None:
    lying = "sha256:" + "a" * 64
    url = f"https://ghcr.io/v2/acme/app/manifests/{lying}"
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(headers={}, url=url)
    with pytest.raises(RegistryError, match="digest mismatch"):
        client.fetch_manifest(ref, reference=lying)


def test_fetch_by_digest_matching_reference_passes() -> None:
    url = f"https://ghcr.io/v2/acme/app/manifests/{_MANIFEST_DIGEST}"
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(headers={}, url=url)
    resp = client.fetch_manifest(ref, reference=_MANIFEST_DIGEST)
    assert resp.digest == _MANIFEST_DIGEST


def test_resolve_digest_rejects_malformed_header() -> None:
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = OciRegistryClient(_StubHttp({
        _URL: _StubResponse(
            200, b"", headers={"Docker-Content-Digest": "sha256:nothex"},
        ),
    }))
    with pytest.raises(RegistryError, match="malformed"):
        client.resolve_digest(ref)


def test_stream_blob_verifies_on_exhaustion() -> None:
    body = b"layer-bytes"
    good = "sha256:" + hashlib.sha256(body).hexdigest()
    bad = "sha256:" + "b" * 64
    ref = parse_image_ref("ghcr.io/acme/app:latest")

    url_good = f"https://ghcr.io/v2/acme/app/blobs/{good}"
    client = OciRegistryClient(
        _StubHttp({url_good: _StubResponse(200, body)}),
    )
    assert b"".join(client.stream_blob(ref, good)) == body

    url_bad = f"https://ghcr.io/v2/acme/app/blobs/{bad}"
    client = OciRegistryClient(
        _StubHttp({url_bad: _StubResponse(200, body)}),
    )
    with pytest.raises(RegistryError, match="digest mismatch"):
        list(client.stream_blob(ref, bad))


def test_stream_blob_rejects_malformed_digest_before_request() -> None:
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    http = _StubHttp({})
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="malformed"):
        list(client.stream_blob(ref, "sha256:xyz/../../escape"))
    assert http.calls == []  # refused before any URL was built

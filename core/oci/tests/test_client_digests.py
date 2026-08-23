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
        self.calls.append({"method": method, "url": url,
                           "headers": kwargs.get("headers")})
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


def test_fetch_by_non_sha256_pin_refused_before_request() -> None:
    """A digest-shaped reference in an algorithm the client cannot
    verify (e.g. supplied by a hostile image index) must be refused
    BEFORE any fetch — pre-fix it was fetched and returned with no
    content authentication at all."""
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    sha512_pin = "sha512:" + "a" * 128
    http = _StubHttp({
        f"https://ghcr.io/v2/acme/app/manifests/{sha512_pin}":
            _StubResponse(200, _MANIFEST),
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="sha256"):
        client.fetch_manifest(ref, reference=sha512_pin)
    assert http.calls == []     # refused before any URL was fetched


def test_ref_pinned_with_non_sha256_digest_refused() -> None:
    """Defence in depth for a hand-constructed ImageRef that bypassed
    parse_image_ref's algorithm gate."""
    from core.oci.image_ref import ImageRef
    md5_pin = "md5:" + "b" * 32
    ref = ImageRef(registry="ghcr.io", repository="acme/app",
                   tag=None, digest=md5_pin)
    http = _StubHttp({
        f"https://ghcr.io/v2/acme/app/manifests/{md5_pin}":
            _StubResponse(200, _MANIFEST),
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="sha256"):
        client.fetch_manifest(ref)
    assert http.calls == []


def test_deeply_nested_manifest_json_raises_registry_error() -> None:
    """Registry JSON is attacker-shaped: nesting deep enough to blow
    the parser's recursion limit must surface as RegistryError, not
    an unhandled RecursionError crash."""
    depth = 100_000
    bomb = b"[" * depth + b"]" * depth
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(headers={}, body=bomb)
    with pytest.raises(RegistryError, match="parse failed"):
        client.fetch_manifest(ref)


def test_digest_mismatch_beats_parsing() -> None:
    """Bytes failing the digest cross-check are never fed to the
    JSON parser: the mismatch (integrity) error must win over the
    parse (shape) error even when the body is a parser bomb."""
    depth = 100_000
    bomb = b"[" * depth + b"]" * depth
    lying = "sha256:" + "0" * 64
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(
        headers={"Docker-Content-Digest": lying}, body=bomb,
    )
    with pytest.raises(RegistryError, match="digest mismatch"):
        client.fetch_manifest(ref)


def test_deeply_nested_tags_json_raises_registry_error() -> None:
    depth = 100_000
    bomb = b"[" * depth + b"]" * depth
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = OciRegistryClient(_StubHttp({
        "/v2/acme/app/tags/list?n=100": _StubResponse(200, bomb),
        "https://ghcr.io/v2/acme/app/tags/list?n=100":
            _StubResponse(200, bomb),
    }))
    with pytest.raises(RegistryError, match="parse failed"):
        client.list_tags(ref)


# The 100k-deep bombs above historically failed via RecursionError
# inside json.loads — but whether that error fires at all is an
# interpreter property (CPython 3.14 grew its C-stack headroom and
# parses them cleanly), and on such interpreters the bomb sailed past
# the parse guard entirely. These variants stay WITHIN every supported
# interpreter's parser limits, so the client's own _MAX_JSON_NESTING
# gate is the only thing that can refuse them: the RegistryError
# contract is pinned independent of the interpreter's stack behaviour.

def test_moderately_nested_manifest_bomb_refused_without_recursionerror(
) -> None:
    depth = 500  # parses fine on every supported CPython
    bomb = b"[" * depth + b"]" * depth
    assert isinstance(json.loads(bomb), list)  # parser really survives
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(headers={}, body=bomb)
    with pytest.raises(RegistryError, match="parse failed"):
        client.fetch_manifest(ref)


def test_moderately_nested_tags_bomb_refused_without_recursionerror(
) -> None:
    depth = 500
    bomb = b"[" * depth + b"]" * depth
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = OciRegistryClient(_StubHttp({
        "/v2/acme/app/tags/list?n=100": _StubResponse(200, bomb),
        "https://ghcr.io/v2/acme/app/tags/list?n=100":
            _StubResponse(200, bomb),
    }))
    with pytest.raises(RegistryError, match="parse failed"):
        client.list_tags(ref)


def test_realistic_manifest_nesting_untouched_by_depth_gate() -> None:
    """A plausibly-deep real manifest (well under the cap) must parse
    exactly as before — the gate refuses bombs, not registries."""
    nested: dict = {"schemaVersion": 2, "layers": [],
                    "annotations": {"a": {"b": {"c": [{"d": "e"}]}}}}
    body = json.dumps(nested).encode()
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = _client(headers={}, body=body)
    resp = client.fetch_manifest(ref)
    assert resp.parsed["schemaVersion"] == 2


# ---------------------------------------------------------------------------
# Credential redaction in error snippets
# ---------------------------------------------------------------------------


_ECHOED_BASIC = "Authorization: Basic b3BlcmF0b3I6aHVudGVyMnNlY3JldA=="
_ECHOED_BEARER = "Authorization: Bearer eyJhbGciOiJSUzI1NiJ9.c2VjcmV0cGF5bG9hZA.c2ln"


def test_manifest_error_snippet_redacts_echoed_authorization() -> None:
    """A peer that echoes the Authorization header into a non-200
    body must not plant the credential into the exception text."""
    body = f'{{"error": "denied", "echo": "{_ECHOED_BASIC}"}}'.encode()
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    client = OciRegistryClient(_StubHttp({
        _URL: _StubResponse(500, body),
    }))
    with pytest.raises(RegistryError) as excinfo:
        client.fetch_manifest(ref)
    msg = str(excinfo.value)
    assert "b3BlcmF0b3I6aHVudGVyMnNlY3JldA" not in msg
    assert "REDACTED" in msg


def test_blob_error_snippet_redacts_echoed_bearer() -> None:
    digest = "sha256:" + "d" * 64
    body = f"denied; {_ECHOED_BEARER}".encode()
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    url = f"https://ghcr.io/v2/acme/app/blobs/{digest}"
    client = OciRegistryClient(_StubHttp({
        url: _StubResponse(500, body),
    }))
    with pytest.raises(RegistryError) as excinfo:
        list(client.stream_blob(ref, digest))
    msg = str(excinfo.value)
    assert "eyJhbGciOiJSUzI1NiJ9" not in msg
    assert "REDACTED" in msg


def test_stream_blob_requests_identity_encoding() -> None:
    """Blob fetches must pin Accept-Encoding: identity so the HTTP
    layer hands back the exact stored bytes for hashing (a transport
    that transparently gunzips a gzip-shaped blob breaks the content
    address)."""
    body = b"layer-bytes"
    good = "sha256:" + hashlib.sha256(body).hexdigest()
    ref = parse_image_ref("ghcr.io/acme/app:latest")
    url = f"https://ghcr.io/v2/acme/app/blobs/{good}"
    http = _StubHttp({url: _StubResponse(200, body)})
    client = OciRegistryClient(http)
    list(client.stream_blob(ref, good))
    assert http.calls, "no request recorded"
    headers = http.calls[0].get("headers") or {}
    assert headers.get("Accept-Encoding") == "identity"

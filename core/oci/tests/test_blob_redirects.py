"""Blob-GET redirect handling.

Registries answer ``/v2/<name>/blobs/<digest>`` with a redirect to a
pre-signed CDN URL (Docker Hub 307s every layer). core.http never
follows redirects, so the client follows them itself: bounded hops,
every target re-validated through the registry host policy, and the
registry Authorization confined to the registry origin.
"""

from __future__ import annotations

import hashlib
import socket

import pytest

from core.oci.client import OciRegistryClient, RegistryError
from core.oci.image_ref import parse_image_ref

_BODY = b"layer-bytes" * 64
_DIGEST = "sha256:" + hashlib.sha256(_BODY).hexdigest()
_REGISTRY_URL = f"https://registry-1.docker.io/v2/library/app/blobs/{_DIGEST}"
_CDN_URL = f"https://cdn.example/presigned/{_DIGEST}?sig=abc"


class _StubResponse:
    def __init__(self, status_code: int, body: bytes = b"",
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
    """Serves queued responses per URL and records every request.

    ``stream_bytes`` mirrors the backend's true-streaming surface the
    client uses for the terminal CDN hop: it yields the queued 200
    body in chunks, raises ``HttpError`` for a queued >=400 status
    (lazily, on first iteration — matching the real generator), and
    yields nothing for a bodyless response.
    """

    def __init__(self, responses: dict[str, list[_StubResponse]]):
        self._responses = {k: list(v) for k, v in responses.items()}
        self.calls: list[dict] = []
        self.stream_calls: list[dict] = []

    def _next(self, url: str) -> _StubResponse:
        queue = self._responses.get(url)
        if not queue:
            return _StubResponse(404, b'{"errors": []}')
        return queue.pop(0) if len(queue) > 1 else queue[0]

    def request(self, method: str, url: str, **kwargs):
        self.calls.append({
            "method": method, "url": url,
            "headers": dict(kwargs.get("headers") or {}),
        })
        return self._next(url)

    def stream_bytes(self, url: str, **kwargs):
        from core.http import HttpError
        self.stream_calls.append({
            "url": url,
            "headers": dict(kwargs.get("headers") or {}),
            "max_bytes": kwargs.get("max_bytes"),
        })
        resp = self._next(url)
        if resp.status_code >= 400:
            raise HttpError(
                f"HTTP {resp.status_code} from {url}: "
                f"{resp.text!r}"[:200],
                status=resp.status_code,
            )
        yield from resp.iter_content()


def _ref():
    return parse_image_ref("docker.io/library/app:latest")


def _seed_registry_auth(client: OciRegistryClient) -> None:
    """Make the registry request carry a Bearer token so the
    cross-origin stripping assertion is non-vacuous."""
    key = ("https://auth.docker.io/token", "registry.docker.io",
           "repository:library/app:pull")
    client._tokens[key] = "sekrit-registry-token"
    client._last_challenge["docker.io"] = key


def test_offsite_redirect_followed_and_auth_confined() -> None:
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
        _CDN_URL: [_StubResponse(200, _BODY)],
    })
    client = OciRegistryClient(http)
    _seed_registry_auth(client)
    got = b"".join(client.stream_blob(_ref(), _DIGEST))
    assert got == _BODY
    (registry_call,) = http.calls
    assert registry_call["url"] == _REGISTRY_URL
    assert "Authorization" in registry_call["headers"]
    (cdn_call,) = http.stream_calls
    assert cdn_call["url"] == _CDN_URL
    # The registry credential must NOT follow the redirect off-origin.
    assert "Authorization" not in cdn_call["headers"]
    # Raw-bytes contract holds on the hop, and the dedicated blob
    # budget (not the buffered-request default) bounds the stream.
    assert cdn_call["headers"].get("Accept-Encoding") == "identity"
    assert cdn_call["max_bytes"] and cdn_call["max_bytes"] > 2**30


def test_same_origin_relative_redirect_stays_authed() -> None:
    relocated = f"/v2/library/app/blobs-relocated/{_DIGEST}"
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": relocated},
        )],
        f"https://registry-1.docker.io{relocated}": [
            _StubResponse(200, _BODY),
        ],
    })
    client = OciRegistryClient(http)
    _seed_registry_auth(client)
    got = b"".join(client.stream_blob(_ref(), _DIGEST))
    assert got == _BODY
    second = http.calls[1]
    # Same-origin hop re-enters the authed path.
    assert "Authorization" in second["headers"]


def test_hop_budget_enforced() -> None:
    # Registry redirects to itself (same-origin) forever — the hop
    # budget bounds the authed redirect loop.
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _REGISTRY_URL},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="exceeded 3 redirect hops"):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_offsite_hop_is_terminal_and_empty_body_is_loud() -> None:
    """The CDN hop cannot expose a further redirect's status — a
    misbehaving chain surfaces as the named empty-body error, not a
    silent zero-byte blob."""
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
        _CDN_URL: [_StubResponse(
            307, headers={"Location": "https://elsewhere.example/x"},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="empty body from the redirect target"):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_redirect_without_location_is_named() -> None:
    http = _StubHttp({_REGISTRY_URL: [_StubResponse(307)]})
    client = OciRegistryClient(http)
    with pytest.raises(
        RegistryError, match=r"redirected \(307\) without a Location",
    ):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_non_https_redirect_target_refused() -> None:
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": f"http://cdn.example/{_DIGEST}"},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(
        RegistryError, match="refusing blob redirect .* not https",
    ):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_redirect_target_userinfo_refused() -> None:
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307,
            headers={"Location": f"https://evil@cdn.example/{_DIGEST}"},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="userinfo"):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_redirect_target_held_to_address_policy(monkeypatch) -> None:
    """A CDN host that resolves to a non-global address is refused
    loudly — the redirect target gets the full SSRF gate, not a
    bypass."""

    def split_getaddrinfo(host, port, *args, **kwargs):
        addr = "127.0.0.1" if host == "cdn.example" else "8.8.8.8"
        return [(
            socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP,
            "", (addr, port or 443),
        )]

    monkeypatch.setattr(socket, "getaddrinfo", split_getaddrinfo)
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(
        RegistryError, match="refusing blob redirect",
    ):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_redirect_target_ip_literal_policy(monkeypatch) -> None:
    """Loopback IP-literal Location is refused at parse time."""
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307,
            headers={"Location": f"https://127.0.0.1/{_DIGEST}"},
        )],
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="refusing blob redirect"):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_cdn_error_carries_status_detail() -> None:
    """A CDN-side failure names the status and the blob context."""
    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
        _CDN_URL: [_StubResponse(403)],
    })
    client = OciRegistryClient(http)
    with pytest.raises(RegistryError, match="HTTP 403"):
        b"".join(client.stream_blob(_ref(), _DIGEST))


def test_offsite_redirect_extends_proxy_allowlist(monkeypatch) -> None:
    """When the blob redirect targets an off-origin CDN host, the
    proxy allowlist is dynamically extended so stream_bytes can reach
    it."""
    import core.oci.client as _mod

    extended_hosts: list[str] = []

    def fake_get_proxy(hosts):
        extended_hosts.extend(hosts)

    monkeypatch.setattr(
        "core.sandbox.proxy.get_proxy", fake_get_proxy,
    )
    # Clear any prior CDN-host cache so the extension fires.
    monkeypatch.setattr(_mod, "_cdn_hosts_extended", set())

    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
        _CDN_URL: [_StubResponse(200, _BODY)],
    })
    client = OciRegistryClient(http)
    got = b"".join(client.stream_blob(_ref(), _DIGEST))
    assert got == _BODY
    assert "cdn.example" in extended_hosts


def test_offsite_redirect_proxy_extend_idempotent(monkeypatch) -> None:
    """Second redirect to the same CDN host does NOT call get_proxy
    again — the host-cache dedup works."""
    import core.oci.client as _mod

    call_count = 0

    def fake_get_proxy(hosts):
        nonlocal call_count
        call_count += 1

    monkeypatch.setattr(
        "core.sandbox.proxy.get_proxy", fake_get_proxy,
    )
    monkeypatch.setattr(_mod, "_cdn_hosts_extended", set())

    http = _StubHttp({
        _REGISTRY_URL: [_StubResponse(
            307, headers={"Location": _CDN_URL},
        )],
        _CDN_URL: [_StubResponse(200, _BODY)],
    })
    client = OciRegistryClient(http)
    b"".join(client.stream_blob(_ref(), _DIGEST))
    assert call_count == 1
    # Second call — host already cached.
    b"".join(client.stream_blob(_ref(), _DIGEST))
    assert call_count == 1


def test_origin_empty_body_error_carries_status_detail() -> None:
    """A bodyless non-200 from the registry itself must not produce
    a message trailing off into ': ' — the status is named."""
    http = _StubHttp({_REGISTRY_URL: [_StubResponse(500)]})
    client = OciRegistryClient(http)
    with pytest.raises(
        RegistryError, match=r"HTTP 500 with empty body",
    ):
        b"".join(client.stream_blob(_ref(), _DIGEST))

"""OCI / Docker Registry HTTP API v2 client.

Built on :class:`core.http.HttpClient` so calls go through raptor's
existing egress proxy + sandbox plumbing. Three endpoints:

  * ``HEAD /v2/<name>/manifests/<reference>`` — resolve tag → digest
    without downloading the manifest body
  * ``GET  /v2/<name>/manifests/<reference>`` — fetch the manifest
    (or image index for multi-arch tags)
  * ``GET  /v2/<name>/blobs/<digest>`` — fetch a layer or config
    blob

Each call may receive a 401 on first attempt; the auth dance
exchanges the ``WWW-Authenticate`` challenge for a bearer token
(anonymous if no credentials, basic-auth-exchanged if any), then
retries. The bearer token is cached per ``(realm, service, scope)``
so multiple calls for the same image don't repeat the dance.

Limitations (see :doc:`README`):
  * Anonymous + ``docker config.json`` inline + env-var creds only;
    credsStore / credHelpers refused (security).
  * Single-platform pulls only (caller picks one platform from a
    multi-arch image index).
  * No streaming for manifests (they're tiny — JSON ≤ a few MB);
    blobs DO stream via :func:`stream_blob`.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Dict, Iterator, List, Optional, Tuple

from core.http import HttpClient

from .auth import (
    lookup_credentials,
    parse_www_authenticate,
)
from .image_ref import ImageRef


logger = logging.getLogger(__name__)


# Manifest media types the client accepts. Sent in the ``Accept``
# header so the registry knows we can handle both OCI and Docker
# schema 2 — without it, some registries fall back to schema 1
# which we deliberately do NOT support (deprecated, missing
# digest invariants we rely on).
_MANIFEST_ACCEPT = ", ".join([
    # OCI Image Manifest v1
    "application/vnd.oci.image.manifest.v1+json",
    # OCI Image Index v1 (multi-arch)
    "application/vnd.oci.image.index.v1+json",
    # Docker Manifest Schema 2
    "application/vnd.docker.distribution.manifest.v2+json",
    # Docker Manifest List v2 (multi-arch — schema 2's index)
    "application/vnd.docker.distribution.manifest.list.v2+json",
])


def _parse_link_next(link_header: Optional[str]) -> Optional[str]:
    """Pull the ``<url>`` of the ``rel="next"`` entry out of an
    RFC-5988 ``Link:`` header. Returns None if no next link, or
    the header is absent / malformed.

    The OCI Distribution Spec lets registries paginate
    ``/tags/list`` via this header; URLs may be relative (path
    only) or absolute. We strip leading whitespace + the angle
    brackets but otherwise pass the value through verbatim — the
    HTTP client below treats both shapes.
    """
    if not link_header:
        return None
    # Header may carry multiple comma-separated link entries.
    # Split on commas that aren't inside angle-brackets — RFC 5988
    # lets the URL portion contain commas. Use a lenient parser:
    # for each ``<...>; rel=next`` entry, return the URL.
    import re
    for part in link_header.split(","):
        m = re.match(
            r"\s*<([^>]+)>\s*;\s*rel\s*=\s*\"?next\"?", part,
        )
        if m:
            return m.group(1).strip()
    return None


@dataclass
class ManifestResponse:
    """A registry manifest fetch result.

    ``content_type`` tells consumers which parser to dispatch
    (image manifest vs image index). ``digest`` is the
    server-reported manifest digest from ``Docker-Content-Digest``
    — load-bearing for caching, since it's what an immutable
    reference would point at."""
    raw: bytes
    parsed: Dict[str, Any]
    content_type: str
    digest: Optional[str]


class RegistryError(RuntimeError):
    """Raised on non-2xx responses we can't recover from. Carries
    the status code + a short error string so callers can decide
    whether to retry, fall back, or surface to operators."""
    def __init__(self, status: int, message: str):
        self.status = status
        super().__init__(f"registry error {status}: {message}")


class OciRegistryClient:
    """Stateful client tied to a single :class:`HttpClient` and an
    optional ``BasicCredentials``-providing callable.

    State held: per-(realm, service, scope) bearer-token cache. The
    cache is a plain dict — bounded by distinct image references
    consulted in a single process; tokens are short-lived (5-15 min
    typically) so there's no hard expiry tracking.
    """

    def __init__(
        self,
        http: HttpClient,
        *,
        credentials_lookup=None,
    ):
        self.http = http
        # ``credentials_lookup(registry: str) -> BasicCredentials | None``.
        # Default uses the documented chain; tests inject a stub.
        self._lookup = credentials_lookup or lookup_credentials
        # Token cache keyed by (realm, service, scope).
        self._tokens: Dict[Tuple[str, str, str], str] = {}

    # ----- Public API -----

    def resolve_digest(self, ref: ImageRef) -> str:
        """Return the manifest digest for ``ref``.

        When ``ref.digest`` is set, returns it without a network
        call. Otherwise issues a HEAD on the tag and reads the
        ``Docker-Content-Digest`` response header.
        """
        if ref.digest:
            return ref.digest
        url = self._manifest_url(ref)
        resp = self._authed_request("HEAD", ref.registry, url)
        digest = resp.headers.get("Docker-Content-Digest") \
            or resp.headers.get("docker-content-digest")
        if not digest:
            raise RegistryError(
                resp.status_code,
                f"manifest HEAD missing Docker-Content-Digest "
                f"for {ref.to_canonical()}",
            )
        return digest

    def fetch_manifest(
        self, ref: ImageRef, *, reference: Optional[str] = None,
    ) -> ManifestResponse:
        """Fetch the manifest for ``ref``. If ``reference`` is given,
        it overrides ``ref``'s reference (used to fetch a child
        manifest from an image-index list of platforms)."""
        url = self._manifest_url(ref, reference=reference)
        resp = self._authed_request(
            "GET", ref.registry, url,
            headers={"Accept": _MANIFEST_ACCEPT},
        )
        if resp.status_code != 200:
            raise RegistryError(
                resp.status_code,
                f"manifest GET failed for {ref.to_canonical()}: "
                f"{resp.text[:200]}",
            )
        try:
            parsed = json.loads(resp.content)
        except (ValueError, TypeError) as e:
            raise RegistryError(
                resp.status_code,
                f"manifest JSON parse failed for "
                f"{ref.to_canonical()}: {e}",
            )
        content_type = resp.headers.get("Content-Type", "") \
            or resp.headers.get("content-type", "")
        digest = resp.headers.get("Docker-Content-Digest") \
            or resp.headers.get("docker-content-digest")
        return ManifestResponse(
            raw=resp.content, parsed=parsed,
            content_type=content_type.split(";", 1)[0].strip(),
            digest=digest,
        )

    def list_tags(
        self, ref: ImageRef, *, per_page: int = 100,
        max_pages: int = 50,
    ) -> List[str]:
        """Return the full tag list for ``ref.repository`` on its
        registry, following ``Link`` headers across pages.

        Hits ``GET /v2/<repo>/tags/list?n=<per_page>``. The OCI
        Distribution Spec ``/tags/list`` endpoint returns
        ``{"name": "<repo>", "tags": [...]}`` and signals
        pagination via an RFC-5988 ``Link: <url>; rel="next"``
        response header.

        Docker Hub's ordering quirk drives the need for pagination:
        tags come back in repository-internal index order (often
        alphabetic), so for a repo like ``ollama/ollama`` the
        first 100 tags are the ``0.1.x`` line — never reaching the
        actual ``0.21.x`` latest. Without pagination, ``latest_tag``
        recommends a downgrade.

        ``max_pages`` bounds the walk (default 50 — 5000 tags at
        the default page size). Repos with more tags than that are
        rare; the cap prevents an unbounded walk from a
        misconfigured Link chain.

        Raises :class:`RegistryError` on non-200 or malformed
        response.
        """
        all_tags: List[str] = []
        next_url: Optional[str] = (
            f"/v2/{ref.repository}/tags/list?n={per_page}"
        )
        for _ in range(max_pages):
            if next_url is None:
                break
            resp = self._authed_request("GET", ref.registry, next_url)
            if resp.status_code != 200:
                raise RegistryError(
                    resp.status_code,
                    f"tags/list failed for {ref.repository} on "
                    f"{ref.registry}: {resp.text[:200]}",
                )
            try:
                data = json.loads(resp.content)
            except (ValueError, TypeError) as e:
                raise RegistryError(
                    resp.status_code,
                    f"tags/list JSON parse failed for "
                    f"{ref.repository}: {e}",
                )
            tags = data.get("tags") if isinstance(data, dict) else None
            if not isinstance(tags, list):
                raise RegistryError(
                    resp.status_code,
                    f"tags/list response missing 'tags' array "
                    f"for {ref.repository}",
                )
            # Filter to non-empty strings — registries occasionally
            # include nulls for in-progress pushes.
            all_tags.extend(t for t in tags if isinstance(t, str) and t)

            # Follow ``Link: <url>; rel="next"`` if present. The
            # URL is relative to the registry root, but some
            # registries return absolute URLs — normalise.
            next_url = _parse_link_next(
                resp.headers.get("Link") or resp.headers.get("link"),
            )
        return all_tags

    def stream_blob(
        self, ref: ImageRef, digest: str,
        *, chunk_size: int = 65536,
    ) -> Iterator[bytes]:
        """Stream a blob's bytes in chunks. The caller decides what
        to do with each chunk — typically feed it through a gzip +
        tar streaming decoder (see :mod:`core.oci.blob`).

        Yields the response in chunks of ``chunk_size`` bytes.
        Raises :class:`RegistryError` on non-200. Caller must
        consume the entire iterator (or ensure the underlying
        response is closed) — leaking a half-read response leaks
        the registry connection.
        """
        url = f"/v2/{ref.repository}/blobs/{digest}"
        resp = self._authed_request(
            "GET", ref.registry, url, stream=True,
        )
        if resp.status_code != 200:
            raise RegistryError(
                resp.status_code,
                f"blob GET failed for {digest} in "
                f"{ref.to_canonical()}: {resp.text[:200]}",
            )
        try:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    yield chunk
        finally:
            resp.close()

    # ----- Internals -----

    def _manifest_url(
        self, ref: ImageRef, *, reference: Optional[str] = None,
    ) -> str:
        return (
            f"/v2/{ref.repository}/manifests/"
            f"{reference or ref.reference}"
        )

    def _authed_request(
        self, method: str, registry: str, url_path: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        stream: bool = False,
    ):
        """Issue ``METHOD https://<api-endpoint><url_path>`` with the
        appropriate auth header. The API endpoint is resolved via
        :func:`api_endpoint_for` — for most registries this is just
        ``registry`` itself, but Docker Hub canonical ``docker.io``
        rewrites to ``registry-1.docker.io`` (the v2 API endpoint).
        On 401, parse the ``WWW-Authenticate`` challenge, exchange
        for a bearer token (cached), and retry once. Subsequent
        failures bubble up as :class:`RegistryError`."""
        from .registry_hosts import api_endpoint_for
        full_url = f"https://{api_endpoint_for(registry)}{url_path}"
        req_headers = dict(headers) if headers else {}
        # First attempt with whatever auth is already cached for
        # this registry's most-recent (realm, service, scope) tuple.
        # Cache is keyed by the challenge triple, so we don't have
        # one yet — make the unauthenticated attempt first to
        # discover the realm.
        # raise_on_status=False so the 401-with-WWW-Authenticate
        # challenge reaches the retry path below instead of being
        # converted to an exception by the backend.
        resp = self.http.request(
            method, full_url, headers=req_headers, stream=stream,
            raise_on_status=False,
        )
        if resp.status_code != 401:
            return resp

        # 401 — parse the challenge and exchange.
        challenge_header = (
            resp.headers.get("WWW-Authenticate")
            or resp.headers.get("www-authenticate")
            or ""
        )
        scheme, params = parse_www_authenticate(challenge_header)
        if scheme.lower() != "bearer":
            # Servers using Basic auth direct can take BasicCredentials
            # as a header without an exchange dance.
            creds = self._lookup(registry)
            if creds is None:
                raise RegistryError(
                    resp.status_code,
                    f"{registry} requires {scheme} auth and no "
                    f"credentials configured "
                    f"(set RAPTOR_OCI_<HOST>_USER/_PASSWORD)",
                )
            req_headers["Authorization"] = f"Basic {creds.to_basic_header()}"
            resp.close()
            return self.http.request(
                method, full_url, headers=req_headers, stream=stream,
            )

        realm = params.get("realm", "")
        service = params.get("service", "")
        scope = params.get("scope", "")
        if not realm:
            raise RegistryError(
                resp.status_code,
                f"{registry} 401 with no realm — cannot exchange "
                f"for bearer token",
            )
        token = self._exchange_token(registry, realm, service, scope)
        req_headers["Authorization"] = f"Bearer {token}"
        resp.close()
        return self.http.request(
            method, full_url, headers=req_headers, stream=stream,
        )

    def _exchange_token(
        self, registry: str, realm: str, service: str, scope: str,
    ) -> str:
        """Exchange registry credentials (or anonymous) for a
        bearer token at ``realm``. Cached per ``(realm, service,
        scope)`` triple so the same image fetched multiple times
        only does one exchange.

        Anonymous requests have no Authorization header; the token
        the registry returns is anonymously-scoped (read-only on
        public images). Authenticated requests use HTTP Basic
        against the realm; the registry's auth service exchanges
        that for a bearer token with the requested scope.
        """
        cache_key = (realm, service, scope)
        cached = self._tokens.get(cache_key)
        if cached is not None:
            return cached

        # Encode service+scope into the URL ourselves — the
        # core.http backend doesn't support requests-style ``params=``.
        from urllib.parse import urlencode
        qs_pairs = []
        if service:
            qs_pairs.append(("service", service))
        if scope:
            qs_pairs.append(("scope", scope))
        token_url = realm
        if qs_pairs:
            sep = "&" if "?" in realm else "?"
            token_url = f"{realm}{sep}{urlencode(qs_pairs)}"

        headers: Dict[str, str] = {}
        creds = self._lookup(registry)
        if creds is not None:
            headers["Authorization"] = f"Basic {creds.to_basic_header()}"

        resp = self.http.request(
            "GET", token_url, headers=headers,
            raise_on_status=False,
        )
        if resp.status_code != 200:
            raise RegistryError(
                resp.status_code,
                f"token exchange at {realm} failed: "
                f"{resp.text[:200]}",
            )
        try:
            payload = json.loads(resp.content)
        except (ValueError, TypeError) as e:
            raise RegistryError(
                resp.status_code,
                f"token exchange at {realm} returned non-JSON: {e}",
            )
        # Token may be in ``token`` or ``access_token`` per the
        # registry spec — both must be supported.
        token = payload.get("token") or payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RegistryError(
                resp.status_code,
                f"token exchange at {realm} returned no token field",
            )
        self._tokens[cache_key] = token
        return token


__all__ = [
    "OciRegistryClient",
    "ManifestResponse",
    "RegistryError",
]

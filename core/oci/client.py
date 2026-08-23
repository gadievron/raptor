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

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING


from .auth import (
    lookup_credentials,
    parse_www_authenticate,
)

if TYPE_CHECKING:
    from .image_ref import ImageRef
    from core.http import HttpClient
    from collections.abc import Iterator

logger = logging.getLogger(__name__)


# Manifest media types the client accepts. Sent in the ``Accept``
# header so the registry knows we can handle both OCI and Docker
# schema 2 — without it, some registries fall back to schema 1
# which we deliberately do NOT support (deprecated, missing
# digest invariants we rely on).
_MANIFEST_ACCEPT = ", ".join([  # noqa: FLY002 — per-entry comments below
    # OCI Image Manifest v1
    "application/vnd.oci.image.manifest.v1+json",
    # OCI Image Index v1 (multi-arch)
    "application/vnd.oci.image.index.v1+json",
    # Docker Manifest Schema 2
    "application/vnd.docker.distribution.manifest.v2+json",
    # Docker Manifest List v2 (multi-arch — schema 2's index)
    "application/vnd.docker.distribution.manifest.list.v2+json",
])


# Size caps on registry-returned JSON. Hostile / compromised mirror
# can serve multi-GiB responses; cap before json.loads to bound
# memory. 16 MiB is generous for real manifests/tags lists (typical
# manifest <10 KiB, tags list a few MiB at most).
_MAX_MANIFEST_BYTES = 16 * 1024 * 1024

# The one digest algorithm this client speaks. Content addresses are
# recomputed from response bytes and compared against requested
# references, so the grammar is deliberately strict — a looser OCI
# grammar would admit algorithms we can't verify.
_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_TAGS_BYTES = 16 * 1024 * 1024
# Aggregate budgets across ALL tags/list pages. The per-page byte cap
# resets each iteration, so without these a hostile registry
# (selectable via target-derived image refs) could feed 50 pages ×
# 16 MiB of tag data that gets retained wholesale — and cached — by
# callers. Docker Hub's biggest real repos are low-thousands of tags.
_MAX_TAGS_TOTAL_BYTES = 64 * 1024 * 1024
_MAX_TAGS_TOTAL_COUNT = 50_000
# OCI tag grammar caps names at 128 chars; anything longer is not a
# real tag and only inflates the retained list.
_MAX_TAG_LENGTH = 128
_MAX_TOKEN_BYTES = 256 * 1024  # token-exchange responses are tiny

# Depth cap on registry-returned JSON, enforced right after every
# json.loads of registry bytes. The RecursionError mapping at those
# sites only fires on interpreters whose C parser still exhausts its
# stack inside the byte caps — CPython 3.14 grew the C-stack headroom,
# so a 100k-deep bracket bomb parses cleanly there and a nested bomb
# would otherwise flow onward as a "legitimate" value (or surface as
# the wrong RegistryError). Real OCI payloads nest ~10 levels; 100 is
# generous, and the explicit bound makes nested-bomb refusal a
# contract of THIS client rather than of the interpreter's stack.
_MAX_JSON_NESTING = 100


def _reject_deep_nesting(
    obj: object, *, max_depth: int = _MAX_JSON_NESTING,
) -> None:
    """Raise ValueError when *obj* nests containers deeper than
    *max_depth*. Iterative walk — measuring the depth must not itself
    be able to blow the recursion limit."""
    stack: list[tuple[object, int]] = [(obj, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children: "list[object]" = list(node.values())
        elif isinstance(node, list):
            children = node
        else:
            continue
        if children and depth >= max_depth:
            msg = (
                f"nesting depth exceeds {max_depth} — refusing "
                f"attacker-shaped deeply nested JSON"
            )
            raise ValueError(msg)
        for child in children:
            stack.append((child, depth + 1))


# Token-service realm allowlist per registry. Realm hosts beyond
# the registry's own host or its documented auth subdomain are
# rejected — closes the SSRF / credential-handover attack where a
# malicious / compromised registry returns
# ``WWW-Authenticate: Bearer realm="https://attacker.com/steal"``.
# Keep this list tight; new entries require explicit knowledge of
# the registry's token-service host.
_REALM_HOST_ALLOWLIST: dict[str, frozenset[str]] = {
    "docker.io":            frozenset({"auth.docker.io"}),
    "registry-1.docker.io": frozenset({"auth.docker.io"}),
    "ghcr.io":              frozenset({"ghcr.io"}),
    "quay.io":              frozenset({"quay.io"}),
    "gcr.io":               frozenset({"gcr.io"}),
    "registry.gitlab.com":  frozenset({"gitlab.com", "registry.gitlab.com"}),
}


def _validate_realm(registry: str, realm: str) -> None:
    """Raise :class:`RegistryError` if ``realm`` is not an HTTPS
    URL whose host is the registry itself or on the per-registry
    token-service allowlist.

    SSRF defence: see comment on ``_REALM_HOST_ALLOWLIST`` above.
    """
    from urllib.parse import urlsplit
    parts = urlsplit(realm)
    if parts.scheme != "https":
        raise RegistryError(
            401,
            f"refusing non-HTTPS realm from {registry}: "
            f"{realm!r} (SSRF defence)",
        )
    if not parts.hostname:
        raise RegistryError(
            401, f"{registry} realm has no host: {realm!r}",
        )
    host = parts.hostname.lower()
    # Case-fold ``registry`` for the allowlist lookup too. Pre-fix
    # a future caller path that passed ``"Docker.io"`` (mixed-case
    # reference output) would miss the ``"docker.io"`` allowlist
    # key, the ``.get(..., frozenset())`` would return empty, and
    # the realm host comparison would fall through to a false
    # refusal. ``parse_image_ref`` is the canonical source today
    # and lowercases internally, but the defensive case-fold here
    # closes that surface for any future caller path.
    allowed = _REALM_HOST_ALLOWLIST.get(registry.lower(), frozenset())
    if host == registry.lower() or host in allowed:
        return
    raise RegistryError(
        401,
        f"refusing realm host {host!r} for registry {registry!r} "
        f"(not on token-service allowlist; SSRF defence)",
    )



def _safe_error_snippet(resp) -> str:
    """Short response-body excerpt for error messages, with
    credential-shaped substrings masked.

    Non-2xx bodies are peer-controlled and can echo the request's
    ``Authorization`` header (Basic base64 or bearer token) straight
    back — a hostile or misconfigured peer would then plant the
    operator's registry credentials into exceptions, logs, and
    scorecards. Redact before the text ever reaches an error string;
    the extra pre-truncation slack keeps a token that straddles the
    200-char boundary recognisable to the redactor.
    """
    from core.security.redaction import redact_secrets
    return redact_secrets(resp.text[:600], reveal_secrets=False)[:200]


def _validate_link_next(
    raw: str | None, *, repository: str,
) -> str | None:
    """Validate a ``Link: rel=next`` URL extracted from a registry
    response. Returns the URL if it's a relative path under
    ``/v2/<repository>/`` (the only shape the OCI spec produces
    for tags/list pagination); returns None otherwise.

    Rejection cases:
    * Absolute URL (any scheme + host) — registry could redirect
      us at an attacker-controlled endpoint, bypassing the
      api_endpoint_for() + realm-validation chain.
    * Path traversal (``..`` segments) — registry could escape
      out of the repository scope.
    * Cross-repo path — pagination must stay within the same
      repository's tag list.
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    # Must be a relative path. Scheme presence (`://`) or
    # authority-relative (`//host`) shapes are rejected.
    if "://" in s or s.startswith("//"):
        return None
    if not s.startswith("/v2/"):
        return None
    # Path-traversal guard.
    path = s.split("?", 1)[0]
    if any(seg in (".", "..") for seg in path.split("/")):
        return None
    # Stay within the same repository's namespace.
    expected_prefix = f"/v2/{repository}/"
    if not path.startswith(expected_prefix):
        return None
    return s


def _parse_link_next(link_header: str | None) -> str | None:
    """Pull the ``<url>`` of the ``rel="next"`` entry out of an
    RFC-5988 ``Link:`` header. Returns None if no next link, or
    the header is absent / malformed.

    The OCI Distribution Spec lets registries paginate
    ``/tags/list`` via this header; registries may emit relative
    (path-only) or absolute URLs. We strip leading whitespace + the
    angle brackets and pass the value through verbatim; the caller
    then runs it through :func:`_validate_link_next`, which accepts
    only relative ``/v2/<repository>/`` paths (absolute URLs are
    rejected as an SSRF guard, ending pagination), and
    ``_authed_request`` resolves the surviving path against the
    registry's API endpoint.
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
    (image manifest vs image index). ``digest`` is the sha256 of
    ``raw`` COMPUTED by this client — load-bearing for caching, and
    safe for it precisely because it is derived from the bytes rather
    than echoed from the ``Docker-Content-Digest`` header (which is
    cross-checked and must agree)."""
    raw: bytes
    parsed: dict[str, Any]
    content_type: str
    digest: str | None


class RegistryError(RuntimeError):
    """Raised on non-2xx responses we can't recover from. Carries
    the status code + a short error string so callers can decide
    whether to retry, fall back, or surface to operators."""
    def __init__(self, status: int, message: str) -> None:
        self.status = status
        super().__init__(f"registry error {status}: {message}")


class OciRegistryClient:
    """Stateful client tied to a single :class:`HttpClient` and an
    optional ``BasicCredentials``-providing callable.

    State held: per-(realm, service, scope) bearer-token cache plus a
    per-registry memo of the most recent challenge triple (the triple
    is only discoverable from a 401 challenge, so the memo is what
    lets later requests attach a cached token on their FIRST attempt).
    Both are plain dicts — bounded by distinct image references
    consulted in a single process; tokens are short-lived (5-15 min
    typically) so there's no hard expiry tracking: an expired token
    surfaces as a 401, which evicts it and re-exchanges. Not
    thread-safe — one client per thread, like the HttpClient it wraps.
    """

    def __init__(
        self,
        http: HttpClient,
        *,
        credentials_lookup=None,
    ) -> None:
        self.http = http
        # ``credentials_lookup(registry: str) -> BasicCredentials | None``.
        # Default uses the documented chain; tests inject a stub.
        self._lookup = credentials_lookup or lookup_credentials
        # Token cache keyed by (realm, service, scope).
        self._tokens: dict[tuple[str, str, str], str] = {}
        # Most recent challenge triple seen per registry — the key
        # under which the next request for that registry looks up a
        # cached token for its first attempt.
        self._last_challenge: dict[str, tuple[str, str, str]] = {}

    # ----- Public API -----

    def resolve_digest(self, ref: ImageRef) -> str:
        """Return the manifest digest for ``ref``.

        When ``ref.digest`` is set, returns it without a network
        call. Otherwise issues a HEAD on the tag and reads the
        ``Docker-Content-Digest`` response header.

        The HEAD path has no body to hash, so the returned value is a
        SERVER CLAIM, not a verified content address. It is safe to use
        only as a fetch reference: ``fetch_manifest`` re-verifies any
        digest-shaped reference against the bytes it actually returns,
        so a lying HEAD is caught at fetch time. Do not key caches or
        name files on this value without fetching through it first.
        The shape is validated here so a malformed header can't smuggle
        path syntax into later URL construction.
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
        if not _DIGEST_RE.match(digest):
            raise RegistryError(
                resp.status_code,
                f"malformed Docker-Content-Digest for "
                f"{ref.to_canonical()}: {digest[:80]!r}",
            )
        return digest

    def fetch_manifest(
        self, ref: ImageRef, *, reference: str | None = None,
    ) -> ManifestResponse:
        """Fetch the manifest for ``ref``. If ``reference`` is given,
        it overrides ``ref``'s reference (used to fetch a child
        manifest from an image-index list of platforms).

        Digest discipline: any digest-shaped pin (the ``reference``
        override — commonly an image-index entry the registry itself
        supplied — or ``ref.digest``) must be a verifiable sha256
        content address. Pins in other algorithms are refused BEFORE
        the fetch: the pre-fix check only compared pins that started
        with ``sha256:``, so a ``sha512:``/``md5:`` pin was fetched
        and used with no content authentication at all.
        """
        requested_pin: str | None = None
        if reference is not None and ":" in reference:
            # Digest-shaped (tags cannot contain ':'). Refusing here
            # also keeps a hostile index-supplied digest inert in the
            # URL path below.
            if not _DIGEST_RE.match(reference):
                raise RegistryError(
                    0,
                    f"refusing manifest reference {reference[:80]!r} "
                    f"for {ref.to_canonical()}: pinned digest is not "
                    f"a verifiable sha256 content address",
                )
            requested_pin = reference
        elif reference is None and ref.digest:
            if not _DIGEST_RE.match(ref.digest):
                raise RegistryError(
                    0,
                    f"refusing digest pin {ref.digest[:80]!r} for "
                    f"{ref.to_canonical()}: not a verifiable sha256 "
                    f"content address",
                )
            requested_pin = ref.digest
        url = self._manifest_url(ref, reference=reference)
        resp = self._authed_request(
            "GET", ref.registry, url,
            headers={"Accept": _MANIFEST_ACCEPT},
        )
        if resp.status_code != 200:
            raise RegistryError(
                resp.status_code,
                f"manifest GET failed for {ref.to_canonical()}: "
                f"{_safe_error_snippet(resp)}",
            )
        if len(resp.content) > _MAX_MANIFEST_BYTES:
            raise RegistryError(
                resp.status_code,
                f"manifest exceeds {_MAX_MANIFEST_BYTES}-byte cap "
                f"for {ref.to_canonical()} (got {len(resp.content)})",
            )
        content_type = resp.headers.get("Content-Type", "") \
            or resp.headers.get("content-type", "")
        # The digest we report is COMPUTED from the body, never echoed
        # from the Docker-Content-Digest header: downstream consumers
        # key forever-caches and filenames on it, so it must be a
        # provable content address, not a server claim. The header and
        # the requested reference (fetch-by-digest / index sub-manifest
        # picks) are cross-checked against the computed value and a
        # disagreement is an integrity failure, not a soft fallback.
        # Digest verification runs BEFORE json.loads so bytes that
        # fail the cross-check are never fed to the parser at all.
        computed = "sha256:" + hashlib.sha256(resp.content).hexdigest()
        header_digest = resp.headers.get("Docker-Content-Digest") \
            or resp.headers.get("docker-content-digest")
        if (header_digest and header_digest.startswith("sha256:")
                and header_digest != computed):
            raise RegistryError(
                resp.status_code,
                f"manifest digest mismatch for {ref.to_canonical()}: "
                f"header claims {header_digest}, body hashes to "
                f"{computed}",
            )
        if requested_pin and requested_pin != computed:
            raise RegistryError(
                resp.status_code,
                f"manifest digest mismatch for {ref.to_canonical()}: "
                f"requested {requested_pin}, body hashes to {computed}",
            )
        # RecursionError: registry JSON is attacker-shaped; deeply
        # nested arrays/objects within the size cap blow the parser's
        # recursion limit. Convert to the module's error type instead
        # of letting it escape as an unhandled crash. The explicit
        # depth gate covers interpreters that parse the same nesting
        # without ever raising RecursionError (CPython 3.14+).
        try:
            parsed = json.loads(resp.content)
            _reject_deep_nesting(parsed)
        except (ValueError, TypeError, RecursionError) as e:
            raise RegistryError(
                resp.status_code,
                f"manifest JSON parse failed for "
                f"{ref.to_canonical()}: {type(e).__name__}: {e}",
            ) from e
        return ManifestResponse(
            raw=resp.content, parsed=parsed,
            content_type=content_type.split(";", 1)[0].strip(),
            digest=computed,
        )

    def list_tags(
        self, ref: ImageRef, *, per_page: int = 100,
        max_pages: int = 50,
    ) -> list[str]:
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

        Aggregate budgets: cumulative response bytes and total tag
        count are bounded across pages (the per-page caps alone let a
        hostile registry stream max_pages × 16 MiB into a retained —
        and downstream-cached — list). Exceeding either budget raises
        :class:`RegistryError` rather than silently truncating.
        Tags longer than the OCI grammar's 128-char maximum are
        dropped like other non-tag entries.

        Raises :class:`RegistryError` on non-200 or malformed
        response.
        """
        all_tags: list[str] = []
        total_bytes = 0
        next_url: str | None = (
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
                    f"{ref.registry}: {_safe_error_snippet(resp)}",
                )
            if len(resp.content) > _MAX_TAGS_BYTES:
                raise RegistryError(
                    resp.status_code,
                    f"tags/list exceeds {_MAX_TAGS_BYTES}-byte cap "
                    f"for {ref.repository} (got {len(resp.content)})",
                )
            total_bytes += len(resp.content)
            if total_bytes > _MAX_TAGS_TOTAL_BYTES:
                raise RegistryError(
                    resp.status_code,
                    f"tags/list pagination exceeds aggregate "
                    f"{_MAX_TAGS_TOTAL_BYTES}-byte budget for "
                    f"{ref.repository} on {ref.registry}",
                )
            try:
                data = json.loads(resp.content)
                _reject_deep_nesting(data)
            except (ValueError, TypeError, RecursionError) as e:
                # RecursionError: deep nesting within the byte cap.
                # The depth gate covers interpreters that parse the
                # same nesting without raising (CPython 3.14+).
                raise RegistryError(
                    resp.status_code,
                    f"tags/list JSON parse failed for "
                    f"{ref.repository}: {type(e).__name__}: {e}",
                ) from e
            tags = data.get("tags") if isinstance(data, dict) else None
            if not isinstance(tags, list):
                raise RegistryError(
                    resp.status_code,
                    f"tags/list response missing 'tags' array "
                    f"for {ref.repository}",
                )
            # Filter to non-empty strings — registries occasionally
            # include nulls for in-progress pushes. Overlong entries
            # violate the OCI tag grammar (128-char max) and are
            # dropped the same way.
            all_tags.extend(
                t for t in tags
                if isinstance(t, str) and t and len(t) <= _MAX_TAG_LENGTH
            )
            if len(all_tags) > _MAX_TAGS_TOTAL_COUNT:
                raise RegistryError(
                    resp.status_code,
                    f"tags/list exceeds {_MAX_TAGS_TOTAL_COUNT}-tag "
                    f"budget for {ref.repository} on {ref.registry}",
                )

            # Follow ``Link: <url>; rel="next"`` if present.
            # Must be a relative path under ``/v2/`` for the same
            # repository — absolute URLs / path traversal / cross-
            # repo references are rejected (registry-controlled URL
            # would otherwise bypass the api_endpoint_for() routing
            # and the realm validation; relative paths route through
            # _authed_request as expected).
            raw_next = _parse_link_next(
                resp.headers.get("Link") or resp.headers.get("link"),
            )
            next_url = _validate_link_next(
                raw_next, repository=ref.repository,
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

        The stream is hashed as it is consumed and checked against
        ``digest`` once exhausted — blobs are content-addressed, so a
        registry that serves different bytes is an integrity failure
        (RegistryError after the final chunk). A caller that stops
        early skips the check by construction; only fully-consumed
        streams are verified.
        """
        if not _DIGEST_RE.match(digest):
            # Also keeps digest inert in the URL path below.
            raise RegistryError(
                0, f"malformed blob digest: {digest[:80]!r}",
            )
        url = f"/v2/{ref.repository}/blobs/{digest}"
        # Blobs are content-addressed: the sha256 below must run over
        # exactly the bytes the registry stores. ``Accept-Encoding:
        # identity`` pins the raw-bytes contract in the HTTP backend
        # (no transport decompression), so a gzip-shaped blob is never
        # transparently mutated before hashing.
        resp = self._authed_request(
            "GET", ref.registry, url,
            headers={"Accept-Encoding": "identity"}, stream=True,
        )
        if resp.status_code != 200:
            raise RegistryError(
                resp.status_code,
                f"blob GET failed for {digest} in "
                f"{ref.to_canonical()}: {_safe_error_snippet(resp)}",
            )
        hasher = hashlib.sha256()
        try:
            for chunk in resp.iter_content(chunk_size=chunk_size):
                if chunk:
                    hasher.update(chunk)
                    yield chunk
        finally:
            resp.close()
        computed = "sha256:" + hasher.hexdigest()
        if computed != digest:
            raise RegistryError(
                200,
                f"blob digest mismatch for {ref.to_canonical()}: "
                f"requested {digest}, body hashes to {computed}",
            )

    # ----- Internals -----

    def _manifest_url(
        self, ref: ImageRef, *, reference: str | None = None,
    ) -> str:
        return (
            f"/v2/{ref.repository}/manifests/"
            f"{reference or ref.reference}"
        )

    def _authed_request(
        self, method: str, registry: str, url_path: str,
        *,
        headers: dict[str, str] | None = None,
        stream: bool = False,
    ):
        """Issue ``METHOD https://<api-endpoint><url_path>`` with the
        appropriate auth header. The API endpoint is resolved via
        :func:`api_endpoint_for` — for most registries this is just
        ``registry`` itself, but Docker Hub canonical ``docker.io``
        rewrites to ``registry-1.docker.io`` (the v2 API endpoint).
        On 401, parse the ``WWW-Authenticate`` challenge, exchange
        for a bearer token (cached), and retry once. Subsequent
        failures bubble up as :class:`RegistryError`.

        Address policy runs twice here: ``api_endpoint_for`` applies
        the parse-time gate to the NAME, then
        ``validate_resolved_registry_addresses`` re-validates the
        addresses the host actually resolves to. The second gate is
        what stops DNS rebinding / private-DNS answers: a
        target-derived registry with an innocent-looking hostname
        must not drive this client at loopback / RFC1918 /
        link-local / metadata endpoints (including NAT64-embedded
        IPv4 in AAAA answers)."""
        from .registry_hosts import (
            api_endpoint_for,
            validate_resolved_registry_addresses,
        )
        endpoint = api_endpoint_for(registry)
        try:
            validate_resolved_registry_addresses(endpoint)
        except ValueError as exc:
            raise RegistryError(0, str(exc)) from exc
        full_url = f"https://{endpoint}{url_path}"
        req_headers = dict(headers) if headers else {}
        # First attempt with whatever auth is already cached for
        # this registry's most-recent (realm, service, scope) tuple —
        # repeat calls for the same image must skip the exchange
        # dance. The triple is only discoverable from a 401 challenge,
        # so the very first call for a registry goes out
        # unauthenticated and takes the challenge path below.
        used_cache_key: tuple[str, str, str] | None = None
        last_challenge = self._last_challenge.get(registry)
        if last_challenge is not None:
            cached_token = self._tokens.get(last_challenge)
            if cached_token is not None:
                req_headers["Authorization"] = f"Bearer {cached_token}"
                used_cache_key = last_challenge
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
                raise_on_status=False,
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
        # SSRF defence: the realm URL comes from the registry's own
        # WWW-Authenticate header, but a compromised mirror could
        # return e.g. ``Bearer realm="https://attacker.com/steal"``
        # and we'd post HTTP Basic credentials to it. Constrain the
        # realm to https + an explicit allowlist of token-service
        # hosts per registry (most are sub-domains of the registry
        # host; explicit list keeps the surface small).
        _validate_realm(registry, realm)
        cache_key = (realm, service, scope)
        # Evict only the token that actually failed: a 401 while
        # presenting the cached token for THIS exact triple means that
        # token is stale/expired. A 401 with no token attached (first
        # contact) or with a token cached under a different triple
        # (scope change between repositories) says nothing about other
        # cache entries — those stay.
        if used_cache_key == cache_key:
            self._tokens.pop(cache_key, None)
        self._last_challenge[registry] = cache_key
        token = self._exchange_token(registry, realm, service, scope)
        req_headers["Authorization"] = f"Bearer {token}"
        resp.close()
        return self.http.request(
            method, full_url, headers=req_headers, stream=stream,
            raise_on_status=False,
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

        headers: dict[str, str] = {}
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
                f"{_safe_error_snippet(resp)}",
            )
        if len(resp.content) > _MAX_TOKEN_BYTES:
            raise RegistryError(
                resp.status_code,
                f"token exchange response exceeds {_MAX_TOKEN_BYTES}b "
                f"(got {len(resp.content)}) — likely hostile or "
                f"misconfigured token service",
            )
        try:
            payload = json.loads(resp.content)
            _reject_deep_nesting(payload)
        except (ValueError, TypeError, RecursionError) as e:
            # RecursionError: deep nesting within the byte cap.
            # The depth gate covers interpreters that parse the
            # same nesting without raising (CPython 3.14+).
            raise RegistryError(
                resp.status_code,
                f"token exchange at {realm} returned non-JSON: "
                f"{type(e).__name__}: {e}",
            ) from e
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
    "ManifestResponse",
    "OciRegistryClient",
    "RegistryError",
]

"""Shared URL-path chokepoint for registry clients.

Registry clients build request URLs from package names and versions
that ultimately come from the *scanned repository's* manifests —
hostile input. A name like ``../../org/internal-pkg`` or
``rack/versions/1.0.json?`` interpolated raw into a URL path can
steer an (optionally authenticated) registry request at a different
endpoint: path traversal, per-version metadata swap, query-string
injection.

Every client routes its path components through this module:

* :func:`quote_segment` — one URL path segment. Rejects empty
  values, dot segments (``.`` / ``..``), path separators (unless
  the caller opts in to encoding them), whitespace, and control
  characters; percent-encodes everything else.
* :func:`quote_path` — a ``/``-separated multi-segment component
  for ecosystems whose names legitimately contain ``/`` (Composer
  ``vendor/package``, Go module paths, GitHub ``owner/repo``).
  Each segment is validated + encoded individually; the separators
  are preserved.
* :func:`registry_cache_key` — cache-key builder that percent-
  encodes each component (injective key identity) and, when the
  client has a configurable base URL (private mirrors), mixes a
  digest of the resolved base into the key so a private-mirror
  answer is never served as the public registry's (or vice versa).

Invalid components raise :class:`UnsafeUrlComponentError` — a
``ValueError`` subclass. Clients treat it exactly like npm's name
grammar rejection: return the not-found sentinel WITHOUT touching
the cache in either direction.
"""

from __future__ import annotations

import hashlib
import urllib.parse

__all__ = [
    "UnsafeUrlComponentError",
    "quote_path",
    "quote_segment",
    "registry_cache_key",
]


class UnsafeUrlComponentError(ValueError):
    """A name/version component is not safe to place in a URL path."""


def _validate_segment(value: str) -> None:
    if not value:
        raise UnsafeUrlComponentError("empty URL path segment")
    if value in (".", ".."):
        raise UnsafeUrlComponentError(
            f"dot segment {value!r} not allowed in URL path"
        )
    for ch in value:
        # Control characters (including \r\n header-splitting shapes)
        # and whitespace never appear in legitimate package names or
        # versions; reject rather than encode so the caller's
        # not-found path handles them uniformly.
        if ord(ch) < 0x21 or ord(ch) == 0x7F:
            raise UnsafeUrlComponentError(
                f"control/whitespace character in URL segment: {value!r}"
            )


def quote_segment(
    value: str, *, safe: str = "", encode_slash: bool = False,
) -> str:
    """Validate + percent-encode ``value`` as ONE URL path segment.

    A ``/`` in the value is REJECTED by default — package names and
    versions are single segments, and a slash is a splice attempt.
    ``encode_slash=True`` opts in to confining a legitimate
    slash-bearing identifier (a git branch like ``release/1.0``)
    to one percent-encoded segment instead; every slash-separated
    part is still validated so dot segments can't hide inside.

    ``safe`` may name extra characters to leave unencoded for
    readability (e.g. ``"@"`` for npm-style scope markers); ``/``
    and ``%`` are never allowed in ``safe`` — a raw ``/`` would
    splice extra path segments and a raw ``%`` would enable
    double-decode aliasing.
    """
    if "/" in safe or "%" in safe:
        raise ValueError("'/' and '%' may not be marked safe")
    if "/" in value:
        if not encode_slash:
            raise UnsafeUrlComponentError(
                f"path separator in URL segment: {value!r}"
            )
        for part in value.split("/"):
            _validate_segment(part)
    else:
        _validate_segment(value)
    return urllib.parse.quote(value, safe=safe)


def quote_path(
    value: str, *, expected_segments: int | None = None, safe: str = "",
) -> str:
    """Validate + encode a ``/``-separated multi-segment component.

    For ecosystems whose names legitimately span path segments
    (``vendor/package``, ``owner/repo``, Go module paths). Every
    segment must independently pass :func:`quote_segment`'s
    validation — so ``vendor/../pkg`` and ``a//b`` are rejected.
    ``expected_segments`` optionally pins the exact segment count.
    """
    parts = value.split("/")
    if expected_segments is not None and len(parts) != expected_segments:
        raise UnsafeUrlComponentError(
            f"expected {expected_segments} path segment(s), "
            f"got {len(parts)}: {value!r}"
        )
    return "/".join(quote_segment(p, safe=safe) for p in parts)


def registry_cache_key(
    prefix: str, *components: str, base_url: str | None = None,
) -> str:
    """Build an injective cache key from ``prefix`` + components.

    Components are percent-encoded so ``/`` / ``..`` in a raw name
    can't alias another package's cache file after JsonCache path
    sanitisation. ``base_url`` (pass the client's RESOLVED base for
    every client with a configurable registry URL) is mixed in as a
    short digest: the same package fetched via two different bases
    gets two distinct cache entries, so a private-mirror answer is
    never served as the public registry's or vice versa. Old keys
    without the digest simply re-fetch once.
    """
    encoded = [urllib.parse.quote(c, safe="") for c in components]
    key = ":".join([prefix, *encoded])
    if base_url:
        digest = hashlib.sha256(base_url.encode("utf-8")).hexdigest()[:12]
        key = f"{key}:base-{digest}"
    return key

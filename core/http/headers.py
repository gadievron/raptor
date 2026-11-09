"""Conservative header copying for buffered responses forwarded to another client."""

from collections.abc import Mapping
import re

from core.http import HttpError

_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_RESOURCE_HEADERS = frozenset({
    "content-type", "content-encoding", "content-language", "content-range",
    "accept-ranges", "etag", "last-modified", "cache-control", "expires", "vary",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-expose-headers", "cross-origin-resource-policy",
    "cross-origin-embedder-policy", "x-content-type-options",
})


def request_headers(
    defaults: Mapping[str, str], supplied: Mapping[str, str] | None = None,
) -> dict[str, str]:
    """Validate and merge request headers with case-insensitive overrides.

    Invalid values are refused before networking without echoing credentials.
    Caller mappings remain unchanged; duplicate caller names with different
    casing are refused rather than sending ambiguous fields. Values must fit
    the HTTP/1 transport's Latin-1 encoding; no implicit encoding is applied.
    """
    if supplied is not None and not isinstance(supplied, Mapping):
        raise HttpError("request headers must be a mapping")
    selected: dict[str, str] = {}
    names: dict[str, str] = {}
    for group in (defaults, supplied or {}):
        seen = set()
        for name, value in group.items():
            if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
                raise HttpError("invalid request header name")
            if not isinstance(value, str) or any(
                ord(c) < 32 or ord(c) == 127 or ord(c) > 255 for c in value
            ):
                raise HttpError("invalid request header value")
            key = name.lower()
            if key in seen:
                raise HttpError("duplicate request header name")
            seen.add(key)
            if key in names:
                selected.pop(names[key])
            names[key] = name
            selected[name] = value
    return selected


def anonymous_resource_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Copy only resource metadata and CORS headers, without origin state.

    Use when forwarding a separately fetched body under another request URL.
    This never forwards Set-Cookie, Clear-Site-Data, Alt-Svc or other stateful
    response headers. It does not rewrite CORS or Content-Encoding; the caller
    must preserve the body's encoding. This is for anonymous subresources,
    not documents or a transparent HTTP proxy.
    Multi-value fields represented with newlines are refused rather than
    guessing whether combining that field is semantically safe.
    """
    connection = []
    for name, value in headers.items():
        if not isinstance(name, str) or not _HEADER_NAME.fullmatch(name):
            raise HttpError("invalid response header name")
        if not isinstance(value, str):
            raise HttpError("invalid response header value")
        if name.lower() == "connection":
            connection.extend(value.replace("\n", ",").split(","))
    excluded = {name.strip().lower() for name in connection}
    selected = {}
    for name, value in headers.items():
        key = name.lower()
        if key not in _RESOURCE_HEADERS or key in excluded:
            continue
        if key in selected:
            raise HttpError("duplicate forwarded response header")
        if any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise HttpError("ambiguous or invalid forwarded response header value")
        selected[key] = value
    return selected

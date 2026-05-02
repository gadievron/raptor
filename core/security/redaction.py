#!/usr/bin/env python3
"""Shared secret redaction helpers for RAPTOR outputs."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

_SECRET_QUERY_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "auth_token",
    "bearer_token",
    "client_secret",
    "consumer_secret",
    "id_token",
    "refresh_token",
    "secret",
    "session_token",
    "service_token",
    "token",
}


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return raw_url

    if not parsed.scheme or not parsed.netloc:
        return raw_url

    netloc = parsed.netloc
    if "@" in netloc:
        userinfo, host = netloc.rsplit("@", 1)
        if ":" in userinfo:
            username, _password = userinfo.split(":", 1)
            userinfo = f"{username}:[REDACTED]"
        else:
            userinfo = "[REDACTED]"
        netloc = f"{userinfo}@{host}"

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    redacted_pairs = [
        (key, "[REDACTED]" if key.lower() in _SECRET_QUERY_KEYS else value)
        for key, value in query_pairs
    ]
    query = "&".join(
        f"{quote(key, safe='[]')}={quote(value, safe='[]/')}" for key, value in redacted_pairs
    )

    return urlunsplit((parsed.scheme, netloc, parsed.path, query, parsed.fragment))


def redact_secrets(value: object, *, reveal_secrets: bool = False) -> str:
    """Redact common secret material from a string unless explicitly disabled.

    RAPTOR defaults to redacting because scan artifacts and logs are often shared.
    Operators can pass ``reveal_secrets=True`` for local debugging/troubleshooting
    when retaining exact credentials in artifacts is intentional.

    Suitable for FREE-FORM TEXT (log lines, error messages, command-line
    args). For filesystem paths use ``redact_url_secrets_only`` instead —
    paths can legitimately contain "Bearer X" or "Basic X" substrings as
    filename components, and the Bearer/Basic header patterns generate
    false positives in that context.
    """
    text = str(value)
    if reveal_secrets:
        return text

    # Redact URLs first so query-string context is preserved without leaking values.
    text = re.sub(r"https?://[^\s'\"<>]+", _redact_url, text)

    # Redact common authorization header schemes from logs and finding metadata.
    text = re.sub(
        r"Bearer [a-zA-Z0-9._~+/-]{20,}={0,2}",
        "Bearer [REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"Basic\s+[A-Za-z0-9+/]{8,}={0,2}",
        "Basic [REDACTED]",
        text,
        flags=re.IGNORECASE,
    )
    return text


def redact_url_secrets_only(value: object, *,
                             reveal_secrets: bool = False) -> str:
    """Redact URL-embedded credentials only — no Bearer/Basic patterns.

    For filesystem paths and other structured text where the Bearer/Basic
    HTTP-header patterns would produce false positives. A path like
    ``/tmp/Bearer abc123def456ghi789jkl.dat`` would be incorrectly
    redacted by ``redact_secrets`` despite not actually being a credential
    (it's a filename that happens to contain the substring "Bearer").

    URL-shaped substrings still get redacted because:
    - ``https://user:pass@host/path`` IS a credential leak regardless of
      whether it appears in a path component or a free-form log line.
    - URL pattern requires ``://`` so it doesn't false-match on filename
      content.
    """
    text = str(value)
    if reveal_secrets:
        return text
    text = re.sub(r"https?://[^\s'\"<>]+", _redact_url, text)
    return text

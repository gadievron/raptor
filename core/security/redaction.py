#!/usr/bin/env python3
"""Shared secret redaction helpers for RAPTOR outputs."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

# Vendor-published credential shapes. Each entry is a (vendor, regex)
# tuple — the vendor label is documentation only; only the compiled
# regex is used. Anchored on prefix-length-shape rather than just prefix
# so a bare prefix in prose ("OpenAI's sk- format") doesn't false-match.
_VENDOR_SECRET_PATTERNS = (
    # AWS access key ID (AKIA*) and secret-access-key context.
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    # AWS temporary credentials (ASIA*).
    re.compile(r"\bASIA[0-9A-Z]{16}\b"),
    # GitHub personal access tokens / fine-grained / app tokens.
    # ghp_ / gho_ / ghu_ / ghs_ / ghr_ + 36-char alnum body.
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{36}\b"),
    # GitHub fine-grained PAT (github_pat_ + 22-char prefix + _ + 59-char body).
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    # Slack tokens: xoxa-/xoxb-/xoxp-/xoxr-/xoxs-/xoxo- + version + body.
    re.compile(r"\bxox[abporst]-[0-9A-Za-z-]{10,}\b"),
    # OpenAI API key: `sk-` prefix + 48 alphanumeric chars (legacy)
    # OR `sk-proj-` + ≥40 chars (project-scoped, current).
    re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"),
    # Anthropic API key: `sk-ant-` + 95+ chars.
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{90,}\b"),
    # JSON Web Token: 3 base64url segments separated by dots. Strict
    # length floor on the body to avoid matching short dotted alphanum
    # tokens (e.g. `a.b.c` in source code).
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
    # Google API key: `AIza` + 35 chars.
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    # Stripe live secret key.
    re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"),
)

_SECRET_QUERY_KEYS = {
    "api_key",
    "apikey",
    "access_token",
    "accesstoken",
    "auth_token",
    "authtoken",
    "bearer_token",
    "bearertoken",
    "client_secret",
    "clientsecret",
    "consumer_secret",
    "consumersecret",
    "id_token",
    "idtoken",
    "refresh_token",
    "refreshtoken",
    "secret",
    "session_token",
    "sessiontoken",
    "service_token",
    "servicetoken",
    "token",
    # Common-but-missed names. `password` shows up in legacy URL forms
    # like `https://example.com/api?username=u&password=...`; `sig` is the
    # HMAC signature in many provider URL schemes (signed S3 URLs use
    # `Signature`, plain `sig` covers Slack / Twilio / etc.). The
    # `x-amz-*` family covers AWS SigV4 presigned URLs which carry the
    # signature in the query string.
    "password",
    "passwd",
    "pwd",
    "sig",
    "signature",
    "x-amz-signature",
    "x-amz-credential",
    "x-amz-security-token",
    "x-goog-signature",
    "auth",
    "authorization",
    "private_key",
}

_SECRET_FIELD_SUFFIXES = ("_token", "-token", "_secret", "-secret", "_key", "-key")


def is_secret_field_name(name: object) -> bool:
    """Return whether a field/parameter name conventionally carries a secret value."""
    normalized = str(name).strip().lower()
    return normalized in _SECRET_QUERY_KEYS or normalized.endswith(
        _SECRET_FIELD_SUFFIXES
    )


def _redact_url(match: re.Match[str]) -> str:
    raw_url = match.group(0)
    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return raw_url

    # Don't bail when netloc is empty — schemeless or netloc-less inputs
    # (`/api?token=secret`, `data:...`, custom schemes) still carry
    # secrets in the query string. Pre-fix, the early return skipped
    # query/fragment redaction entirely for any URL the caller passed
    # us that didn't match the http(s)://host shape exactly. The
    # public regex guards http/https today, but that's defence-in-depth
    # against future callers passing matches from a wider regex.
    if (
        not parsed.scheme
        and not parsed.netloc
        and not parsed.query
        and not parsed.fragment
    ):
        return raw_url

    netloc = parsed.netloc
    if netloc and "@" in netloc:
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
        f"{quote(key, safe='[]')}={quote(value, safe='[]/')}"
        for key, value in redacted_pairs
    )

    # OAuth 2.0 implicit-flow puts `access_token` / `id_token` in the
    # URL fragment, not the query string (so the token never crosses
    # the wire to the resource server). Pre-fix the fragment was
    # passed through verbatim — leaking the very tokens the spec uses
    # the fragment to protect from server logs. Apply the same
    # secret-key redaction to fragment params.
    fragment = parsed.fragment
    if fragment and "=" in fragment:
        fragment_pairs = parse_qsl(fragment, keep_blank_values=True)
        if fragment_pairs:
            fragment_pairs = [
                (key, "[REDACTED]" if key.lower() in _SECRET_QUERY_KEYS else value)
                for key, value in fragment_pairs
            ]
            fragment = "&".join(
                f"{quote(key, safe='[]')}={quote(value, safe='[]/')}"
                for key, value in fragment_pairs
            )

    return urlunsplit((parsed.scheme, netloc, parsed.path, query, fragment))


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

    # Vendor-specific credential patterns. Each matches the canonical
    # token shape published by the vendor; substring-only false positives
    # are acceptable here because the redaction target is shareable
    # logs / artifacts where false-positive redaction is far cheaper than
    # a credential leak. Order doesn't matter — patterns are mutually
    # disjoint by prefix.
    for pattern in _VENDOR_SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def redact_url_secrets_only(value: object, *, reveal_secrets: bool = False) -> str:
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

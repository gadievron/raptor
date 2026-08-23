#!/usr/bin/env python3
"""Shared secret redaction helpers for RAPTOR outputs."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

# Vendor-published credential shapes. Each entry is a
# (regex, replacement) tuple; context-anchored patterns keep the field
# name visible via a capture group so redacted artifacts stay
# triageable. Anchored on prefix-length-shape rather than just prefix
# so a bare prefix in prose ("OpenAI's sk- format") doesn't false-match.
_VENDOR_SECRET_PATTERNS = (
    # AWS access key ID (AKIA*) and secret-access-key context.
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    # AWS temporary credentials (ASIA*).
    (re.compile(r"\bASIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    # AWS *secret access key*: 40 chars of base64 with no
    # distinguishing prefix — anchor on the assignment context (the
    # field name every SDK/config spelling uses) so ordinary 40-char
    # base64 blobs in logs don't false-match.
    (re.compile(
        r"(?i)\b(aws_?secret_?(?:access_?)?key[\"']?\s*[=:]\s*[\"']?)"
        r"[A-Za-z0-9/+=]{30,60}"),
     r"\1[REDACTED]"),
    # PEM private-key blocks (PKCS#8 `PRIVATE KEY`, PKCS#1
    # `RSA PRIVATE KEY`, `EC/OPENSSH/...` variants). Body bounded;
    # the END-less fallback below catches truncated dumps.
    (re.compile(
        r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----"
        r"[A-Za-z0-9+/=\s]{0,20000}?"
        r"-----END [A-Z0-9 ]{0,32}PRIVATE KEY-----"),
     "[REDACTED-PRIVATE-KEY]"),
    (re.compile(
        r"-----BEGIN [A-Z0-9 ]{0,32}PRIVATE KEY-----"
        r"[ \t]*\r?\n[A-Za-z0-9+/=\r\n \t]{16,20000}"),
     "[REDACTED-PRIVATE-KEY]"),
    # Azure storage account key (connection-string AccountKey= field).
    (re.compile(r"(?i)\b(AccountKey\s*=\s*)[A-Za-z0-9+/=]{40,}"),
     r"\1[REDACTED]"),
    # Azure AD client secret: `xQ~` marker + 30-45 char body.
    (re.compile(r"\b[0-9A-Za-z]?[78]Q~[A-Za-z0-9_~.-]{30,45}"),
     "[REDACTED]"),
    # GitHub personal access tokens / fine-grained / app tokens.
    # ghp_ / gho_ / ghu_ / ghs_ / ghr_ + 36-char alnum body.
    (re.compile(r"\bgh[opusr]_[A-Za-z0-9]{36}\b"), "[REDACTED]"),
    # GitHub fine-grained PAT (github_pat_ + 22-char prefix + _ + 59-char body).
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"), "[REDACTED]"),
    # Slack tokens. Full letter class: beyond the app/bot/user set,
    # `xoxc` (browser session) and `xoxe` (refresh) are live secret
    # shapes — any xox?- + version + body redacts.
    (re.compile(r"\bxox[a-z]-[0-9A-Za-z-]{10,}\b"), "[REDACTED]"),
    # Google OAuth refresh token: `1//` + long base64url body. The
    # body-length floor keeps Python floor-division expressions
    # (`1//divisor`) from false-matching.
    (re.compile(r"\b1//[0-9A-Za-z_-]{28,}"), "[REDACTED]"),
    # OpenAI API key: `sk-` prefix + 48 alphanumeric chars (legacy)
    # OR `sk-proj-` + ≥40 chars (project-scoped, current).
    (re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b"), "[REDACTED]"),
    # Anthropic API key: `sk-ant-` + 95+ chars.
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{90,}\b"), "[REDACTED]"),
    # JSON Web Token: 3 base64url segments separated by dots. The
    # first segment is base64('{...') — `eyJ` for the canonical
    # compact header but `eyA`/`ewo`/`ewk`/`ew0` for headers with
    # whitespace after the brace (still valid JWTs to every verifier
    # that base64-decodes first). Match the `e[wy]` prefix class
    # (= any JSON-object first byte); strict length floors on all
    # three segments keep `a.b.c`-style dotted tokens out.
    (re.compile(
        r"\be[wy][A-Za-z0-9_-]{7,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
     "[REDACTED]"),
    # Google API key: `AIza` + 35 chars.
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "[REDACTED]"),
    # Stripe live secret key.
    (re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), "[REDACTED]"),
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

_SECRET_FIELD_SUFFIXES = (
    "_token", "-token", "_secret", "-secret", "_key", "-key",
    "_password", "-password", "_passwd", "-passwd", "_pwd", "-pwd",
)


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
        (key, "[REDACTED]" if is_secret_field_name(key) else value)
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
                (key, "[REDACTED]" if is_secret_field_name(key) else value)
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
    # URL token cap: PATH_MAX is 4096; HTTP/2 Authority + Path
    # rarely exceeds 8 KB before proxies start rejecting. A
    # 100 KB single URL is essentially never legitimate; cap at
    # 8 KB so a pathological log line containing a megabyte-long
    # quoted "URL" doesn't pin the regex engine on this scan.
    # Pre-fix the unbounded `[^\s'"<>]+` would happily consume
    # any length of non-whitespace, and `re.sub` has no cap on
    # match length — operator-supplied logs containing such a
    # string took O(n) per redact_secrets() call, multiplied
    # across every record processed by reporters.
    # `()` added to exclusions so URLs in prose (`see https://example.com/`
    # at end of sentence, or `(https://example.com/?token=abc)`)
    # don't have the trailing punctuation captured as URL chars
    # — `_redact_url`'s urlsplit then includes the `)` in the
    # path/query and the redacted output preserves the malformed
    # tail visible in logs.
    text = re.sub(
        # Any RFC-3986 scheme, not just http(s): connection strings
        # (postgres://, mongodb+srv://, redis://, amqp://, ftp://, ...)
        # carry credentials in the SAME userinfo/query positions and
        # slipped through the http-only pattern verbatim.
        r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s'\"<>()]{1,8192}",
        _redact_url, text)

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
    for pattern, replacement in _VENDOR_SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
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
    # URL token cap: PATH_MAX is 4096; HTTP/2 Authority + Path
    # rarely exceeds 8 KB before proxies start rejecting. A
    # 100 KB single URL is essentially never legitimate; cap at
    # 8 KB so a pathological log line containing a megabyte-long
    # quoted "URL" doesn't pin the regex engine on this scan.
    # Pre-fix the unbounded `[^\s'"<>]+` would happily consume
    # any length of non-whitespace, and `re.sub` has no cap on
    # match length — operator-supplied logs containing such a
    # string took O(n) per redact_secrets() call, multiplied
    # across every record processed by reporters.
    # `()` added to exclusions so URLs in prose (`see https://example.com/`
    # at end of sentence, or `(https://example.com/?token=abc)`)
    # don't have the trailing punctuation captured as URL chars
    # — `_redact_url`'s urlsplit then includes the `)` in the
    # path/query and the redacted output preserves the malformed
    # tail visible in logs.
    return re.sub(
        # Any RFC-3986 scheme, not just http(s): connection strings
        # (postgres://, mongodb+srv://, redis://, amqp://, ftp://, ...)
        # carry credentials in the SAME userinfo/query positions and
        # slipped through the http-only pattern verbatim.
        r"\b[a-zA-Z][a-zA-Z0-9+.-]{0,31}://[^\s'\"<>()]{1,8192}",
        _redact_url, text)

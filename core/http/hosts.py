"""Canonical HTTP transport host keys for proxy grants and DNS pinning.

This is normalization, not URL validation or origin admission. ASCII spellings
(including IP literals and internal DNS names) retain the existing transport
semantics. Callers must separately validate URLs and enforce their permissions.
"""

from __future__ import annotations


_HOST_DOT_VARIANTS = ".。．｡"


def canonical_transport_host(host: object) -> str:
    """Fold case, trailing label separators and IDNA2008/UTS46 spellings.

    Return an empty key for None, non-ASCII bytes or an IDNA conversion
    failure. Keep the IDNA library lazy so ASCII-only paths need no encoding
    work. This is the historical web DNS-pin normalization contract.
    """
    if host is None:
        return ""
    if isinstance(host, (bytes, bytearray)):
        try:
            text = bytes(host).decode("ascii")
        except UnicodeDecodeError:
            return ""
    else:
        text = str(host)
    text = text.rstrip(_HOST_DOT_VARIANTS).lower()
    if not text or text.isascii():
        return text
    try:
        import idna
        return idna.encode(text, uts46=True).decode("ascii")
    except Exception:
        # A failed conversion cannot be a pin key or proxy grant. Do not
        # substitute the stdlib IDNA2003 codec, which can name another host.
        return ""

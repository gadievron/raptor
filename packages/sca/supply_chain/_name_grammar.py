"""Per-ecosystem package-name grammar for the typosquat trusted set.

The popularity feeds are UNVALIDATED remote input, and every name
they carry becomes a trusted exact-match in the typosquat detector
(an attacker-relevant capability: a garbage row can never be a real
package, but a poisoned feed row COULD be — and malformed rows have
already shipped, e.g. ``"equire('express'"`` in the npm bundle,
scraped markup that then sat in the trusted set).  Names from a
feed also flow into the refresh PR's markdown body.

One grammar per ecosystem, applied at BOTH ends:

  * fetch time (``refresh_typosquat_lists``) — garbage never enters
    a bundle;
  * load time (``typosquat._load_popular``) — garbage already in a
    shipped/operator-edited bundle stops being trusted.

The regexes follow each registry's published naming rules, slightly
relaxed where registries grandfathered legacy names.  Anything that
fails is dropped (logged by the caller); a dropped legitimate name
costs one missing trusted entry, a kept garbage row pollutes the
trusted set — the asymmetry favours dropping.
"""

from __future__ import annotations

import re

# Registry hard cap (npm's 214) reused as a sanity ceiling everywhere.
_MAX_NAME_LEN = 214

_GRAMMARS: dict[str, re.Pattern[str]] = {
    # validate-npm-package-name's new-package rule.
    "npm": re.compile(
        r"^(?:@[a-z0-9\-~][a-z0-9\-._~]*/)?[a-z0-9\-~][a-z0-9\-._~]*$",
    ),
    # PEP 508 name (stored lowercased).
    "PyPI": re.compile(r"^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$"),
    # crates.io: alphanumeric plus - and _ (stored lowercased).
    "Cargo": re.compile(r"^[a-z0-9][a-z0-9_-]*$"),
    # Composer vendor/package rule: alnum runs joined by single
    # ``_``/``.``/``-`` separators (the package half also allows
    # ``--``).  Written with a mandatory separator per repetition —
    # the optional-separator form Composer publishes is ambiguous
    # (an alnum run splits into repetitions many ways) and
    # backtracks exponentially on hostile feed rows; this form
    # accepts the same language in linear time.
    "Packagist": re.compile(
        r"^[a-z0-9]+([_.-][a-z0-9]+)*/[a-z0-9]+(([_.]|-{1,2})[a-z0-9]+)*$",
    ),
    # Go module path (host/path segments).
    "Go": re.compile(
        r"^[a-z0-9][a-z0-9.\-]*(?:/[a-z0-9._~\-]+)+$",
    ),
    # Maven group:artifact coordinates.
    "Maven": re.compile(
        r"^[A-Za-z0-9_.\-]+:[A-Za-z0-9_.\-]+$",
    ),
    # NuGet package ids (dotted, case-preserved).
    "NuGet": re.compile(r"^[A-Za-z0-9_.\-]+$"),
    # RubyGems: letters, digits, - _ . (must contain a letter).
    "RubyGems": re.compile(r"^(?=.*[a-z])[a-z0-9._\-]+$"),
}


def valid_feed_name(ecosystem: str, name: object) -> bool:
    """True iff ``name`` is a string matching ``ecosystem``'s
    package-name grammar.  Unknown ecosystems fail closed — a feed
    for an ecosystem without a grammar here must not mint trusted
    entries."""
    if not isinstance(name, str):
        return False
    if not 0 < len(name) <= _MAX_NAME_LEN:
        return False
    grammar = _GRAMMARS.get(ecosystem)
    if grammar is None:
        return False
    # fullmatch, not match: with ``match`` the patterns' ``$`` accepts
    # a single trailing newline (``"express\n"`` — a poisoned feed row
    # distinct from the real package — would enter the trusted set).
    return grammar.fullmatch(name) is not None


__all__ = ["valid_feed_name"]

"""Offline Public Suffix List lookups shared across RAPTOR consumers."""

import ipaddress
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

PSL_PATH = Path(__file__).with_name("data") / "public_suffix_list.dat"


@dataclass(frozen=True)
class SuffixRules:
    """Suffixes without the *. / ! rule prefixes, normalized to ASCII."""

    exact: frozenset[str]
    wildcard: frozenset[str]
    exceptions: frozenset[str]


def _normalize_host(host: str) -> str:
    # Preserve distinct IDNA2008 labels (e.g. faß vs fass). Python's
    # legacy IDNA codec folds them together, which would widen this allowlist.
    labels = host.rstrip(".").lower().split(".")
    return ".".join(label if label.isascii() else
                    "xn--" + label.encode("punycode").decode("ascii")
                    for label in labels)


def parse_suffix_list(text: str) -> SuffixRules:
    """Validate a complete upstream snapshot and return immutable rules."""
    for section in ("ICANN", "PRIVATE"):
        for edge in ("BEGIN", "END"):
            if f"// ==={edge} {section} DOMAINS===" not in text:
                raise ValueError("incomplete public suffix list")
    exact, wildcard, exceptions = set(), set(), set()
    for line in text.splitlines():
        if not line or line.startswith("//"):
            continue
        if line != line.strip() or any(c.isspace() for c in line):
            raise ValueError("whitespace in public suffix rule")
        target = exact
        if line.startswith("!"):
            target, line = exceptions, line[1:]
        elif line.startswith("*."):
            target, line = wildcard, line[2:]
        rule = _normalize_host(line)
        if any(not label or len(label) > 63 or
               any(c not in "abcdefghijklmnopqrstuvwxyz0123456789-" for c in label)
               for label in rule.split(".")):
            raise ValueError("invalid public suffix rule")
        target.add(rule)
    if len(exact) < 1000 or not wildcard or not exceptions:
        raise ValueError("truncated public suffix list")
    return SuffixRules(frozenset(exact), frozenset(wildcard), frozenset(exceptions))


@lru_cache(maxsize=1)
def load_suffix_rules() -> SuffixRules:
    """Load and cache the bundled immutable exact/wildcard/exception rules."""
    return parse_suffix_list(PSL_PATH.read_text(encoding="utf-8"))



def registrable_domain(host: str) -> str | None:
    """Return eTLD+1 using ICANN and PRIVATE rules, or None for a suffix.

    IP literals return their own normalized spelling. Invalid hosts and
    unavailable/invalid snapshots raise ValueError/OSError; callers must
    choose their own failure policy. No network requests are performed.
    """
    host = _normalize_host(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    rules = load_suffix_rules()
    labels = host.split(".")
    suffix_length = 1  # PSL default rule: *
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in rules.exceptions:
            suffix_length = len(labels) - i - 1
            break
        if suffix in rules.exact:
            suffix_length = max(suffix_length, len(labels) - i)
        if i > 0 and suffix in rules.wildcard:
            suffix_length = max(suffix_length, len(labels) - i + 1)
    if len(labels) <= suffix_length:
        return None  # A public suffix itself grants no tenant-wide access.
    return ".".join(labels[-(suffix_length + 1):])

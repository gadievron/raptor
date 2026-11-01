"""Offline Public Suffix List lookups shared across RAPTOR consumers."""

import ipaddress
from collections.abc import Iterable
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Literal

PSL_PATH = Path(__file__).with_name("data") / "public_suffix_list.dat"


@dataclass(frozen=True)
class SuffixRules:
    """Suffixes without the *. / ! rule prefixes, normalized to ASCII."""

    exact: frozenset[str]
    wildcard: frozenset[str]
    exceptions: frozenset[str]


@dataclass(frozen=True)
class DomainBoundary:
    """A normalized identity, its inferred domain, and the rule's provenance."""

    hostname: str
    registrable_domain: str | None
    public_suffix: str | None
    rule: str | None
    source: Literal["psl", "default", "ip"]


class InvalidHostname(ValueError):
    """Input is not a bounded DNS hostname or IP literal."""


def _normalize_host(host: str, *, allow_underscores: bool = False) -> str:
    # Bound work before splitting or Punycode conversion. DNS names have
    # at most 253 ASCII characters, plus one optional trailing root dot.
    if not host or len(host) > 254:
        raise InvalidHostname("hostname exceeds DNS length bounds or is empty")
    host = host[:-1] if host.endswith(".") else host
    # Preserve distinct IDNA2008 labels (e.g. faß vs fass). Python's
    # legacy IDNA codec folds them together, which would widen this allowlist.
    labels = host.lower().split(".")
    try:
        normalized = ".".join(label if label.isascii() else
                              "xn--" + label.encode("punycode").decode("ascii")
                              for label in labels)
    except UnicodeError as exc:
        raise InvalidHostname("invalid Unicode hostname") from exc
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789-" + ("_" if allow_underscores else "")
    if len(normalized) > 253 or any(
            not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
            or any(c not in alphabet for c in label)
            for label in normalized.split(".")):
        raise InvalidHostname("invalid DNS label or hostname length")
    return normalized


def parse_suffix_list(text: str) -> SuffixRules:
    """Validate a complete upstream snapshot and return immutable rules."""
    for section in ("ICANN", "PRIVATE"):
        for edge in ("BEGIN", "END"):
            if f"// ==={edge} {section} DOMAINS===" not in text:
                raise ValueError("incomplete public suffix list")
    exact: set[str] = set()
    wildcard: set[str] = set()
    exceptions: set[str] = set()
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



def domain_boundary(host: str, *, allow_underscores: bool = False) -> DomainBoundary:
    """Return an offline PSL boundary with explicit/default/IP provenance.

    Only source='psl' denotes a boundary from the bundled list. The default
    '*' rule is a naming heuristic, not evidence of shared ownership.
    Underscores are accepted only by explicit consumer opt-in for private
    DNS telemetry or source analysis. Length bounds apply in either mode.
    Invalid input raises InvalidHostname; invalid/unavailable data raises
    ValueError/OSError. No network request or silent data fallback occurs.
    """
    if not host or len(host) > 254:
        raise InvalidHostname("hostname exceeds DNS length bounds or is empty")
    try:
        address = str(ipaddress.ip_address(host))
        return DomainBoundary(address, address, None, None, "ip")
    except ValueError:
        pass
    host = _normalize_host(host, allow_underscores=allow_underscores)
    rules = load_suffix_rules()
    labels = host.split(".")
    suffix_length = 1
    matched_rule = None
    for i in range(len(labels)):
        suffix = ".".join(labels[i:])
        if suffix in rules.exceptions:
            suffix_length = len(labels) - i - 1
            matched_rule = "!" + suffix
            break
        if suffix in rules.exact and len(labels) - i >= suffix_length:
            suffix_length = len(labels) - i
            matched_rule = suffix
        if i > 0 and suffix in rules.wildcard and len(labels) - i + 1 >= suffix_length:
            suffix_length = len(labels) - i + 1
            matched_rule = "*." + suffix
    domain = (None if len(labels) <= suffix_length else
              ".".join(labels[-(suffix_length + 1):]))
    return DomainBoundary(host, domain, ".".join(labels[-suffix_length:]),
                          matched_rule, "psl" if matched_rule else "default")


def registrable_domain(host: str) -> str | None:
    """Return eTLD+1, preserving the original default-rule lookup API.

    Use domain_boundary() when decisions depend on whether the suffix was
    explicitly listed. IP literals return their normalized identity.
    """
    return domain_boundary(host).registrable_domain


def _share_known_domain(a: DomainBoundary, b: DomainBoundary) -> bool:
    return (a.source == b.source == "psl"
            and a.registrable_domain is not None
            and a.registrable_domain == b.registrable_domain)


def same_registrable_domain(a: str, b: str, *, allow_underscores: bool = False) -> bool:
    """Whether hosts share an explicit PSL tenant boundary.

    Default-rule matches, public suffixes themselves, and IPs return False.
    Invalid input or unavailable/invalid PSL data raises, never returns False.
    """
    load_suffix_rules()
    return _share_known_domain(
        domain_boundary(a, allow_underscores=allow_underscores),
        domain_boundary(b, allow_underscores=allow_underscores))


def host_matches_anchor(host: str, anchor_host: str, *, extra_hosts: Iterable[str] = ()) -> bool:
    """Match exact hosts or an explicit PSL tenant shared with the anchor.

    Arguments are hostnames/IP literals, not URLs. Extras are exact host
    grants only. Unknown/private suffixes and IPs receive no inferred wider
    access. Strict hostname validation applies. Missing/invalid data and
    invalid inputs raise, including for exact matches; callers must deny on
    these errors. HTTPS, anchor provenance, and logging belong to the caller.
    """
    load_suffix_rules()
    target = domain_boundary(host)
    anchor = domain_boundary(anchor_host)
    extras = {domain_boundary(extra).hostname for extra in extra_hosts}
    return (target.hostname == anchor.hostname or target.hostname in extras
            or _share_known_domain(target, anchor))

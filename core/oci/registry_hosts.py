"""Resolve a list of HTTPS hosts the sandbox must allow for a given
image reference's registry to work.

The sandbox's egress proxy takes a static allowlist
(``proxy_hosts=[...]``) at run time. For OCI work, the host(s) we
need depend on the image's registry, and some registries (notably
Docker Hub) split into multiple hosts: ``registry-1.docker.io``
serves manifests + blobs but ``auth.docker.io`` issues bearer tokens.

This resolver knows the well-known mappings. Project-internal /
self-hosted registries pass through as-is (``my-registry.corp.example``
just allows itself).

Adding a new registry family: extend ``_REGISTRY_FAMILIES`` with a
predicate + list of hosts. Tests should add coverage for the
predicate edge cases.
"""

from __future__ import annotations

import ipaddress
import re
import socket

from .image_ref import ImageRef, parse_image_ref
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable


# RFC-1123 hostname label: alnum, optional interior hyphens, 63 max.
_HOSTNAME_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

# Label shapes glibc's resolver treats as numeric address components
# rather than DNS names: decimal (127, 2130706433), hex (0x7f000001),
# octal (0177). A hostname built ONLY from such labels is an address
# literal in every getaddrinfo implementation that falls back to
# inet_aton and can never be a legitimate DNS registry name.
_NUMERIC_LABEL_RE = re.compile(r"^(?:0x[0-9a-f]*|[0-9]+)$")

# IPv6 prefixes that embed an IPv4 address in their low 32 bits:
# RFC 6052 well-known NAT64 prefix + RFC 8215 local-use NAT64 space.
_NAT64_NETS = (
    ipaddress.ip_network("64:ff9b::/96"),
    ipaddress.ip_network("64:ff9b:1::/48"),
)


def _split_registry_host_port(registry: str) -> tuple[str, str | None, bool]:
    """Split ``registry`` into ``(host, port, bracketed)``.

    Handles both ``host[:port]`` and bracketed-IPv6 ``[v6][:port]``
    authorities. Raises :class:`ValueError` on malformed bracket
    syntax; port VALUE validation is the caller's job.
    """
    host = registry
    port: str | None = None
    bracketed = False
    if host.startswith("["):
        bracketed = True
        end = host.find("]")
        if end < 0:
            raise ValueError(f"malformed registry host {registry!r}")
        rest = host[end + 1:]
        host = host[1:end]
        if rest:
            if not rest.startswith(":"):
                raise ValueError(f"malformed registry host {registry!r}")
            port = rest[1:]
    elif host.count(":") == 1:
        host, port = host.split(":", 1)
    return host, port, bracketed


def _as_ip_literal(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse ``host`` as an address literal, normalising BEFORE any
    policy decision. Returns ``None`` only for genuine hostnames.

    ``ipaddress.ip_address`` alone is NOT the resolver's grammar:
    glibc's getaddrinfo falls back to ``inet_aton``, which also
    accepts shorthand dotted forms (``127.1``), bare decimal
    (``2130706433``), hex (``0x7f000001``), octal (``0177.0.0.1``)
    and combinations — all resolving without DNS to addresses the
    string-shape check never saw. A single trailing dot is stripped
    for evaluation (``127.0.0.1.`` resolves like ``127.0.0.1``).
    """
    candidate = host[:-1] if host.endswith(".") else host
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        pass
    try:
        return ipaddress.IPv4Address(socket.inet_aton(candidate))
    except OSError:
        return None


def _embedded_ipv4(
    ip6: ipaddress.IPv6Address,
) -> ipaddress.IPv4Address | None:
    """Extract an IPv4 address embedded in ``ip6``, if any.

    Covers IPv4-mapped (``::ffff:a.b.c.d``), NAT64 (RFC 6052
    ``64:ff9b::/96`` + RFC 8215 ``64:ff9b:1::/48``), 6to4
    (``2002::/16``), Teredo (``2001::/32``, client address) and the
    deprecated IPv4-compatible ``::a.b.c.d`` form. A NAT64 mapping of
    a non-global IPv4 (e.g. ``64:ff9b::a9fe:a9fe`` = 169.254.169.254)
    is ``is_global=True`` as an IPv6 address, so the embedded v4 must
    be policy-checked separately.
    """
    if ip6.ipv4_mapped is not None:
        return ip6.ipv4_mapped
    if any(ip6 in net for net in _NAT64_NETS):
        return ipaddress.IPv4Address(int(ip6) & 0xFFFFFFFF)
    if ip6.sixtofour is not None:
        return ip6.sixtofour
    teredo = ip6.teredo
    if teredo is not None:
        return teredo[1]
    value = int(ip6)
    if value >> 32 == 0 and (value & 0xFFFFFFFF) > 1:
        return ipaddress.IPv4Address(value & 0xFFFFFFFF)
    return None


def _refuse_non_global_ip(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    registry: str,
) -> None:
    """Raise :class:`ValueError` unless ``ip`` (and any IPv4 address
    embedded in an IPv6 ``ip``) is globally routable."""
    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not embedded.is_global:
            raise ValueError(
                f"refusing registry host {registry!r}: {ip} embeds "
                f"IPv4 address {embedded}, which is not globally "
                f"routable (NAT64/mapped forms of loopback/private/"
                f"link-local addresses are refused; SSRF defence)")
    if not ip.is_global:
        raise ValueError(
            f"refusing registry host {registry!r}: {ip} is not "
            f"globally routable (loopback/private/link-local "
            f"registries from target-derived references are "
            f"refused; SSRF defence)")


def _validate_registry_host(registry: str) -> None:
    """Refuse registry hosts that would point egress at non-global
    addresses, plus malformed hostnames. Raises :class:`ValueError`.

    Registry names outside the well-known families are
    target-derived (Dockerfile FROM lines, compose/Helm/CI files in
    a scanned repo) — attacker-influenced. Without this gate they
    pass through as their own host, join the sandbox proxy
    allowlist, and drive HTTPS GETs at loopback / RFC1918 /
    link-local endpoints (including 169.254.169.254 cloud metadata).

    Rules (normalise FIRST, then apply policy — the resolver's
    address grammar is wider than ``ipaddress``'s, so the policy
    must run on the PARSED address, never on the string shape):
      * IP-literal hosts — including every ``inet_aton`` shape
        getaddrinfo resolves without DNS (``127.1``, bare decimal
        ``2130706433``, hex ``0x7f000001``, octal ``0177.0.0.1``,
        trailing-dot forms) — must be globally routable
        (``ipaddress.is_global`` — refuses loopback, private,
        link-local, shared 100.64/10, reserved, unspecified).
      * IPv6 literals additionally have any embedded IPv4 address
        (NAT64, IPv4-mapped, 6to4, Teredo, IPv4-compatible)
        held to the same policy — ``64:ff9b::a9fe:a9fe`` is
        ``is_global=True`` yet routes to 169.254.169.254.
      * ``localhost`` / ``*.localhost`` refused by name.
      * Hostnames must be valid RFC-1123 shapes (refuses
        underscores, empty labels, over-length names) so malformed
        names can't smuggle odd syntax into allowlists or URLs;
        names built ONLY from numeric/hex/octal labels are refused
        even when ``inet_aton`` couldn't parse them (they are
        address syntax to some resolvers, never real registries).
      * An optional ``:port`` must be a sane numeric port.
    """
    host, port, bracketed = _split_registry_host_port(registry)
    if bracketed:
        try:
            ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = \
                ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(
                f"malformed registry host {registry!r}: bracketed "
                f"authority is not an IP literal") from None
    else:
        ip = _as_ip_literal(host)
    if port is not None:
        if not port.isdigit() or not 1 <= int(port) <= 65535:
            raise ValueError(
                f"malformed registry port in {registry!r}")
    if ip is not None:
        _refuse_non_global_ip(ip, registry)
        return
    name = host.lower().rstrip(".")
    if name == "localhost" or name.endswith(".localhost"):
        raise ValueError(
            f"refusing registry host {registry!r}: localhost "
            f"registries from target-derived references are refused "
            f"(SSRF defence)")
    if not name or len(name) > 253 or not all(
        _HOSTNAME_LABEL_RE.match(label) for label in name.split(".")
    ):
        raise ValueError(f"malformed registry hostname {registry!r}")
    if all(_NUMERIC_LABEL_RE.match(label) for label in name.split(".")):
        # inet_aton refused it (e.g. ``1.2.3.4.5``, ``300.1.2.3``)
        # but every label is numeric/hex/octal address syntax — some
        # resolvers are laxer than the local inet_aton, and no
        # legitimate registry is named this way. Refuse outright
        # rather than let it reach DNS.
        raise ValueError(
            f"refusing registry host {registry!r}: numeric hostname "
            f"shape is address syntax, not a DNS name (SSRF defence)")


def validate_resolved_registry_addresses(registry: str) -> None:
    """Resolve ``registry``'s host and refuse when ANY resolved
    address is non-global. Raises :class:`ValueError`.

    :func:`_validate_registry_host` is parse-time-only: it judges the
    NAME. A hostname that passes every string-shape rule can still
    resolve to loopback / RFC1918 / link-local / metadata addresses
    (attacker-controlled DNS, DNS rebinding, split-horizon private
    DNS), landing egress on internal endpoints. This gate runs at
    request time on the addresses ``getaddrinfo`` actually returns:

      * every A and AAAA answer must be globally routable;
      * AAAA answers additionally have any embedded IPv4
        (NAT64 / IPv4-mapped / 6to4 / Teredo) held to the same
        policy — ``64:ff9b::a9fe:a9fe`` is ``is_global=True`` yet
        routes to 169.254.169.254;
      * a host that does not resolve at all is refused (fail
        closed — the fetch could not succeed anyway, and a
        selectively-failing resolver must not downgrade the gate).

    IP-literal hosts skip DNS and get the literal policy directly.
    TOCTOU note: the subsequent connect re-resolves, so a rebinding
    attacker must win a race per request instead of passing a
    one-time parse check; combine with the parse-time gate rather
    than replacing it.
    """
    host, _port, bracketed = _split_registry_host_port(registry)
    if bracketed:
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            raise ValueError(
                f"malformed registry host {registry!r}: bracketed "
                f"authority is not an IP literal") from None
        _refuse_non_global_ip(ip, registry)
        return
    literal = _as_ip_literal(host)
    if literal is not None:
        _refuse_non_global_ip(literal, registry)
        return
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(
            f"refusing registry host {registry!r}: cannot resolve "
            f"({exc}); unresolvable target-derived registries are "
            f"refused rather than probed") from exc
    for family, _stype, _proto, _canon, sockaddr in infos:
        if family not in (socket.AF_INET, socket.AF_INET6):
            continue
        # AAAA sockaddrs may carry a ``%zone`` suffix on link-local
        # answers; strip it before parsing.
        addr_text = str(sockaddr[0]).split("%", 1)[0]
        try:
            resolved = ipaddress.ip_address(addr_text)
        except ValueError:
            raise ValueError(
                f"refusing registry host {registry!r}: resolver "
                f"returned unparseable address {sockaddr[0]!r}") from None
        try:
            _refuse_non_global_ip(resolved, registry)
        except ValueError as exc:
            raise ValueError(
                f"refusing registry host {registry!r}: resolves to "
                f"{resolved}, which is not globally routable "
                f"(loopback/private/link-local DNS answers for "
                f"target-derived registries are refused; "
                f"DNS-rebinding defence)") from exc


# Each entry is (predicate, hosts). The predicate takes the image's
# registry (e.g. "docker.io" or "1234.dkr.ecr.us-east-1.amazonaws.com")
# and returns True if this family applies. First match wins.
_REGISTRY_FAMILIES: list[tuple[Callable[[str], bool], list[str]]] = [
    # Docker Hub: manifests on registry-1, tokens on auth.
    (lambda r: r == "docker.io",
     ["registry-1.docker.io", "auth.docker.io"]),

    # GitHub Container Registry: single host, anonymous OK for public.
    (lambda r: r == "ghcr.io", ["ghcr.io"]),

    # GitHub Packages (legacy npm/maven, not OCI but operators
    # sometimes write ``docker.pkg.github.com/...``).
    (lambda r: r == "docker.pkg.github.com",
     ["docker.pkg.github.com"]),

    # AWS ECR private — host shape ``<acct>.dkr.ecr.<region>.amazonaws.com``.
    # ECR auth uses STS-issued tokens; the host itself plus the STS
    # endpoint for the region.
    (lambda r: bool(re.match(
        r"^\d+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com$", r,
    )),
     # The STS regional host gets injected at runtime since the
     # region is in the registry name. The list-form helper below
     # handles that. For static use, allow the registry alone and
     # let the ECR auth code add STS dynamically.
     []),       # filled by ``_aws_ecr_hosts(registry)`` below

    # AWS ECR public — ``public.ecr.aws``.
    (lambda r: r == "public.ecr.aws", ["public.ecr.aws"]),

    # Quay.io.
    (lambda r: r == "quay.io", ["quay.io"]),

    # Google Container Registry / Artifact Registry.
    (lambda r: r in {"gcr.io", "us.gcr.io", "eu.gcr.io", "asia.gcr.io"},
     [None]),     # fill the registry-name as the host (see below)
    (lambda r: r.endswith("-docker.pkg.dev"),
     [None]),     # Artifact Registry: <region>-docker.pkg.dev

    # Azure Container Registry — ``<name>.azurecr.io``.
    (lambda r: r.endswith(".azurecr.io"), [None]),

    # GitLab Container Registry — usually ``registry.gitlab.com`` for
    # the SaaS, or ``registry.<host>`` for self-hosted.
    (lambda r: r == "registry.gitlab.com", ["registry.gitlab.com"]),

    # Elastic's container registry — manifests on docker.elastic.co,
    # tokens on docker-auth.elastic.co. Same auth-host split as Docker
    # Hub. Missing from the registry-family map was surfaced by the
    # May 2026 200-project sweep: any project with
    # ``FROM docker.elastic.co/...`` (multiple Maven-Elasticsearch
    # variants) emitted repeated egress-proxy DENYs on
    # ``docker-auth.elastic.co``.
    (lambda r: r == "docker.elastic.co",
     ["docker.elastic.co", "docker-auth.elastic.co"]),
]


def registry_hosts_for(image: str | ImageRef) -> list[str]:
    """Return the list of HTTPS hostnames the sandbox must allow for
    operations against ``image``'s registry.

    Accepts either a raw image reference string (parsed via
    :func:`core.oci.image_ref.parse_image_ref`) or a pre-parsed
    :class:`ImageRef`. Always returns at least one host — the image's
    own registry — even when the registry isn't in the well-known
    families list.

    For ECR private registries the regional STS host is added so the
    auth dance succeeds. The list is deduplicated and order-stable.
    """
    ref = parse_image_ref(image) if isinstance(image, str) else image

    registry = ref.registry
    out: list[str] = []
    matched_family = False
    for predicate, hosts in _REGISTRY_FAMILIES:
        if not predicate(registry):
            continue
        matched_family = True
        if hosts == []:                            # ECR private special-case
            out.extend(_aws_ecr_hosts(registry))
        elif hosts == [None]:                      # registry name IS the host
            out.append(registry)
        else:
            out.extend(hosts)
        break

    if not matched_family:
        # Unknown registry — assume the host is the registry name
        # itself. Operators with self-hosted / corporate registries
        # always satisfy this (their registry IS its own host); the
        # failure mode for genuinely-bogus references is later, when
        # the auth or manifest call fails clearly. Unknown names are
        # target-derived, so they must pass the address / hostname
        # policy BEFORE joining any egress allowlist.
        _validate_registry_host(registry)
        out.append(registry)

    # Dedup, preserve order.
    seen = set()
    deduped: list[str] = []
    for h in out:
        if h not in seen:
            seen.add(h)
            deduped.append(h)
    return deduped


def _aws_ecr_hosts(registry: str) -> list[str]:
    """ECR private: the registry host plus the regional STS endpoint
    for the auth dance.

    Registry shape: ``<account>.dkr.ecr.<region>.amazonaws.com``.
    Extract ``<region>``, return ``[registry, "sts.<region>.amazonaws.com",
    "ecr.<region>.amazonaws.com"]``. ``ecr.<region>.amazonaws.com`` is the
    AWS API endpoint that issues authorization tokens; ``sts`` is for
    role assumption when credentials are role-based."""
    match = re.match(
        r"^\d+\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com$", registry,
    )
    if not match:
        return [registry]
    region = match.group(1)
    return [
        registry,
        f"ecr.{region}.amazonaws.com",
        f"sts.{region}.amazonaws.com",
    ]


def api_endpoint_for(registry: str) -> str:
    """Return the actual HTTPS hostname to send registry-API requests to.

    For most registries this is the canonical name itself
    (``ghcr.io`` -> ``ghcr.io``). Docker Hub is the notable
    exception: the canonical name ``docker.io`` is a brand /
    namespace identifier, but the v2 API lives at
    ``registry-1.docker.io``. Connecting to ``docker.io`` directly
    returns 301-to-marketing-page or fails, depending on the path.

    Used by :class:`core.oci.client.RegistryClient` when building
    request URLs. Pairs with :func:`registry_hosts_for` which
    returns the same hostnames for sandbox-allowlist purposes —
    the proxy must permit whatever the client actually CONNECTs to,
    not the canonical name.
    """
    if registry == "docker.io":
        return "registry-1.docker.io"
    # Same address / hostname policy as the allowlist path — the
    # client resolves every request URL through here, so a
    # target-derived registry naming a loopback / private /
    # metadata endpoint is refused even when the caller skipped
    # registry_hosts_for. Well-known family hosts all satisfy the
    # policy trivially.
    _validate_registry_host(registry)
    return registry


__all__ = [
    "api_endpoint_for",
    "registry_hosts_for",
    "validate_resolved_registry_addresses",
]

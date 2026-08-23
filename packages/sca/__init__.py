"""RAPTOR SCA Package — Software Composition Analysis.

Houses the SCA-specific config that the rest of the package threads
into otherwise-generic ``core.http`` / ``core.json.cache`` machinery:

  - :data:`SCA_USER_AGENT` — pinned user-agent so /sca traffic is
    identifiable in OSV / KEV / EPSS rate-limit logs.
  - :data:`SCA_CACHE_ROOT` — default disk-cache root under
    ``~/.raptor/cache/sca/``. Callers thread this as the explicit
    fallback when the operator passes ``--cache-root`` as None.
  - :data:`SCA_ALLOWED_HOSTS` — the full set of registries / vuln
    feeds /sca needs to reach. Anything outside this set is refused
    by the in-process egress proxy: a parser or registry-client
    compromise can't exfiltrate beyond the hosts the operator
    already implicitly trusts (they're how the project's deps were
    installed in the first place). Adding a new registry client
    requires adding its host here.
  - :func:`default_client` — single seam where the HTTP backend is
    chosen. Always returns an :class:`~core.http.egress_backend.EgressClient`
    routed through ``core.sandbox.proxy`` with the allowlist above.
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

from core.http.egress_backend import EgressClient
from typing import NoReturn, TYPE_CHECKING

if TYPE_CHECKING:
    from core.http import HttpClient

logger = logging.getLogger(__name__)

SCA_USER_AGENT = "raptor-sca/0.1 (+https://github.com/gadievron/raptor)"
SCA_CACHE_ROOT = Path.home() / ".raptor" / "cache" / "sca"

# The full set of hosts /sca needs to reach for vuln data + registry
# metadata. Ordered by purpose for readability; the egress proxy treats
# the set as flat. Every host appears verbatim in at least one client's
# URL constant under packages/sca/{osv,kev,epss}.py or
# packages/sca/registries/.
SCA_ALLOWED_HOSTS = (
    # Vulnerability feeds
    "api.osv.dev",
    "osv-vulnerabilities.storage.googleapis.com",   # OSV offline-DB zip mirror
    "www.cisa.gov",                                 # KEV feed
    "api.first.org",                                # EPSS scores
    # NVD — pre-fix this was missing from the allowlist
    # despite being a primary CVE-data source consumed by
    # the SCA verification path (see packages/nvd/client.py).
    # SCA runs that depended on NVD lookups (cve_diff oracle,
    # NVD-only CVEs not in OSV) silently returned no data
    # because the sandbox blocked the egress; operators saw
    # empty NVD sections in reports without diagnostic
    # explanation.
    "services.nvd.nist.gov",
    # Registry metadata (harden / typosquat / supply-chain heuristics)
    "pypi.org",
    "registry.npmjs.org",
    "crates.io",
    "rubygems.org",
    "proxy.golang.org",
    "search.maven.org",
    "repo.packagist.org",
    "api.nuget.org",
    "api.ftp-master.debian.org",                    # Debian madison (binary-aware, per-suite versions)
    "formulae.brew.sh",
    # GHSA — GitHub's security advisory feed; not the same
    # data as OSV's GHSA mirror (slight latency + occasional
    # advisories that GitHub publishes before OSV ingests).
    "raw.githubusercontent.com",
    # Source-archive downloads (version-diff review + wheel-metadata fallback)
    "files.pythonhosted.org",                       # PyPI sdist/wheel archives
    "static.crates.io",                             # Cargo crate tarballs
    "sum.golang.org",                               # Go module checksums
    "repo.maven.apache.org",                        # Maven/Gradle source jars
    "repo1.maven.org",                              # Maven Central mirror
    "api.github.com",                               # GHA ref→SHA resolution
    # Calibration-corpus ground-truth sources (Tier 2: boolean-
    # signal-only consumption, no exploit content stored).
    "gitlab.com",                                   # Exploit-DB index
)


def default_client(
    target: Path | None = None,
    *,
    offline: bool = False,
) -> HttpClient:
    """Return the default HttpClient for /sca.

    Always routes through the in-process egress proxy at
    :mod:`core.sandbox.proxy` with :data:`SCA_ALLOWED_HOSTS` enforced
    by the proxy. The proxy is a process-wide singleton with UNION
    semantics on the allowlist — multiple subsystems calling this
    function (or constructing their own EgressClients) all share the
    same proxy and the same allowlist union.

    When ``target`` is provided AND contains Dockerfiles / compose
    files / GitLab CI configs declaring container image references,
    the allowlist is augmented with the corresponding container-
    registry hosts (via :func:`compose_proxy_hosts`). Without this,
    the B9 base-image scanner fails at the proxy with "host not on
    allowlist" because ``SCA_ALLOWED_HOSTS`` only covers OSV / KEV /
    EPSS / static-registry-metadata hosts — not container registries
    which are project-specific.

    ``offline=True`` returns a :class:`_NoopHttpClient` whose every
    method raises :class:`HttpError`. This is the universal gate for
    the SCA scan path: direct ``http.get_json(url)`` calls (in
    license enrichment, registry-metadata walks, etc.) that bypass
    the Client-class layer's per-client offline flag are now
    refused at the http layer. Callers' existing try/except
    HttpError paths handle the no-op response.

    The egress proxy itself is shared across raptor subsystems (codeql,
    cve_diff, etc.) and stays up regardless of SCA's offline state.
    The proxy is fine without clients; this knob only neuters this
    one HttpClient instance.

    Tests bypass this seam by injecting an HttpClient directly via
    dependency injection (``run_sca(..., http=StubHttp(...))``); they
    never trigger proxy startup.
    """
    if offline:
        return _NoopHttpClient()
    hosts = compose_proxy_hosts(target)
    return EgressClient(tuple(hosts), user_agent=SCA_USER_AGENT)


class _NoopHttpClient:
    """HttpClient impl that refuses every request.

    Returned by :func:`default_client` when ``offline=True``. Every
    method raises :class:`core.http.HttpError` so the existing
    try/except HttpError fall-through paths in callers (license
    enrichment, typosquat walker, calibration corpus builder) take
    the "couldn't fetch, skip" branch instead of leaking through
    to live network.

    Cached entries are NOT served by this class — callers that
    want to use cached data must keep the client-class layer
    (PyPIClient, NpmClient, etc.) which has its own cache-only
    short-circuit. The cache layer sits ABOVE this class.
    """
    _OFFLINE_MSG = (
        "sca.default_client(offline=True): network call refused"
    )

    def request(self, method, url, **kw) -> NoReturn:
        from core.http import HttpError
        msg = f"{self._OFFLINE_MSG}: {method} {url}"
        raise HttpError(msg)

    def post_json(self, url, body, *a, **kw) -> NoReturn:
        from core.http import HttpError
        msg = f"{self._OFFLINE_MSG}: POST {url}"
        raise HttpError(msg)

    def get_json(self, url, *a, **kw) -> NoReturn:
        from core.http import HttpError
        msg = f"{self._OFFLINE_MSG}: GET {url}"
        raise HttpError(msg)

    def get_bytes(self, url, *a, **kw) -> NoReturn:
        from core.http import HttpError
        msg = f"{self._OFFLINE_MSG}: GET {url}"
        raise HttpError(msg)

    def stream_bytes(self, url, **kw) -> NoReturn:
        from core.http import HttpError
        msg = f"{self._OFFLINE_MSG}: STREAM {url}"
        raise HttpError(msg)


# RFC 1123 hostname: dot-separated alphanumeric labels, hyphens
# allowed inside a label, 253 chars max. IPv4 literals match too
# (all-digit labels), which is fine for the proxy's hostname-keyed
# allowlist.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
    re.IGNORECASE,
)

# Ports tolerated on repo-derived host strings. The egress proxy's
# allowlist is hostname-keyed, so the port is stripped — but only
# the standard HTTP(S) ports are accepted at all; anything else is
# rejected so a manifest can't smuggle odd-port syntax through.
# Self-hosted registries commonly serve on non-standard ports
# (``registry.corp:5000``); the OPERATOR — not the scanned repo —
# can extend the tolerated set via ``RAPTOR_SCA_REGISTRY_PORTS``
# (comma-separated port numbers). The port is still stripped before
# the hostname reaches the allowlist; the env var only widens which
# repo-derived ``host:port`` strings are considered well-formed.
_ALLOWED_HOST_PORTS = frozenset({"80", "443"})


def _operator_extra_ports() -> frozenset:
    """Ports the operator declared via ``RAPTOR_SCA_REGISTRY_PORTS``.

    Read per call (not at import) so tests and long-lived processes
    honour changes; validation is strict — each entry must be a
    decimal port in 1-65535, anything else is ignored with a warning
    so a typo can't silently disable the whole list.
    """
    raw = os.environ.get("RAPTOR_SCA_REGISTRY_PORTS", "")
    if not raw:
        return frozenset()
    ports = set()
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        if tok.isdigit() and 1 <= int(tok) <= 65535:
            ports.add(tok)
        else:
            logger.warning(
                "sca: ignoring invalid RAPTOR_SCA_REGISTRY_PORTS "
                "entry %r (want a decimal port 1-65535)", tok,
            )
    return frozenset(ports)


def _normalise_repo_host(raw: object) -> str | None:
    """Validate one repo-derived allowlist candidate.

    Returns the bare lowercase hostname, or ``None`` when the value
    is not a plain hostname (whitespace, scheme, path, userinfo,
    or a non-standard port) — repo manifests are untrusted input,
    so a malformed value must not reach the proxy allowlist where
    it could carry proxy-config syntax.
    """
    if not isinstance(raw, str):
        return None
    if not raw or raw != raw.strip() or any(c.isspace() for c in raw):
        return None
    if any(c in raw for c in "/@\\?#,"):
        return None
    host, sep, port = raw.partition(":")
    if sep and port not in _ALLOWED_HOST_PORTS \
            and port not in _operator_extra_ports():
        return None
    if not _HOSTNAME_RE.match(host):
        return None
    return host.lower()


def _extend_repo_hosts(
    hosts: list,
    seen: set,
    raw_hosts,
    *,
    source: str,
    added: dict,
    rejected: dict,
) -> None:
    """Append validated repo-derived hosts to ``hosts``/``seen``,
    recording per-source added / rejected values for the one-line
    per-run log in :func:`compose_proxy_hosts`."""
    for raw in raw_hosts:
        h = _normalise_repo_host(raw)
        if h is None:
            rejected.setdefault(source, []).append(repr(raw))
            continue
        if h not in seen:
            hosts.append(h)
            seen.add(h)
            added.setdefault(source, []).append(h)


def compose_proxy_hosts(target: Path | None = None) -> list:
    """Build the proxy_hosts allowlist for a SCA run.

    Always includes :data:`SCA_ALLOWED_HOSTS` (the static set of
    OSV / KEV / EPSS / registry-metadata hosts). When ``target`` is
    given AND contains Dockerfiles with FROM image references, also
    adds the container-registry hosts for every image — required for
    the B9 base-image scanner's manifest / blob requests.

    Order: static set first (deterministic), then the dynamic
    image-source-derived hosts. Deduplicated by the union.

    Best-effort: a malformed Dockerfile in the target shouldn't
    prevent the SCA run from starting with the static allowlist.
    The discovery failure is logged but not raised.
    """
    hosts = list(SCA_ALLOWED_HOSTS)
    seen = set(hosts)

    # LLM API hosts — SCA pipeline stages (optimise, whatif, etc.)
    # use LLM calls. Include the well-known provider API hosts so
    # the egress proxy permits model-resolution and inference.
    try:
        from core.llm.config import LLMConfig
        from core.llm.egress import derive_allowlist
        for h in derive_allowlist(LLMConfig()):
            if h not in seen:
                hosts.append(h)
                seen.add(h)
    except Exception as e:                           # noqa: BLE001
        logger.debug(
            "LLM egress allowlist derivation failed: %s", e,
        )

    # Operator-supplied private-registry overrides (Artifactory /
    # Nexus / GHE / etc.) — env-var-driven. Always consulted, with
    # or without ``target``, since overrides are operator-level
    # config, not project-level.
    try:
        from .private_registry import (
            hosts_for_overrides,
            load_overrides,
        )
        for h in hosts_for_overrides(load_overrides()):
            if h not in seen:
                hosts.append(h)
                seen.add(h)
    except Exception:
        logger.warning(
            "sca: private-registry override discovery failed",
            exc_info=True,
        )

    if target is None:
        return hosts
    # Repo-derived additions below come from the SCANNED TREE
    # (image refs, chart deps). They are deliberately NOT
    # trust-gated — the scan legitimately needs to reach them —
    # but every value is shape-validated (hostname grammar; only
    # :443/:80 ports tolerated) and the additions are logged once
    # per run so an operator can see what the target added to the
    # egress allowlist.
    added: dict = {}
    rejected: dict = {}
    try:
        from .dockerfile_from import image_source_registry_hosts
        _extend_repo_hosts(
            hosts, seen, image_source_registry_hosts(target),
            source="image refs", added=added, rejected=rejected,
        )
    except Exception:
        logger.warning(
            "sca: failed to derive image-source registry hosts for "
            "proxy allowlist", exc_info=True,
        )
    # Helm chart repositories declared in ``Chart.yaml``
    # ``dependencies[*].repository`` — needed by ``raptor-sca bump``
    # so the underlying ``<repo>/index.yaml`` fetch isn't refused
    # at the egress proxy. Without this, every bump candidate
    # pointing at a non-static-allowlist Helm repo (bitnami /
    # ingress-nginx / argoproj / etc.) is skipped with
    # "host not on the allowlist".
    try:
        from .parsers._safe_read import scan_root_context
        from .parsers.helm_chart import chart_repository_hosts
        # Scan-root context: Chart.yaml reads are bounded and refuse
        # symlinks unless the resolved target stays inside the tree.
        with scan_root_context(target):
            chart_hosts = chart_repository_hosts(target)
        _extend_repo_hosts(
            hosts, seen, chart_hosts,
            source="chart deps", added=added, rejected=rejected,
        )
    except Exception:
        logger.warning(
            "sca: failed to derive Helm chart repository hosts "
            "for proxy allowlist", exc_info=True,
        )
    if added:
        logger.warning(
            "sca: repo-derived hosts added to the egress allowlist — %s",
            "; ".join(f"{src}: {', '.join(vals)}"
                      for src, vals in added.items()),
        )
    if rejected:
        logger.warning(
            "sca: rejected malformed repo-derived egress host value(s) "
            "— %s",
            "; ".join(f"{src}: {', '.join(vals)}"
                      for src, vals in rejected.items()),
        )
    return hosts


__all__ = [
    "SCA_ALLOWED_HOSTS",
    "SCA_CACHE_ROOT",
    "SCA_USER_AGENT",
    "compose_proxy_hosts",
    "default_client",
]
